"""eml_parser serves as a python module for parsing eml files and returning various information found in the e-mail as well as computed information."""

import base64
import binascii
import collections
import collections.abc
import dataclasses
import datetime as dt
import email
import email.errors
import email.generator
import email.headerregistry
import email.message
import email.policy
import email.utils
import functools
import hashlib
import html
import io
import ipaddress
import itertools
import logging
import os
import pathlib
import re
import socket
import typing
import urllib.parse

import idna
import publicsuffixlist
import regex

import eml_parser.anomalies
import eml_parser.constants
import eml_parser.decode
import eml_parser.regexes
import eml_parser.routing

#
# Georges Toth (c) 2013-2014 <georges@trypill.org>
# GOVCERT.LU (c) 2013-present <info@govcert.etat.lu>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
# Functionality inspired by:
#   https://github.com/CybOXProject/Tools/blob/master/scripts/email_to_cybox/email_to_cybox.py
#   https://github.com/iscoming/eml_parser/blob/master/eml_parser.py
#
# Regular expressions and subject field decoding inspired by:
#   "A Really Ruby Mail Library" - https://github.com/mikel/mail (MIT)
#
# Known issues:
#  - searching for IPs in the e-mail header sometimes leads to false positives
#    if a mail-server (e.g. exchange) uses an ID which looks like a valid IP
#

logger = logging.getLogger(__name__)

try:
    import magic
except ImportError:
    magic = None
else:
    if not hasattr(magic, 'open'):
        logger.warning(
            'The installed "magic" module does not provide the file-magic compatible API (magic.open), '
            'mime types will not be determined. Install file-magic or a python-magic version which provides it.'
        )

        magic = None

__author__ = 'Toth Georges, Jung Paul'
__email__ = 'georges@trypill.org, georges.toth@govcert.etat.lu'
__copyright__ = 'Copyright 2013-2014 Georges Toth, Copyright 2013-present GOVCERT Luxembourg'
__license__ = 'AGPL v3+'

HASH_TYPES = ('md5', 'sha1', 'sha256', 'sha512')

# Header fields which contain e-mail addresses, they are parsed by the stdlib address parser.
_ADDRESS_HEADERS = frozenset(('sender', 'resent-sender', 'to', 'resent-to', 'cc', 'resent-cc', 'bcc', 'resent-bcc', 'from', 'resent-from', 'reply-to'))

# Whitespace and quote characters in front of an URL.
_URL_LEADING_JUNK = ' \t\n\r\f\v\'"«»“”‘’'

# Characters ending an URL found in text: what follows them is noise.
_URL_NOISE_REGEX = re.compile(r"""[', ")}\\]""")

_WHITESPACE_RUN_REGEX = re.compile(r"""\s+""")

# Writes header fields as they are (no refolding, so no parsing) and as UTF-8, see `_Utf8BytesGenerator`.
_UNFOLDED_UTF8_POLICY = email.policy.default.clone(max_line_length=0, refold_source='none', utf8=True)


class _Utf8BytesGenerator(email.generator.BytesGenerator):
    """Bytes generator which writes text as UTF-8 instead of failing on non-ASCII characters; 8-bit data is written unchanged."""

    _fp: typing.BinaryIO  # set by Generator.__init__(), missing in the typeshed stubs

    def write(self, s: str) -> None:
        """Write text as UTF-8, surrogate escaped bytes as the original bytes."""
        self._fp.write(s.encode('utf-8', 'surrogateescape'))


def _normalized_ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse an IP address for comparisons, independent of its notation.

    Brackets and the zone index are removed and an IPv4-mapped IPv6 address is its IPv4 address, so `2001:DB8:0::1`
    equals `2001:db8::1`, `[fe80::1%eth0]` equals `fe80::1` and `::ffff:192.0.2.1` equals `192.0.2.1`.

    Args:
        text: The address.

    Returns:
        The address, or None if the text is no IP address.
    """
    address_text = text.strip('[]').partition('%')[0]

    try:
        address = ipaddress.ip_address(address_text)
    except ValueError:
        return None

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped

    return address


def _payload_text(part: email.message.Message) -> list[email.message.Message] | str:
    """Return the payload of a part like `part.get_payload()`, also if its declared charset fails.

    For 8-bit text the stdlib decodes the payload with the declared charset and falls back to ASCII only for unknown charset
    names; others raise, e.g. "idna" (which supports no error handler). These are decoded as ASCII as well, after the
    content transfer encoding (the stdlib offers the undecoded bytes only that way).

    Args:
        part (email.message.Message): The part.

    Returns:
        The list of sub-parts of a multipart part, otherwise the text.
    """
    try:
        return typing.cast('list[email.message.Message] | str', part.get_payload())
    except ValueError:
        logger.warning('Payload cannot be decoded with its charset "%s", decoding it as ASCII.', part.get_content_charset())

    return typing.cast('bytes', part.get_payload(decode=True)).decode('ascii', 'replace')


def _filename(part: email.message.Message) -> str:
    """Return the file name of a part, or an empty string if it has none or it cannot be decoded.

    The stdlib fails on some malformed parameters, e.g. with a ValueError on an RFC 2231 value with a NUL in its charset.
    """
    try:
        return part.get_filename('')
    except (binascii.Error, AssertionError, ValueError):
        logger.exception('Exception occurred while trying to parse the content-disposition header. Collected data will not be complete.')

    return ''


def iter_parts(msg: email.message.Message, recursion_limit: int) -> collections.abc.Iterator[tuple[email.message.Message, str | None]]:
    """Walk a message and all its MIME parts depth first, each part before its sub-parts.

    The walk is iterative, so the nesting depth is limited by *recursion_limit* only and not by the Python stack.

    Args:
        msg (email.message.Message): The message.
        recursion_limit: Maximum nesting depth of the parts.

    Yields:
        tuple: The part and the boundary of the multipart which encloses it (None for the message itself).

    Raises:
        RecursionError: If the parts are nested deeper than *recursion_limit*.
    """
    stack: list[tuple[email.message.Message, str | None, int]] = [(msg, None, 0)]

    while stack:
        part, boundary, depth = stack.pop()

        if depth > recursion_limit:
            logger.warning('multi-part nesting limit (%d) exceeded, aborting', recursion_limit)
            raise RecursionError('Recursion limit exceeded')

        yield part, boundary

        if not part.is_multipart():
            continue

        part_boundary = part.get_boundary(failobj=None)
        sub_parts = typing.cast('list[email.message.Message]', part.get_payload())

        # Pushed in reverse, so that the first sub-part is walked next.
        for sub_part in reversed(sub_parts):
            stack.append((sub_part, part_boundary, depth + 1))


@dataclasses.dataclass(frozen=True)
class PartData:
    """Data of one e-mail part, handed to the `part_hook` callback of `EmlParser`.

    The bytes in `data` are exactly the bytes the parser hashed for this part, so
    `sha256` equals `hashlib.sha256(data).hexdigest()` and matches the hash stored in
    the parse result (`body[].hash` or `attachment[].hash['sha256']`). A consumer
    can therefore correlate a scan hit with the part in the
    result without the plaintext ever appearing in it.
    """

    kind: str  # 'body' for a text part, 'attachment' for a part parsed as attachment
    data: bytes  # the part content, exactly the bytes that were hashed
    sha256: str  # SHA-256 of `data`, hex encoded
    content_type: str | None  # content type of the part, e.g. 'text/html'
    filename: str | None  # attachment file name, if any
    content_headers: dict[str, list[str]]  # part headers, lower-cased names
    boundary: str | None  # boundary of the enclosing multipart, if any


class BodyPart(typing.NamedTuple):
    """A text part of the e-mail, as returned by `EmlParser._get_raw_body_text()`."""

    encoding: str  # content transfer encoding, lower-cased
    text: str  # the decoded text
    headers: list[tuple[str, str]]  # the header fields of the part
    boundary: str | None  # boundary of the enclosing multipart, if any


@dataclasses.dataclass
class BodyIndicators:
    """The indicators found in a text part, in order of their first occurrence. The field names are the keys in the parse result."""

    uri: dict[str, None] = dataclasses.field(default_factory=dict)
    uri_noscheme: dict[str, None] = dataclasses.field(default_factory=dict)
    unc: dict[str, None] = dataclasses.field(default_factory=dict)
    email: dict[str, None] = dataclasses.field(default_factory=dict)
    domain: dict[str, None] = dataclasses.field(default_factory=dict)
    ip: dict[str, None] = dataclasses.field(default_factory=dict)


@functools.cache
def get_public_suffix_list(accept_unknown: bool) -> publicsuffixlist.PublicSuffixList:
    """Return the public suffix list; it is parsed once per setting and shared, as parsing it takes about 40 ms and it is read-only afterwards.

    Args:
        accept_unknown: Whether names with an unknown top level domain are accepted.

    Returns:
        The parsed public suffix list.
    """
    return publicsuffixlist.PublicSuffixList(accept_unknown=accept_unknown)


def find_header_start(data: bytes) -> int:
    """Find the first line which looks like a header field.

    Plain bytes operations are used on purpose: this is much faster than a regular expression on large inputs
    and every line is looked at only once.

    Args:
        data: Raw e-mail, possibly with garbage in front of the headers.

    Returns:
        Offset of the first line starting with a valid field name followed by a colon, or 0 if there is none.
    """
    pos = 0

    while (colon := data.find(b':', pos)) != -1:
        line_start = max(pos, data.rfind(b'\n', pos, colon) + 1)
        field_name = data[line_start:colon].rstrip(b' \t')

        if field_name and not field_name.translate(None, eml_parser.constants.FIELD_NAME_BYTES):
            return line_start

        line_end = data.find(b'\n', colon)

        if line_end == -1:
            break

        pos = line_end + 1

    return 0


class HeaderParsingLimitDefect(email.errors.HeaderDefect):
    """The message has more header fields or header bytes than are parsed in structured form, see `EmlParser.limit_header_parsing`."""


class UnparsedHeaderValue(str):
    """A raw header value which is kept as it is instead of being run through the structured header parsers of the stdlib."""

    __slots__ = ()


class CustomPolicy(email.policy.EmailPolicy):
    """Custom parsing policy based on the default policy but relaxing some checks and early fixing invalid values."""

    email_regex: regex.Pattern[str] = eml_parser.regexes.email_no_force_tld_regex

    def __init__(self, email_regex: regex.Pattern[str] = eml_parser.regexes.email_no_force_tld_regex) -> None:
        """Constructor.

        Args:
            email_regex (regex.Pattern[str], optional): Pattern used to extract e-mail addresses from malformed headers.
        """
        # Policies are immutable; the stdlib accepts any declared class attribute as keyword. The typeshed stubs do not know ours.
        custom: dict[str, typing.Any] = {'email_regex': email_regex}
        super().__init__(max_line_length=0, refold_source='none', **custom)

    def header_fetch_parse(self, name: str, value: str) -> str:
        """Pass the name/value to the parent header_fetch_parse method for proper parsing, unless the value is too long to be parsed in reasonable time.

        Values beyond the header parsing limits of the message (`UnparsedHeaderValue`, see `EmlParser.limit_header_parsing`) are not parsed either.
        """
        if isinstance(value, UnparsedHeaderValue):
            return self.unparsed_header_value(name, value)

        if len(value) <= eml_parser.constants.MAX_PARSED_HEADER_SIZE:
            return self.fetch_fixed_header(name, value)

        # The recursive descent parsers of the stdlib are quadratic in the length of a value, a megabyte of words takes seconds.
        logger.warning('Header field "%s" is %d characters long, it is not parsed.', name.lower(), len(value))
        return self.unparsed_header_value(name, value)

    @staticmethod
    def unparsed_header_value(name: str, value: str) -> str:
        """The raw value of a header field which is not run through the structured header parsers."""
        if name.lower() == 'date':
            return eml_parser.decode.default_date

        return str(email.policy.compat32.header_fetch_parse(name, value))

    def fetch_fixed_header(self, name: str, value: str) -> str:
        """Early fix parsing issues and pass the name/value to the parent header_fetch_parse method for proper parsing.

        The stdlib parses a header again on every access (`get()`, `get_all()`, `items()`), which are several per header, so the results are cached in `_fetch_fixed_header`.
        The warning is logged here, once per access, because the cached method must stay pure and would otherwise only warn on the first occurrence of a value.
        """
        result, warning = self._fetch_fixed_header(name, value)

        if warning is not None:
            logger.warning(warning)

        return result

    @functools.lru_cache(maxsize=1024)  # noqa: B019 - the cache is bounded, so it keeps at most 1024 policies alive
    def _fetch_fixed_header(self, name: str, value: str) -> tuple[str, str | None]:  # noqa: PLR0911 - a value and a fallback per kind of header
        """Cached pure variant of `fetch_fixed_header` which reports its warning as the second return value instead of logging it."""
        header = name.lower()

        if header == 'message-id':
            if '[' in value and not self.email_regex.match(value):
                # try workaround for bad message-id formats
                m = self.email_regex.search(value)
                if m:
                    value = f'<{m.group(1)}>'
                else:
                    return '', 'Header field "message-id" is in an invalid format and cannot be fixed, it will be dropped.'
        elif header == 'date':
            try:
                value = super().header_fetch_parse(name, value)
            except TypeError as exc:
                return eml_parser.decode.default_date, f'Error parsing date: {exc!s}.'

            return eml_parser.decode.robust_string2date(value).isoformat(), None

        elif header in _ADDRESS_HEADERS:
            try:
                return super().header_fetch_parse(name, value), None
            except RecursionError:
                # This can happen when the recursion gets too deep in the stdlib recursive descent parser.
                # In this case, the header is certainly pathological. We still try to extract some addresses.
                m = self.email_regex.findall(value)
                return ', '.join(m), None

        try:
            return super().header_fetch_parse(name, value), None
        except (IndexError, ValueError):
            # The stdlib parsers fail on some malformed values, e.g. on a parameter `name*` without a value (IndexError) or with a
            # NUL in its RFC 2231 charset (ValueError) in Content-Type or Content-Disposition. This happens while the stdlib
            # parses the message, so the raw value is used instead.
            return self.unparsed_header_value(name, value), f'Header field "{header}" cannot be parsed, its raw value is used.'


class EmlParser:
    """eml-parser class."""

    MULTIPART_RECURSION_LIMIT = 100

    def __init__(  # noqa: PLR0917 - the positional parameters are public API
        self,
        include_raw_body: bool = False,
        include_attachment_data: bool = False,
        pconf: dict | None = None,
        policy: email.policy.Policy | None = None,
        ignore_bad_start: bool = False,
        email_force_tld: bool = False,
        domain_force_tld: bool = False,
        ip_force_routable: bool = False,
        parse_attachments: bool = True,
        include_www: bool = True,
        include_href: bool = True,
        *,
        part_hook: typing.Callable[[PartData], None] | None = None,
    ) -> None:
        """Initialisation.

        Args:
            include_raw_body (bool, optional): Boolean parameter which indicates whether
                                               to include the original file contents in
                                               the returned structure: the text parts in
                                               `raw_body` (content transfer encoding and
                                               decoded text), the text of each part in
                                               `body[].content` and the indicators in plain
                                               text instead of hashed. Default is False.
            include_attachment_data (bool, optional): Boolean parameter which indicates whether
                                                      to include raw attachment data in the
                                                      returned structure. Default is False.
            pconf (dict, optional): A dict with various optional configuration parameters,
                                    e.g. whitelist IPs, whitelist e-mail addresses, etc.
            policy (CustomPolicy, optional): Policy to use when parsing e-mails.
                                                    Default = CustomPolicy.
            ignore_bad_start (bool, optional): Ignore invalid file start, i.e. any lines in front of the first header field.
            email_force_tld (bool, optional): Only match e-mail addresses with a TLD, i.e. exclude something like
                                              john@doe. If enabled, it uses domain_force_tld and ip_force_routable settings
                                              to validate the host portion of the address. By default this is disabled.
            domain_force_tld (bool, optional): For domain validation, requires global IP or a valid TLD.
                                               By default this is disabled.
            ip_force_routable (bool, optional): For IP validation, requires globally routable IP.
                                               By default this is disabled.
            parse_attachments (bool, optional): Set this to false if you want to disable the parsing of attachments.
                                                Please note that HTML attachments as well as other text data marked to be
                                                in-lined, will always be parsed.
            include_www (bool, optional): Include potential URLs starting with www
            include_href (bool, optional): Include potential URLs in HREFs matching non-simple regular expressions
            part_hook (Callable[[PartData], None], optional): Callback invoked for every part of
                                                               the e-mail (text parts and attachments) with the
                                                               part's data, at the point where its hash is computed.
                                                               The data is passed exactly as hashed (see `PartData`), so
                                                               it can be scanned without the plaintext
                                                               ending up in the returned structure. The callback is
                                                               invoked independently of `include_raw_body` and
                                                               `include_attachment_data`, and text attachments are
                                                               delivered once per representation (as `body` and as
                                                               `attachment`), like in the result itself. Exceptions
                                                               raised by the callback are not caught. Default is None.

        """
        self.include_raw_body = include_raw_body
        self.include_attachment_data = include_attachment_data
        # If no pconf was specified, default to empty dict. It is read only, the optional keys default to no whitelisting.
        self.pconf = pconf or {}
        self.ignore_bad_start = ignore_bad_start
        self.email_force_tld = email_force_tld
        self.domain_force_tld = domain_force_tld
        self.ip_force_routable = ip_force_routable
        self.parse_attachments = parse_attachments
        self.include_www = include_www
        self.include_href = include_href
        self.part_hook = part_hook
        self._psl = get_public_suffix_list(not self.domain_force_tld)
        # A file extension which is a TLD (or becomes one) is a domain and not a file name, so the public suffix list decides.
        self._file_extensions = frozenset(
            ext for ext in eml_parser.constants.FILE_EXTENSIONS if self._psl.publicsuffix(f'x.{ext}', accept_unknown=False) is None
        )
        # The same hosts occur over and over in a body; the verdict only depends on settings which are constant for an instance.
        self._cached_valid_domain_or_ip = functools.lru_cache(maxsize=32768)(self._get_valid_domain_or_ip)

        self.email_regex = eml_parser.regexes.email_force_tld_regex if email_force_tld else eml_parser.regexes.email_no_force_tld_regex
        self.policy = policy or CustomPolicy(email_regex=self.email_regex)

        self.msg: email.message.Message | None = None
        # The addresses of pconf['whiteip'], parsed at the start of each message (pconf may change between messages).
        self._white_ip_addresses: frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address] = frozenset()

    def decode_email(self, eml_file: os.PathLike[str] | str, ignore_bad_start: bool = False) -> dict:
        """Function for decoding an EML file into an easily parsable structure.

        Some intelligence is applied while parsing the file in order to work around
        broken files.
        Besides just parsing, this function also computes hashes and extracts meta
        information from the source file.

        Args:
            eml_file: Path to the file to be parsed. os.PathLike objects are supported.
            ignore_bad_start: Ignore invalid file start for this run, i.e. any lines in front of the first header field.

        Returns:
            dict: A dictionary with the content of the EML parsed and broken down into
                  key-value pairs.
        """
        return self.decode_email_bytes(pathlib.Path(eml_file).read_bytes(), ignore_bad_start=ignore_bad_start)

    def decode_email_bytes(self, eml_file: bytes, ignore_bad_start: bool = False) -> dict:
        """Function for decoding an EML file into an easily parsable structure.

        Some intelligence is applied while parsing the file in order to work around
        broken files.
        Besides just parsing, this function also computes hashes and extracts meta
        information from the source file.

        Args:
            eml_file: Contents of the raw EML file passed to this function as string.
            ignore_bad_start: Ignore invalid file start for this run, i.e. any lines in front of the first header field.

        Returns:
            dict: A dictionary with the content of the EML parsed and broken down into
                  key-value pairs.
        """
        if self.ignore_bad_start or ignore_bad_start:
            # Skip any garbage in front of the first header field.
            # The data is only sliced, so line endings and the message body stay untouched.
            eml_file = eml_file[find_header_start(eml_file) :]

        self.msg = email.message_from_bytes(eml_file, policy=self.policy)
        self.repair_multipart(self.msg)
        self.limit_header_parsing(self.msg)

        return self.parse_email()

    @staticmethod
    def guess_boundary(payload: str, declared: str | None) -> str | None:
        """Find the boundary of a multipart payload: the declared one if it occurs, else the first line which looks like a delimiter (`--something`)."""
        if declared and f'--{declared}' in payload:
            return declared

        return next((m.group(1) for m in eml_parser.regexes.multipart_boundary_guess_regex.finditer(payload) if not m.group(1).endswith('--')), None)

    def repair_multipart(self, msg: email.message.Message) -> None:
        """Split multipart parts which the stdlib parser could not split because their boundary is missing or wrong.

        The stdlib leaves the content of such a part as one opaque string, so the URLs, addresses and attachments in it would be invisible.
        This is what malware authors and broken mailers produce. If no boundary can be found at all, the part is treated as plain text instead
        of being ignored. The defects reported by the stdlib are kept. Parts created by the repair are checked as well.

        Args:
            msg (email.message.Message): The parsed message, modified in place.
        """
        parts = [msg]

        while parts:
            part = parts.pop()

            if part.is_multipart():
                parts.extend(typing.cast('list[email.message.Message]', part.get_payload()))
                continue

            if part.get_content_maintype() != 'multipart':
                continue

            payload = _payload_text(part)

            if isinstance(payload, str):
                boundary = self.guess_boundary(payload, part.get_boundary(failobj=None))

                if boundary is None:
                    part.replace_header('Content-Type', 'text/plain')
                    continue

                try:
                    repaired = email.message_from_string(f'Content-Type: multipart/mixed; boundary="{boundary}"\n\n{payload}', policy=self.policy).get_payload()
                except RecursionError:
                    logger.warning('Multipart parts nested too deeply to repair, treating the part as text.')
                    repaired = None

                if not isinstance(repaired, list):
                    # The stdlib did not split it either, e.g. because it decodes an encoded word in the boundary. Retrying would never end.
                    part.replace_header('Content-Type', 'text/plain')
                    continue

                try:
                    part.set_param('boundary', boundary)
                except ValueError:
                    # The other parameters contain line breaks, which may not be stored again. set_param() removed the header already.
                    logger.warning('Content-Type of a repaired multipart part contains line breaks, keeping only the boundary.')
                    part['Content-Type'] = f'multipart/mixed; boundary="{boundary}"'

                part.set_payload(repaired)
                parts.append(part)

    @staticmethod
    def limit_header_parsing(msg: email.message.Message) -> None:
        """Keep the header fields beyond the parsing limits of a message with their raw value, without structured parsing.

        Defence in depth against messages made of huge numbers of header fields: the header fields of the message and of all its MIME parts are
        counted in order, and once `constants.MAX_PARSED_HEADER_FIELDS` fields or `constants.MAX_PARSED_HEADER_BYTES` bytes of values are reached,
        the remaining values are marked as `UnparsedHeaderValue`. They stay in the output as raw text, so no evidence is lost, but they cost no
        more than copying them. The first occurrence of each field in `constants.ALWAYS_PARSED_HEADERS` is parsed in every part regardless, so that
        junk fields in front of them cannot hide the sender, the subject or the MIME structure. A `HeaderParsingLimitDefect` is added to the
        defects of the message, as exceeding the limits is a strong sign of a crafted message.

        Args:
            msg (email.message.Message): The parsed message, modified in place.
        """
        fields = 0
        size = 0
        unparsed = 0
        parts = collections.deque([msg])

        # Iterative breadth first walk (the message's own fields first), Message.walk() recurses and fails on deeply nested parts.
        while parts:
            part = parts.popleft()

            if part.is_multipart():
                parts.extend(typing.cast('list[email.message.Message]', part.get_payload()))

            # Message has no public interface to replace a value in place without reordering or scanning the fields again.
            headers: list[tuple[str, str]] = part._headers  # type: ignore[attr-defined]  # noqa: SLF001
            always_parsed = set(eml_parser.constants.ALWAYS_PARSED_HEADERS)

            for i, (name, value) in enumerate(headers):
                fields += 1
                if len(value) <= eml_parser.constants.MAX_PARSED_HEADER_SIZE:
                    size += len(value)

                lower_name = name.lower()
                if lower_name in always_parsed:
                    always_parsed.discard(lower_name)
                elif fields > eml_parser.constants.MAX_PARSED_HEADER_FIELDS or size > eml_parser.constants.MAX_PARSED_HEADER_BYTES:
                    headers[i] = (name, UnparsedHeaderValue(value))
                    unparsed += 1

        if unparsed:
            description = (
                f'{fields} header fields with {size} bytes of values exceed the parsing limits of '
                f'{eml_parser.constants.MAX_PARSED_HEADER_FIELDS} fields and {eml_parser.constants.MAX_PARSED_HEADER_BYTES} bytes, '
                f'{unparsed} values are kept unparsed'
            )
            logger.warning('%s.', description)
            msg.defects.append(HeaderParsingLimitDefect(description))

    def parse_email(self) -> dict:
        """Parse an e-mail and return a dictionary containing the various parts of the e-mail broken down into key-value pairs.

        Returns:
          dict: A dictionary with the content of the EML parsed and broken down into
                key-value pairs.
        """
        if self.msg is None:
            raise ValueError('msg is not set.')

        msg = self.msg
        self._white_ip_addresses = self._parse_white_ips()
        headers_struc: dict[str, typing.Any] = {'subject': eml_parser.decode.decode_field(msg.get('subject', ''))}

        # If parsing had problems, report it. str() of most stdlib defects is empty, the class name identifies the problem.
        if msg.defects:
            headers_struc['defect'] = []

            for defect in msg.defects:
                defect_name = type(defect).__name__

                if str(defect):
                    headers_struc['defect'].append(f'{defect_name}: {defect}')
                else:
                    headers_struc['defect'].append(defect_name)

        sender = self._parse_from(msg)
        if sender is not None:
            headers_struc['from'] = sender

        headers_struc['to'] = self.headeremail2list('to')
        for key, field_name in (('cc', 'cc'), ('delivered_to', 'delivered-to')):
            if addresses := self.headeremail2list(field_name):
                headers_struc[key] = addresses

        # The default date is used if the field is absent.
        date_value: str | None = msg.get('date')

        if date_value is None:
            headers_struc['date'] = eml_parser.decode.DEFAULT_DATE
        else:
            headers_struc['date'] = dt.datetime.fromisoformat(date_value)

        headers_struc.update(self._parse_received(msg))

        body_parts = self._get_raw_body_text(msg)
        is_multipart = len(body_parts) != 1
        bodies = [self._parse_body_part(body_part, is_multipart) for body_part in body_parts]

        header = self._collect_header_fields(msg)
        headers_struc['header'] = header

        if authentication := self.parse_authentication_results(header):
            headers_struc['authentication'] = authentication

        report_struc: dict[str, typing.Any] = {}

        if self.parse_attachments:
            try:
                attachments = self._traverse_multipart(msg)
            except (binascii.Error, AssertionError):
                # we hit this exception if the payload contains invalid data
                logger.exception('Exception occurred while parsing attachment data. Collected data will not be complete!')
                attachments = []

            if attachments:
                report_struc['attachment'] = attachments

        report_struc['body'] = bodies

        if self.include_raw_body:
            # As up to v0.5: the content transfer encoding and the decoded text of each text part.
            report_struc['raw_body'] = [(body_part.encoding, body_part.text) for body_part in body_parts]

        report_struc['header'] = headers_struc

        return report_struc

    def _parse_from(self, msg: email.message.Message) -> str | None:
        """Extract the address of the sender from the *From* header field, working around values the stdlib fails to parse.

        Args:
            msg (email.message.Message): The message, its *From* field is replaced if it cannot be parsed.

        Returns:
            str: The lower-cased address (or the raw value if it contains none), or None if the field is missing or empty.
        """
        try:
            field = str(msg.get('from', '')).lower()
        except (IndexError, AttributeError):
            # We have hit current open issue #27257
            # https://bugs.python.org/issue27257
            # The field is replaced by the first address found in it, or emptied, as a workaround.
            logger.exception('We hit bug 27257!')

            addresses = eml_parser.decode.workaround_bug_27257(msg, 'from', self.email_regex)
            first_address = addresses[0] if addresses else ''

            del msg['from']
            msg.add_header('from', first_address)
            field = first_address.lower()
        except ValueError:
            raw_values = eml_parser.decode.workaround_field_value_parsing_errors(msg, 'from')
            field = eml_parser.decode.rfc2047_decode(raw_values[0]).lower()

        if field == '':
            return None

        address = email.utils.parseaddr(field)

        if address != ('', ''):
            return address[1]

        if m := self.email_regex.search(field):
            return m.group(1)

        logger.warning('FROM header parsing failed.')
        return field

    def _parse_received(self, msg: email.message.Message) -> dict[str, typing.Any]:
        """Parse the *Received* header fields, i.e. the path of the e-mail, and collect the hosts and addresses in them.

        Args:
            msg (email.message.Message): The message.

        Returns:
            dict: The parsed lines in *received*, and the unique e-mail addresses, domains, IP addresses and recipients found in them in
                *received_email*, *received_domain*, *received_ip* and *received_foremail* (if any). The *from* part of the most external
                line passing a server of `pconf['byhostentry']` is *received_src*.
        """
        received: list[dict[str, typing.Any]] = []
        found: dict[str, list[str]] = {'received_email': [], 'received_domain': [], 'received_ip': []}
        source: dict[str, typing.Any] = {}

        try:
            found_smtpin: collections.Counter[str] = collections.Counter()  # Counter for storing potential duplicate "HOP"

            for received_line in msg.get_all('received', []):
                received_line_flat = _WHITESPACE_RUN_REGEX.sub(' ', str(received_line).lower())
                parsed_routing = eml_parser.routing.parserouting(received_line_flat, self.email_regex)

                if self.pconf.get('byhostentry'):
                    self._track_byhostentry(parsed_routing, found_smtpin, source)

                received.append(parsed_routing)

                for ip in eml_parser.regexes.findall_ipv6(received_line_flat) + eml_parser.regexes.ipv4_regex.findall(received_line_flat):
                    if self._is_white_ip(ip):
                        continue

                    if valid_ip := self.get_valid_domain_or_ip(ip):
                        found['received_ip'].append(valid_ip)
                    else:
                        logger.debug('Invalid IP in received line - "%s"', ip)

                # search for domain (the last label contains a letter, so IPs are never matched; they are found above)
                found['received_domain'] += eml_parser.regexes.recv_dom_regex.findall(received_line_flat)

                recipients = parsed_routing.get('for', [])
                for mail_candidate in self.email_regex.findall(received_line_flat):
                    # The host of the address must be a valid domain or IP address, the address itself is reported.
                    if self.email_force_tld and self.get_valid_domain_or_ip(mail_candidate) is None:
                        continue

                    if mail_candidate not in recipients:
                        found['received_email'].append(mail_candidate)

        except TypeError:  # Ready to parse email without received headers.
            logger.exception('Exception occurred while parsing received lines.')

        # The recipients of all lines, for a rapid search.
        found_foremail: dict[str, None] = {}
        for parsed_routing in received:
            for recipient in parsed_routing.get('for', []):
                if recipient not in self.pconf.get('whitefor', []):
                    found_foremail[recipient] = None

        # Unique values, keys without values are left out.
        result: dict[str, typing.Any] = {'received': received}
        for key, values in found.items():
            if values:
                result[key] = list(dict.fromkeys(values))

        result.update(source)

        if found_foremail:
            result['received_foremail'] = list(found_foremail)

        return result

    def _track_byhostentry(self, parsed_routing: dict[str, typing.Any], found_smtpin: collections.Counter[str], source: dict[str, typing.Any]) -> None:
        """Collect the IP of the gateway that has injected the mail, i.e. the *from* part of a line passing a server of `pconf['byhostentry']`.

        The lines are parsed from the MOST recent to the OLDEST (from IN > Out), the last match is the most external one.
        Warning .. It may be spoofed !! A warning is added to the line if a gateway is found multiple times.

        Args:
            parsed_routing: The parsed received line, a warning is added to it.
            found_smtpin: How often each gateway was found so far, updated.
            source: Gets the *from* part of the line as *received_src* if it matches.
        """
        for by_item in parsed_routing.get('by', []):
            for configured_byhostentry in self.pconf['byhostentry']:
                byhostentry = configured_byhostentry.lower()
                if byhostentry not in by_item:
                    continue

                source['received_src'] = parsed_routing.get('from')

                found_smtpin[byhostentry] += 1
                if found_smtpin[byhostentry] > 1:  # Twice found the header...
                    parsed_routing.setdefault('warning', []).append('Duplicate SMTP by entrypoint')

    def _parse_body_part(self, body_part: BodyPart, multipart: bool) -> dict[str, typing.Any]:
        """Build the entry of a text part in the parse result: its indicators (or their hashes), header fields and hash.

        Args:
            body_part: The text part.
            multipart: Whether the e-mail has several text parts. If not, only the *Content-* header fields of the message are stored
                with the part, the others are in the header of the result anyway.

        Returns:
            dict: The entry.
        """
        entry: dict[str, typing.Any] = {}
        indicators = self._extract_indicators(body_part.text)

        # The field names of BodyIndicators are the keys of the entry, e.g. "uri" or "uri_hash".
        for key, values in vars(indicators).items():
            if not values:
                continue

            if self.include_raw_body:
                entry[key] = list(values)
            else:
                entry[f'{key}_hash'] = [self.get_hash(value.lower(), 'sha256') for value in values]

        content_headers: dict[str, list[str]] = {}
        for name, value in body_part.headers:
            # The "." in header names is replaced, for MongoDB.
            key = name.lower().replace('.', ':')

            if multipart or key.startswith('content'):
                content_headers.setdefault(key, []).append(str(value))

        entry['content_header'] = content_headers

        if self.include_raw_body:
            entry['content'] = body_part.text

        # Sometimes bad people play with multiple header instances. We "display" the "LAST" one, as does thunderbird.
        if content_type := content_headers.get('content-type'):
            entry['content_type'] = content_type[-1].split(';', 1)[0].strip()

        body_data = body_part.text.encode('utf-8')
        entry['hash'] = hashlib.sha256(body_data).hexdigest()

        if self.part_hook is not None:
            self.part_hook(
                PartData(
                    kind='body',
                    data=body_data,
                    sha256=entry['hash'],
                    content_type=entry.get('content_type'),
                    filename=None,
                    content_headers=content_headers,
                    boundary=body_part.boundary,
                )
            )

        if body_part.boundary is not None:
            entry['boundary'] = body_part.boundary

        return entry

    def _extract_indicators(self, text: str) -> BodyIndicators:
        """Find the URLs, remote file shares, e-mail addresses, domains and IP addresses in a text.

        Args:
            text: The text, e.g. a decoded body.

        Returns:
            BodyIndicators: The valid indicators, the ones in `pconf['whiteip']` left out.
        """
        found = BodyIndicators()

        # Running the regular expressions over a 500K+ body at once causes time and memory issues, so the body is processed in slices.
        # Namespace declarations (Outlook HTML, SVG, XHTML) are identifiers, not links, and would be reported as indicators on nearly every mail.
        for body_slice in self.string_sliding_window_loop(eml_parser.regexes.xmlns_declaration_regex.sub(' ', text)):
            for url in self.get_uri_ondata(body_slice):
                if ':/' in url[:10]:
                    found.uri[url] = None
                else:
                    found.uri_noscheme[url] = None

            for share in eml_parser.regexes.unc_regex.finditer(body_slice):
                found.unc[share.group(0).rstrip('.,;')] = None

            for match in self.email_regex.findall(body_slice):
                address = match.lower()
                if self.get_valid_domain_or_ip(address):
                    found.email[address] = None

            self._add_domains(eml_parser.regexes.dom_regex.findall(body_slice), found.domain)

            for ip in eml_parser.regexes.ipv4_regex.findall(body_slice) + eml_parser.regexes.findall_ipv6(body_slice):
                if ':' in ip and not any(char.isdigit() for char in ip) and ip.count(':') < 3:
                    # "::" or a scope resolution like "Add::dead" is not an address
                    continue

                self._add_ip(self.get_valid_domain_or_ip(ip.lower()), found.ip)

        # URLs do not necessarily appear as-is in the body, as they may contain escaped entities.
        # For this reason, we have to extract the domains again from each parsed URL.
        # Run once over the deduplicated URLs after slicing to keep the cost linear in the body size.
        # The URLs are percent-decoded, as the target of a redirector is usually encoded (`?url=https%3A%2F%2Fevil.example%2F`).
        # The host is also added in the ASCII form a browser resolves, which covers non-ASCII host names (`пример.рф`, `аpple.com`).
        for url in [*found.uri, *found.uri_noscheme]:
            try:
                host = urllib.parse.urlparse(url if ':/' in url else f'//{url}').hostname
            except ValueError:
                host = None
            ascii_host = self.get_ascii_host(host.rstrip('.')) if host else None

            domain_candidates = eml_parser.regexes.dom_regex.findall(urllib.parse.unquote(url))
            if ascii_host and eml_parser.regexes.dom_regex.fullmatch(ascii_host):
                domain_candidates.append(ascii_host)
            self._add_domains(domain_candidates, found.domain)

            # http://3232235777/ is a valid URL for browsers but contains no dotted IP address
            if ascii_host:
                self._add_ip(self.get_obfuscated_ip(ascii_host), found.ip)

        # The host of a remote file share is the indicator: it is contacted (and authenticated to) when the path is opened.
        for share in found.unc:
            share_host = self.get_share_host(share)
            if not share_host:
                continue

            try:
                ipaddress.ip_address(share_host)
            except ValueError:
                found.domain[share_host] = None
            else:
                self._add_ip(share_host, found.ip)

        return found

    def _add_domains(self, candidates: collections.abc.Iterable[str], domains: dict[str, None]) -> None:
        """Add the candidates which are valid domains, and not file names, lower-cased to *domains*."""
        for candidate in candidates:
            domain = candidate.lower()
            if not self.is_file_name(domain) and self.get_valid_domain_or_ip(domain):
                domains[domain] = None

    def _add_ip(self, ip: str | None, ips: dict[str, None]) -> None:
        """Add an IP address to *ips*, unless it is None or in `pconf['whiteip']`."""
        if ip and not self._is_white_ip(ip):
            ips[ip] = None

    def _parse_white_ips(self) -> frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        """Parse the entries of `pconf['whiteip']` which are IP addresses, see `_normalized_ip()`."""
        addresses = set()

        for entry in self.pconf.get('whiteip', []):
            address = _normalized_ip(str(entry))
            if address is not None:
                addresses.add(address)

        return frozenset(addresses)

    def _is_white_ip(self, ip: str) -> bool:
        """Check whether an IP address is in `pconf['whiteip']`, in any notation (see `_normalized_ip()`)."""
        # Entries are also compared as given, as before addresses were parsed.
        if ip in self.pconf.get('whiteip', []):
            return True

        address = _normalized_ip(ip)
        return address is not None and address in self._white_ip_addresses

    def _collect_header_fields(self, msg: email.message.Message) -> dict[str, list[str]]:
        """Collect the decoded values of all header fields of a message, working around values the stdlib fails to parse.

        Args:
            msg (email.message.Message): The message.

        Returns:
            dict: The non-empty values per lower-cased field name, the names in the order of their first occurrence.
        """
        header: dict[str, list[str]] = {}

        # Group the raw header fields by lower-cased name in a single pass over the header list. Grouping case-insensitively keeps names
        # differing only in case (e.g. "X-Foo" and "x-foo") in one entry, and a stable order keeps the output independent of PYTHONHASHSEED.
        # Do not call get_all() per name here: each call scans the whole header list, which makes collection
        # quadratic in the number of header fields and lets a message with many small fields stall the parser.
        raw_fields_by_name: dict[str, list[tuple[str, str]]] = {}
        for raw_name, raw_value in msg.raw_items():
            raw_fields_by_name.setdefault(raw_name.lower(), []).append((raw_name, raw_value))

        for name, raw_fields in raw_fields_by_name.items():
            decoded_values = []

            try:
                for raw_name, raw_value in raw_fields:
                    value = msg.policy.header_fetch_parse(raw_name, raw_value)
                    if value:
                        decoded_values.append(value)
            except (IndexError, AttributeError, TypeError):
                # We have hit a field value parsing error.
                # Try to work around this by using a relaxed policy, if possible.
                # Parsing might not give meaningful results in this case!
                logger.error('Field value parsing error, trying to work around this!')
                # compat32 returns values with 8-bit bytes as Header objects, which are no JSON values
                decoded_values = [str(value) for value in eml_parser.decode.workaround_field_value_parsing_errors(msg, name)]
            except ValueError:
                # extract values using a relaxed policy
                for raw_field in eml_parser.decode.workaround_field_value_parsing_errors(msg, name):
                    field = str(raw_field)
                    # check if this is a RFC2047 encoded field
                    if eml_parser.regexes.email_regex_rfc2047.search(field):
                        decoded_values.append(eml_parser.decode.rfc2047_decode(field))
                    else:
                        logger.error('Field value parsing error, trying to work around this! - %s', field)

            if decoded_values:
                header[name] = decoded_values

        return header

    @staticmethod
    def string_sliding_window_loop(body: str, slice_step: int = 500, max_distance: int = 8192) -> typing.Iterator[str]:
        """Split a large string into consecutive slices which are cut at whitespace.

        Running the regular expressions over a 500K+ body at once causes time and memory issues, so the body is processed in slices.
        A slice is never cut in the middle of a token (URL, address, domain): it ends at the first whitespace found within
        *max_distance* characters after *slice_step* (or at the end of the body). Together the slices cover the complete body without gaps or overlaps.

        Args:
            body: Body to slice into smaller pieces.
            slice_step: Preferred length of a slice.
            max_distance: Maximum number of characters a slice is extended to reach the next whitespace. Tokens longer than
                this are cut. The default is the usual request line limit of web servers, which no sane URL exceeds.

        Yields:
            str: Consecutive slices of the body.
        """
        start = 0
        scanned = 0  # no whitespace was found before this position, so it is not searched again

        while len(body) - start > slice_step:
            end = start + slice_step
            boundary = eml_parser.regexes.window_slice_regex.search(body, max(end, scanned), end + max_distance)
            if boundary:
                end = boundary.start()
            elif len(body) - end <= max_distance:
                # No whitespace, but the body ends within reach, so the last token is complete.
                break
            else:
                scanned = end + max_distance

            yield body[start:end]
            start = end

        yield body[start:]

    def is_file_name(self, domain: str) -> bool:
        """Check whether a domain-like string is rather a file name, e.g. *invoice.pdf*."""
        return domain.rpartition('.')[2].lower() in self._file_extensions

    def get_valid_domain_or_ip(self, data: str) -> str | None:
        """Function to determine if an IP address, Email address, or Domain is valid.

        The result is cached per instance, so `domain_force_tld` and `ip_force_routable` must not be changed after construction.

        Args:
            data (str): Text input which should be validated.

        Returns:
            str: Returns a string of the validated IP address or the host.
        """
        return self._cached_valid_domain_or_ip(data)

    def _get_valid_domain_or_ip(self, data: str) -> str | None:
        """Uncached implementation of `get_valid_domain_or_ip()`."""
        host = data.rpartition('@')[-1].strip(' \r\n\t[]')
        try:
            # Zone index support was added to ipaddress in Python 3.9
            addr, _, _ = host.partition('%')
            valid_ip = ipaddress.ip_address(addr)
            if self.ip_force_routable:
                # Not a precise filter for IPv4/IPv6 addresses. Can be enhanced with pconf whiteip ranges
                if valid_ip.is_global and not valid_ip.is_reserved:
                    return str(valid_ip)
            else:
                return str(valid_ip)
        except ValueError:
            # A top level domain is never numeric (RFC 3696, section 2): this rejects invalid addresses ("999.1.1.1") and version numbers ("v1.20.30").
            if host.rstrip('.').rpartition('.')[2].isdecimal():
                return None

            # _psl uses self.domain_force_tld
            valid_domain = self._psl.publicsuffix(host)
            if valid_domain:
                return host

        return None

    @staticmethod
    def parse_authentication_results(header: dict[str, list[str]]) -> dict[str, list[str]]:
        """Extract the results of the e-mail authentication methods (SPF, DKIM, DMARC, ARC, ...) reported by the receiving servers.

        The headers *Authentication-Results* (RFC 8601) and *Received-SPF* (RFC 7208) are evaluated. Comments are ignored and
        so are properties like `header.d=` of a method. Note that these headers are only meaningful if they were added by
        a server you trust; a sender can forge them, and mail from outside of your infrastructure may carry anything.

        Args:
            header: The parsed headers (lower-cased names, list of values).

        Returns:
            dict: The results per method, in the order of occurrence, e.g. `{'spf': ['pass'], 'dkim': ['pass', 'fail']}`.
        """
        results: dict[str, list[str]] = {}

        for value in header.get('authentication-results', []):
            without_comments = eml_parser.decode.noparenthesis(str(value), ' ')
            for method, result in eml_parser.regexes.authentication_result_regex.findall(without_comments):
                results.setdefault(method.lower(), []).append(result.lower())

        for value in header.get('received-spf', []):
            spf_result = eml_parser.regexes.received_spf_regex.match(str(value))
            if spf_result:
                results.setdefault('spf', []).append(spf_result.group(1).lower())

        return results

    def get_share_host(self, share: str) -> str | None:
        """Get the host of a remote file share reference (see `regexes.unc_regex`) if it is a domain or an IP address.

        A bare NetBIOS name such as *fileserver* is a host of the local network and no indicator; *localhost* is local as well.
        Encoded IPv6 addresses (`2001-db8--1.ipv6-literal.net`) are decoded and numeric hosts (a decimal IPv4 address) are resolved like in the URLs.

        Args:
            share: A match of `regexes.unc_regex`.

        Returns:
            str: The domain or IP address, or None.
        """
        match = eml_parser.regexes.unc_regex.match(share)
        if match is None:
            return None

        host = (match.group('unc_host') or match.group('url_host')).partition('@')[0].lower()  # `@SSL` and `@port` select WebDAV
        if host.endswith('.ipv6-literal.net'):
            host = host.removesuffix('.ipv6-literal.net').replace('-', ':')

        if '.' in host or ':' in host:
            return self.get_valid_domain_or_ip(host)

        return self.get_obfuscated_ip(host)

    @staticmethod
    def get_ascii_host(host: str) -> str | None:
        """Convert the host name of an URL to the ASCII form a browser resolves (domain to ASCII of the WHATWG URL standard).

        The host is percent-decoded and mapped with UTS #46, non-transitional like browsers: upper case and full width characters
        are folded, ignored characters such as U+200B or U+00AD are dropped and the ideographic full stop separates labels.
        Non-ASCII labels are converted to punycode (`аpple.com` with a Cyrillic "а" is `xn--pple-43d.com`, `faß.de` is
        `xn--fa-hia.de`). Unlike the `idna` codecs, symbols such as emoji are accepted, as browsers do (`💩.la` is `xn--ls8h.la`).

        Args:
            host (str): The host name of an URL.

        Returns:
            str: The host name in ASCII, or None if a browser rejects it (a disallowed or forbidden code point, a misplaced joiner,
            a label violating the bidi rule or starting with a combining mark).
        """
        if not host.isascii() or '%' in host:
            try:
                labels = idna.uts46_remap(urllib.parse.unquote(host), std3_rules=False, transitional=False).split('.')
                for position, label in enumerate(labels):
                    if label.isascii():
                        continue

                    idna.check_initial_combiner(label)
                    idna.check_bidi(label)
                    if not all(idna.valid_contextj(label, index) for index, char in enumerate(label) if char in '‌‍'):
                        return None

                    labels[position] = f'xn--{label.encode("punycode").decode("ascii")}'
            except idna.IDNAError:
                return None

            host = '.'.join(labels)

        return None if eml_parser.regexes.forbidden_domain_char_regex.search(host) else host

    def get_obfuscated_ip(self, host: str) -> str | None:
        """Resolve a host which is an IPv4 address in a notation browsers accept, e.g. `3232235777`, `0xC0A80101`, `0300.0250.0.1` or `127.1`.

        Args:
            host (str): The host name of an URL.

        Returns:
            str: The address in dotted decimal notation (if it passes the IP validation of this instance) or None.
        """
        if not eml_parser.regexes.ipv4_obfuscated_regex.fullmatch(host):
            return None

        try:
            return self.get_valid_domain_or_ip(socket.inet_ntoa(socket.inet_aton(host)))
        except OSError:
            return None

    def clean_found_uri(self, url: str) -> str | None:
        """Function for validating URLs from the input string.

        Args:
            url (str): Text input which should have a single URL validated.

        Returns:
            str: Returns a valid URL, if found in the input string.
        """
        if '&' in url:
            url = html.unescape(url)

        if not any(dot in url for dot in '.。．｡') and '[' not in url and not eml_parser.regexes.url_numeric_host_regex.match(url.lstrip(_URL_LEADING_JUNK)):
            # if we found a URL like e.g. http://afafasasfasfas; that makes no
            # sense, thus skip it, but include http://[2001:db8::1] and http://3232235777 (a numeric host is an IPv4 address)
            # Browsers also separate the labels of a host by the ideographic and full width full stops (http://example。com).
            return None

        try:
            # Remove leading spaces and quote characters
            url = url.lstrip(_URL_LEADING_JUNK).replace('\r', '').replace('\n', '').replace('\t', '')
            url = urllib.parse.urlparse(url).geturl()
            scheme_url = url
            if url.startswith('//'):
                # protocol-relative URL, i.e. the scheme of the document is used
                scheme_url = f'noscheme:{url}'
            elif ':/' not in scheme_url:
                scheme_url = f'noscheme://{url}'

            _hostname = urllib.parse.urlparse(scheme_url).hostname

            if _hostname is None:
                return None

            host = _hostname.rstrip('.')

            # Without a scheme, a host without a dot or with a file extension is a relative reference like "images/logo.png", not a host.
            is_relative_reference = scheme_url.startswith('noscheme:') and ('.' not in host or self.is_file_name(host))

            if is_relative_reference or (self.get_valid_domain_or_ip(host) is None and self.get_obfuscated_ip(host) is None):
                return None
        except ValueError:
            logger.warning('Unable to parse URL - %s', url)
            return None

        # let's try to be smart by stripping of noisy bogus parts
        url = _URL_NOISE_REGEX.split(url, maxsplit=1)[0]

        # filter bogus URLs
        if url.endswith('://'):
            return None

        return url

    def get_uri_ondata(self, body: str) -> list[str]:
        """Function for extracting URLs from the input string.

        Args:
            body (str): Text input which should be searched for URLs.

        Returns:
            list: Returns a list of URLs found in the input string.
        """
        if self.include_www:
            url_regex, comma_regex = eml_parser.regexes.url_regex_www, eml_parser.regexes.url_regex_www_comma
        else:
            url_regex, comma_regex = eml_parser.regexes.url_regex_simple, eml_parser.regexes.url_regex_comma

        # Several URLs separated by commas only are matched as one, split them.
        candidates: list[str] = []
        for found_url in url_regex.findall(body):
            candidates.extend(comma_regex.split(found_url))

        if self.include_href:
            for attribute_value in eml_parser.regexes.findall_href(body):
                candidates.append(eml_parser.decode.normalize_attribute_url(attribute_value))

        found_urls: dict[str, None] = {}
        for candidate in candidates:
            clean_uri = self.clean_found_uri(candidate)
            if clean_uri is not None:
                found_urls[clean_uri] = None

        return list(found_urls)

    def headeremail2list(self, header: str) -> list[str]:
        """Parses a given header field with e-mail addresses to a list of e-mail addresses.

        Args:
            header (str): The header field to decode.

        Returns:
            list: Returns a list of strings which represent e-mail addresses.
        """
        if self.msg is None:
            raise ValueError('msg is not set.')

        try:
            field = email.utils.getaddresses(self.msg.get_all(header, []))
        except (IndexError, AttributeError):
            field = email.utils.getaddresses(eml_parser.decode.workaround_bug_27257(self.msg, header, self.email_regex))
        except ValueError:
            field = []

            for raw_value in eml_parser.decode.workaround_field_value_parsing_errors(self.msg, header):
                v = eml_parser.decode.rfc2047_decode(raw_value).replace('\n', '').replace('\r', '')

                try:
                    parsing_result: dict[str, typing.Any] = {}
                    parser_cls = typing.cast('email.headerregistry.AddressHeader', email.headerregistry.HeaderRegistry()[header])
                    parser_cls.parse(v, parsing_result)
                    for group in parsing_result['groups']:
                        for address in group.addresses:
                            field.append((address.display_name, address.addr_spec))
                except (AttributeError, IndexError, ValueError):
                    # The stdlib address/header parser can itself raise on certain malformed
                    # values (e.g. an unquoted display name ending in a bare period, such as
                    # "Test.<test@example.com>"). The exact exception type raised for this
                    # case has varied across Python versions, so we defensively catch it here
                    # too and fall back to a best-effort regex extraction of e-mail addresses.
                    logger.exception('Field value parsing error while parsing "%s", falling back to regex extraction!', v)
                    for address in self.email_regex.findall(v):
                        field.append(('', address))

        addresses = []

        for _, address in field:
            if address == '':
                continue

            if self.email_force_tld and not eml_parser.regexes.email_force_tld_regex.match(address):
                continue

            addresses.append(address.lower())

        return addresses

    @staticmethod
    def is_text_part(msg: email.message.Message, filename: str) -> bool:
        """Check whether a part is text which is to be scanned like the body.

        These are text parts (unless they are attachments) and attachments which carry links, i.e. scripts, shortcuts, web pages, SVG, ...
        Data attachments (XML, JSON, CSV, ...) are not scanned, and neither are attachments larger than `MAX_TEXT_ATTACHMENT_SIZE`.
        """
        is_attachment = msg.get_content_disposition() == 'attachment'
        is_text = (
            (msg.get_content_maintype() == 'text' and not is_attachment)
            or msg.get_content_type() in eml_parser.constants.TEXT_ATTACHMENT_CONTENT_TYPES
            or filename.endswith(eml_parser.constants.TEXT_ATTACHMENT_EXTENSIONS)
        )

        if is_text and is_attachment and len(_payload_text(msg)) > eml_parser.constants.MAX_TEXT_ATTACHMENT_SIZE:
            logger.warning('Text attachment "%s" is larger than %d bytes, it is not scanned.', filename, eml_parser.constants.MAX_TEXT_ATTACHMENT_SIZE)
            return False

        return is_text

    def _get_raw_body_text(self, msg: email.message.Message) -> list[BodyPart]:
        """Retrieve all text parts of an e-mail, i.e. the text parts and the attachments which are scanned as text (see `is_text_part()`).

        Args:
            msg (email.message.Message): The actual e-mail message or sub-message.

        Returns:
            list: The text parts, in the order of the message.

        Raises:
            RecursionError: If the parts are nested deeper than `MULTIPART_RECURSION_LIMIT`.
        """
        body_parts: list[BodyPart] = []

        for part, boundary in iter_parts(msg, self.MULTIPART_RECURSION_LIMIT):
            if part.is_multipart():
                continue

            # Treat text document attachments as belonging to the body of the mail.
            # Attachments with a file-extension of .htm/.html are implicitly treated
            # as text as well in order not to escape later checks (e.g. URL scan).
            filename = _filename(part).lower()

            if not self.is_text_part(part, filename):
                continue

            encoding = part.get('content-transfer-encoding', '').lower()
            text = eml_parser.decode.decode_body(typing.cast('bytes', part.get_payload(decode=True)), part.get_content_charset())

            headers = eml_parser.decode.header_items(part)
            body_parts.append(BodyPart(encoding, text, headers, boundary))

        return body_parts

    @staticmethod
    def get_file_hash(data: bytes) -> dict[str, str]:
        """Generate hashes of various types (``MD5``, ``SHA-1``, ``SHA-256``, ``SHA-512``) for the provided data.

        Args:
          data (bytes): The data to calculate the hashes on.

        Returns:
          dict: Returns a dict with as key the hash-type and value the calculated hash.
        """
        return {hash_type: EmlParser.get_hash(data, hash_type) for hash_type in HASH_TYPES}

    @staticmethod
    def get_hash(value: str | bytes, hash_type: str) -> str:
        """Generate a hash of type *hash_type* for a given value.

        Args:
            value: String or bytes object to calculate the hash on.
            hash_type: Hash type to use, can be any of 'md5', 'sha1', 'sha256', 'sha512'.

        Returns:
            str: Returns the calculated hash as a string.
        """
        if hash_type not in HASH_TYPES:
            raise ValueError(f'Invalid hash type requested - "{hash_type}"')

        if isinstance(value, str):
            value = value.encode('utf-8')

        return hashlib.new(hash_type, value).hexdigest()

    def _traverse_multipart(self, msg: email.message.Message) -> list[dict[str, typing.Any]]:
        """Traverse all parts of an e-mail and collect the attachments.

        Args:
            msg (email.message.Message): An e-mail message object.

        Returns:
            list: The attachments (see `_prepare_multipart_part_attachment()`), in the order of the message.

        Raises:
            RecursionError: If the parts are nested deeper than `MULTIPART_RECURSION_LIMIT`.
        """
        # Shared by all parts, numbers the attachments without a file name.
        counter = itertools.count()
        attachments = []

        for part, _ in iter_parts(msg, self.MULTIPART_RECURSION_LIMIT):
            # An attached e-mail message (message/rfc822) is added to the attachments apart from parsing its parts.
            # Without a Content-Type field, get_content_type() returns the default of the enclosing multipart.
            is_attached_message = 'content-type' in part and part.get_content_type() == 'message/rfc822'

            if part.is_multipart() and not is_attached_message:
                continue

            attachment = self._prepare_multipart_part_attachment(part, counter)
            if attachment is not None:
                attachments.append(attachment)

        return attachments

    def _prepare_multipart_part_attachment(self, msg: email.message.Message, counter: collections.abc.Iterator[int]) -> dict[str, typing.Any] | None:
        """Extract meta-information from a multipart-part.

        Args:
            msg (email.message.Message): An e-mail message object.
            counter (Iterator[int]): Iterator shared by all parts of one message, used for generating attachments
                file-names in case there are none found in the header.

        Returns:
            dict: The original headers of the part, hash check-sums, size, file extension and real mime-type,
                or None if the part is no attachment.
        """
        # Any part which is not text is an attachment, and so is text with a disposition other than inline.
        has_attachment_disposition = 'content-disposition' in msg and msg.get_content_disposition() != 'inline'

        if not has_attachment_disposition and msg.get_content_maintype() == 'text':
            return None

        if msg.get_content_type() == 'message/rfc822':
            data = self._get_embedded_message_bytes(msg)
        else:
            data = typing.cast('bytes', msg.get_payload(decode=True))

        part_number = next(counter)
        filename = _filename(msg)

        if filename:
            filename = eml_parser.decode.decode_field(filename)
        else:
            filename = f'part-{part_number:03d}'

        attachment: dict[str, typing.Any] = {'filename': filename, 'size': len(data)}

        # in case there is no extension pathlib.Path(filename).suffix returns an empty string
        if extension := pathlib.Path(filename).suffix:
            # strip leading dot and lower-case
            attachment['extension'] = extension[1:].lower()

        attachment['hash'] = self.get_file_hash(data)

        mime_type, mime_type_short = self.get_mime_type(data)

        if anomalies := eml_parser.anomalies.find_filename_anomalies(filename, data, mime_type_short):
            attachment['anomaly'] = anomalies

        if mime_type is not None and mime_type_short is not None:
            attachment['mime_type'] = mime_type
            attachment['mime_type_short'] = mime_type_short
        elif magic is not None:
            logger.warning('Error determining attachment mime-type - "%s"', filename)

        if self.include_attachment_data:
            attachment['raw'] = base64.b64encode(data)

        content_headers: dict[str, list[str]] = {}
        for name, value in eml_parser.decode.header_items(msg):
            content_headers.setdefault(name.lower(), []).append(str(value))
        attachment['content_header'] = content_headers

        if self.part_hook is not None:
            self.part_hook(
                PartData(
                    kind='attachment',
                    data=data,
                    sha256=attachment['hash']['sha256'],
                    content_type=msg.get_content_type(),
                    filename=filename,
                    content_headers=content_headers,
                    boundary=None,
                )
            )

        return attachment

    @staticmethod
    def _get_embedded_message_bytes(msg: email.message.Message) -> bytes:
        """Serialize the e-mail message attached in a *message/rfc822* part.

        Args:
            msg (email.message.Message): The *message/rfc822* part.

        Returns:
            bytes: The attached message, text which cannot be encoded as declared (lone surrogates, a wrong charset) is replaced.
        """
        payload = typing.cast('list[email.message.Message]', msg.get_payload())
        if len(payload) > 1:
            logger.warning('More than one payload for "message/rfc822" part detected. This is not supported, please report!')

        try:
            return payload[0].as_bytes(policy=email.policy.default.clone(max_line_length=0))
        except (AttributeError, IndexError, UnicodeEncodeError):
            # AttributeError and IndexError: the stdlib address parser fails on a header field while refolding it.
            custom_policy = email.policy.compat32.clone(max_line_length=0)

        try:
            return payload[0].as_bytes(policy=custom_policy)
        except UnicodeEncodeError:
            pass

        try:
            return payload[0].as_string(policy=custom_policy).encode('utf-8', 'replace')
        except (LookupError, TypeError, UnicodeEncodeError, email.errors.MessageError):
            # The text generator re-encodes 8-bit text with the declared charset, which fails for unknown, unsuitable (UTF-16)
            # or RFC 2231 charsets, and refuses header fields with line breaks. Written as is instead: text as UTF-8, 8-bit data unchanged.
            logger.warning('The message in a "message/rfc822" part cannot be serialized, writing it without re-encoding.')

        serialized = io.BytesIO()
        _Utf8BytesGenerator(serialized, mangle_from_=False, policy=_UNFOLDED_UTF8_POLICY).flatten(payload[0])
        return serialized.getvalue()

    @staticmethod
    def get_mime_type(data: bytes) -> tuple[str, str] | tuple[None, None]:
        """Get mime-type information based on the provided bytes object.

        Args:
            data: Binary data.

        Returns:
            typing.Tuple[str, str]: Identified mime information and mime-type. If **magic** is not available, returns *None, None*.
                                    E.g. *"ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)", "application/x-sharedlib"*
        """
        if magic is None:
            return None, None

        detected = magic.detect_from_content(data)
        return detected.name, detected.mime_type
