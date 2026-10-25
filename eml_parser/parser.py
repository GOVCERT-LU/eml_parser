"""eml_parser serves as a python module for parsing eml files and returning various information found in the e-mail as well as computed information."""

import base64
import binascii
import collections
import collections.abc
import datetime as dt
import email
import email.errors
import email.headerregistry
import email.message
import email.policy
import email.utils
import functools
import hashlib
import ipaddress
import itertools
import logging
import os.path
import pathlib
import re
import socket
import string
import typing
import urllib.parse
import uuid
from html import unescape

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


@functools.cache
def get_public_suffix_list(accept_unknown: bool) -> publicsuffixlist.PublicSuffixList:
    """Return the public suffix list; it is parsed once per setting and shared, as parsing it takes about 40 ms and it is read-only afterwards.

    Args:
        accept_unknown: Whether names with an unknown top level domain are accepted.

    Returns:
        The parsed public suffix list.
    """
    return publicsuffixlist.PublicSuffixList(accept_unknown=accept_unknown)


# Characters allowed in a header field name (RFC 5322 ftext): printable ASCII except space and colon.
FIELD_NAME_BYTES = (string.ascii_letters + string.digits + string.punctuation.replace(':', '')).encode()


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

        if field_name and not field_name.translate(None, FIELD_NAME_BYTES):
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
    def _fetch_fixed_header(self, name: str, value: str) -> tuple[str, str | None]:
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

        elif header in ('sender', 'resent-sender', 'to', 'resent-to', 'cc', 'resent-cc', 'bcc', 'resent-bcc', 'from', 'resent-from', 'reply-to'):
            try:
                return super().header_fetch_parse(name, value), None
            except RecursionError:
                # This can happen when the recursion gets too deep in in the stdlib recursive descent parser.
                # In this case, the header is certainly pathological. We still try to extract some addresses.
                m = self.email_regex.findall(value)
                return ', '.join(m), None

        return super().header_fetch_parse(name, value), None


class EmlParser:
    """eml-parser class."""

    MULTIPART_RECURSION_LIMIT = 100

    # pylint: disable=too-many-arguments
    def __init__(
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
    ) -> None:
        """Initialisation.

        Args:
            include_raw_body (bool, optional): Boolean parameter which indicates whether
                                               to include the original file contents in
                                               the returned structure. Default is False.
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

        """
        self.include_raw_body = include_raw_body
        self.include_attachment_data = include_attachment_data
        # If no pconf was specified, default to empty dict
        self.pconf = pconf or {}
        self.ignore_bad_start = ignore_bad_start
        self.email_force_tld = email_force_tld
        self.domain_force_tld = domain_force_tld
        self.ip_force_routable = ip_force_routable
        self.parse_attachments = parse_attachments
        self.include_www = include_www
        self.include_href = include_href
        self._psl = get_public_suffix_list(not self.domain_force_tld)
        # A file extension which is a TLD (or becomes one) is a domain and not a file name, so the public suffix list decides.
        self._file_extensions = frozenset(
            ext for ext in eml_parser.constants.FILE_EXTENSIONS if self._psl.publicsuffix(f'x.{ext}', accept_unknown=False) is None
        )
        # The same hosts occur over and over in a body; the verdict only depends on settings which are constant for an instance.
        self._cached_valid_domain_or_ip = functools.lru_cache(maxsize=32768)(self._get_valid_domain_or_ip)

        self.email_regex = eml_parser.regexes.email_force_tld_regex if email_force_tld else eml_parser.regexes.email_no_force_tld_regex
        self.policy = policy or CustomPolicy(email_regex=self.email_regex)

        # If no whitelisting is required, set to emtpy list
        if 'whiteip' not in self.pconf:
            self.pconf['whiteip'] = []
        # If no whitelisting is required, set to emtpy list
        if 'whitefor' not in self.pconf:
            self.pconf['whitefor'] = []

        self.msg: email.message.Message | None = None

    def decode_email(self, eml_file: os.PathLike, ignore_bad_start: bool = False) -> dict:
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
        eml_file_path = pathlib.Path(eml_file)

        with eml_file_path.open('rb') as fp:
            raw_email = fp.read()

        return self.decode_email_bytes(raw_email, ignore_bad_start=ignore_bad_start)

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
        _eml_file = eml_file

        if self.ignore_bad_start or ignore_bad_start:
            # Skip any garbage in front of the first header field.
            # The data is only sliced, so line endings and the message body stay untouched.
            _eml_file = eml_file[find_header_start(eml_file) :]

        self.msg = email.message_from_bytes(_eml_file, policy=self.policy)
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
            payload = part.get_payload()

            if part.is_multipart():
                parts.extend(typing.cast('list[email.message.Message]', payload))
            elif part.get_content_maintype() == 'multipart' and isinstance(payload, str):
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

                part.set_param('boundary', boundary)
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
        header: dict[str, typing.Any] = {}
        report_struc: dict[str, typing.Any] = {}  # Final structure
        headers_struc: dict[str, typing.Any] = {}  # header_structure
        bodys_struc: dict[str, typing.Any] = {}  # body structure

        if self.msg is None:
            raise ValueError('msg is not set.')

        # parse and decode subject
        subject = self.msg.get('subject', '')
        headers_struc['subject'] = eml_parser.decode.decode_field(subject)

        # If parsing had problems, report it
        if self.msg.defects:
            headers_struc['defect'] = []
            for exception in self.msg.defects:
                # str() of most stdlib defects is empty, the class name identifies the problem
                headers_struc['defect'].append(f'{type(exception).__name__}: {exception}' if str(exception) else type(exception).__name__)

        # parse and decode "from"
        # @TODO verify if this hack is necessary for other e-mail fields as well
        try:
            msg_header_field = str(self.msg.get('from', '')).lower()
        except (IndexError, AttributeError):
            # We have hit current open issue #27257
            # https://bugs.python.org/issue27257
            # The field will be set to emtpy as a workaround.
            #
            logger.exception('We hit bug 27257!')

            _from = eml_parser.decode.workaround_bug_27257(self.msg, 'from', self.email_regex)
            del self.msg['from']

            if _from:
                self.msg.add_header('from', _from[0])
                __from = _from[0].lower()
            else:
                self.msg.add_header('from', '')
                __from = ''

            msg_header_field = __from
        except ValueError:
            _field_item = eml_parser.decode.workaround_field_value_parsing_errors(self.msg, 'from')
            msg_header_field = eml_parser.decode.rfc2047_decode(_field_item[0]).lower()

        if msg_header_field != '':
            from_ = email.utils.parseaddr(msg_header_field)

            if (from_ and from_ == ('', '')) or not isinstance(from_, collections.abc.Sequence):
                m = self.email_regex.search(msg_header_field)
                if m:
                    headers_struc['from'] = m.group(1)
                else:
                    logger.warning('FROM header parsing failed.')
                    headers_struc['from'] = msg_header_field

            else:
                headers_struc['from'] = from_[1]

        # parse and decode "to"
        headers_struc['to'] = self.headeremail2list('to')
        # parse and decode "cc"
        headers_struc['cc'] = self.headeremail2list('cc')
        if not headers_struc['cc']:
            headers_struc.pop('cc')

        # parse and decode delivered-to
        headers_struc['delivered_to'] = self.headeremail2list('delivered-to')
        if not headers_struc['delivered_to']:
            headers_struc.pop('delivered_to')

        # parse and decode Date
        # If date field is present
        # (the default date is used if the field is absent)
        date_value: str | None = self.msg.get('date')
        headers_struc['date'] = dt.datetime.fromisoformat(eml_parser.decode.default_date if date_value is None else date_value)

        # mail receiver path / parse any domain, e-mail
        # @TODO parse case where domain is specified but in parentheses only an IP
        headers_struc['received'] = []
        headers_struc['received_email'] = []
        headers_struc['received_domain'] = []
        headers_struc['received_ip'] = []
        try:
            found_smtpin: collections.Counter = collections.Counter()  # Array for storing potential duplicate "HOP"

            for received_line in self.msg.get_all('received', []):
                line = str(received_line).lower()

                received_line_flat = re.sub(r'\s+', ' ', line)

                # Parse and split routing headers.
                # Return dict of list
                #   date string
                #   from list
                #   for list
                #   by list
                #   with string
                #   warning list
                parsed_routing = eml_parser.routing.parserouting(received_line_flat, self.email_regex)

                # If required collect the IP of the gateway that have injected the mail.
                # Iterate all parsed item and find IP
                # It is parsed from the MOST recent to the OLDEST (from IN > Out)
                # We match external IP from the most "OUT" Found.
                # Warning .. It may be spoofed !!
                # It add a warning if multiple identical items are found.

                if self.pconf.get('byhostentry'):
                    for by_item in parsed_routing.get('by', []):
                        for byhostentry_ in self.pconf['byhostentry']:
                            byhostentry = byhostentry_.lower()

                            if byhostentry in by_item:
                                # Save the last Found.. ( most external )
                                headers_struc['received_src'] = parsed_routing.get('from')

                                # Increment watched by detection counter, and warn if needed
                                found_smtpin[byhostentry] += 1
                                if found_smtpin[byhostentry] > 1:  # Twice found the header...
                                    if parsed_routing.get('warning'):
                                        parsed_routing['warning'].append(['Duplicate SMTP by entrypoint'])
                                    else:
                                        parsed_routing['warning'] = ['Duplicate SMTP by entrypoint']

                headers_struc['received'].append(parsed_routing)

                # Parse IPs in "received headers"
                ips_in_received_line = eml_parser.regexes.findall_ipv6(received_line_flat) + eml_parser.regexes.ipv4_regex.findall(received_line_flat)
                for ip in ips_in_received_line:
                    if ip in self.pconf['whiteip']:
                        continue
                    valid_ip = self.get_valid_domain_or_ip(ip)
                    if valid_ip:
                        headers_struc['received_ip'].append(valid_ip)
                    else:
                        logger.debug('Invalid IP in received line - "%s"', ip)

                # search for domain
                for m in eml_parser.regexes.recv_dom_regex.findall(received_line_flat):
                    try:
                        _ = ipaddress.ip_address(m)  # type of findall is list[str], so this is correct
                    except ValueError:
                        # we find IPs using the previous IP crawler, hence we ignore them
                        # here.
                        # iff the regex fails, we add the entry
                        headers_struc['received_domain'].append(m)

                # search for e-mail addresses
                for mail_candidate in self.email_regex.findall(received_line_flat):
                    validated_mail_candidate = mail_candidate
                    if self.email_force_tld:
                        validated_mail_candidate = self.get_valid_domain_or_ip(mail_candidate)
                    if validated_mail_candidate is not None and validated_mail_candidate not in parsed_routing.get('for', []):
                        headers_struc['received_email'] += [validated_mail_candidate]

        except TypeError:  # Ready to parse email without received headers.
            logger.exception('Exception occurred while parsing received lines.')

        # Concatenate for emails into one array | uniq
        # for rapid "find"
        headers_struc['received_foremail'] = []
        if 'received' in headers_struc:
            for _parsed_routing in headers_struc['received']:
                for itemfor in _parsed_routing.get('for', []):
                    if itemfor not in self.pconf['whitefor']:
                        headers_struc['received_foremail'].append(itemfor)

        # Uniq data found
        headers_struc['received_email'] = list(dict.fromkeys(headers_struc['received_email']))
        headers_struc['received_domain'] = list(dict.fromkeys(headers_struc['received_domain']))
        headers_struc['received_ip'] = list(dict.fromkeys(headers_struc['received_ip']))

        # Clean up if empty
        if not headers_struc['received_email']:
            del headers_struc['received_email']

        if 'received_foremail' in headers_struc:
            if not headers_struc['received_foremail']:
                del headers_struc['received_foremail']
            else:
                headers_struc['received_foremail'] = list(dict.fromkeys(headers_struc['received_foremail']))

        if not headers_struc['received_domain']:
            del headers_struc['received_domain']

        if not headers_struc['received_ip']:
            del headers_struc['received_ip']
        ####################

        # Parse text body
        raw_body = self.get_raw_body_text(self.msg)

        if self.include_raw_body:
            bodys_struc['raw_body'] = raw_body

        bodys = {}

        # Is it a multipart email ?
        if len(raw_body) == 1:
            multipart = False
        else:
            multipart = True

        for body_tup in raw_body:
            bodie: dict[str, typing.Any] = {}
            _, body, body_multhead, boundary = body_tup
            # Parse any URLs and mail found in the body
            list_observed_urls: list[str] = []
            list_observed_urls_noscheme: list[str] = []
            list_observed_unc: dict[str, int] = {}
            list_observed_email: dict[str, int] = {}
            list_observed_dom: dict[str, int] = {}
            list_observed_ip: dict[str, int] = {}

            # If we start directly a findall on 500K+ body we got time and memory issues...
            # if more than 4K.. lets cheat, we will cut around the thing we search "://, @, ."
            # in order to reduce regex complexity.
            # Namespace declarations (Outlook HTML, SVG, XHTML) are identifiers, not links, and would be reported as indicators on nearly every mail.
            for body_slice in self.string_sliding_window_loop(eml_parser.regexes.xmlns_declaration_regex.sub(' ', body)):
                for url_match in self.get_uri_ondata(body_slice):
                    if ':/' in url_match[:10]:
                        list_observed_urls.append(url_match)
                    else:
                        list_observed_urls_noscheme.append(url_match)

                for share in eml_parser.regexes.unc_regex.finditer(body_slice):
                    list_observed_unc[share.group(0).rstrip('.,;')] = 1

                for match in self.email_regex.findall(body_slice):
                    valid_email = self.get_valid_domain_or_ip(match.lower())
                    if valid_email:
                        list_observed_email[match.lower()] = 1

                for match in eml_parser.regexes.dom_regex.findall(body_slice):
                    if self.is_file_name(match):
                        continue

                    valid_domain = self.get_valid_domain_or_ip(match.lower())
                    if valid_domain:
                        list_observed_dom[match.lower()] = 1

                for match in eml_parser.regexes.ipv4_regex.findall(body_slice) + eml_parser.regexes.findall_ipv6(body_slice):
                    if ':' in match and not any(char.isdigit() for char in match) and match.count(':') < 3:
                        # "::" or a scope resolution like "Add::dead" is not an address
                        continue

                    valid_ip = self.get_valid_domain_or_ip(match.lower())
                    if valid_ip in self.pconf['whiteip']:
                        continue
                    if valid_ip:
                        list_observed_ip[valid_ip] = 1

            # URLs do not necessarily appear as-is in the body, as they may contain escaped entities.
            # For this reason, we have to extract the domains again from each parsed URL.
            # Run once over the deduplicated URLs after slicing to keep the cost linear in the body size.
            # The URLs are percent-decoded, as the target of a redirector is usually encoded (`?url=https%3A%2F%2Fevil.example%2F`).
            for url in dict.fromkeys([*list_observed_urls, *list_observed_urls_noscheme]):
                for match in eml_parser.regexes.dom_regex.findall(urllib.parse.unquote(url)):
                    if self.is_file_name(match):
                        continue

                    valid_domain = self.get_valid_domain_or_ip(match.lower())
                    if valid_domain:
                        list_observed_dom[match.lower()] = 1

                # http://3232235777/ is a valid URL for browsers but contains no dotted IP address
                try:
                    host = urllib.parse.urlparse(url if ':/' in url else '//' + url).hostname
                except ValueError:
                    host = None
                obfuscated_ip = self.get_obfuscated_ip(host.rstrip('.')) if host else None
                if obfuscated_ip and obfuscated_ip not in self.pconf['whiteip']:
                    list_observed_ip[obfuscated_ip] = 1

            # The host of a remote file share is the indicator: it is contacted (and authenticated to) when the path is opened.
            for share_host in filter(None, map(self.get_share_host, list_observed_unc)):
                try:
                    ipaddress.ip_address(share_host)
                except ValueError:
                    list_observed_dom[share_host] = 1
                else:
                    if share_host not in self.pconf['whiteip']:
                        list_observed_ip[share_host] = 1

            # Report uri,email and observed domain or hash if no raw body
            if self.include_raw_body:
                if list_observed_urls:
                    bodie['uri'] = list(dict.fromkeys(list_observed_urls))

                if list_observed_urls_noscheme:
                    bodie['uri_noscheme'] = list(dict.fromkeys(list_observed_urls_noscheme))

                if list_observed_unc:
                    bodie['unc'] = list(list_observed_unc)

                if list_observed_email:
                    bodie['email'] = list(list_observed_email)

                if list_observed_dom:
                    bodie['domain'] = list(list_observed_dom)

                if list_observed_ip:
                    bodie['ip'] = list(list_observed_ip)

            else:
                if list_observed_urls:
                    bodie['uri_hash'] = [self.get_hash(element.lower(), 'sha256') for element in dict.fromkeys(list_observed_urls)]
                if list_observed_urls_noscheme:
                    bodie['uri_noscheme_hash'] = [self.get_hash(element.lower(), 'sha256') for element in dict.fromkeys(list_observed_urls_noscheme)]
                if list_observed_unc:
                    bodie['unc_hash'] = [self.get_hash(share.lower(), 'sha256') for share in list_observed_unc]
                if list_observed_email:
                    # Email already lowered
                    bodie['email_hash'] = [self.get_hash(element, 'sha256') for element in list_observed_email]
                if list_observed_dom:
                    bodie['domain_hash'] = [self.get_hash(element, 'sha256') for element in list_observed_dom]
                if list_observed_ip:
                    # IP (v6) already lowered
                    bodie['ip_hash'] = [self.get_hash(element, 'sha256') for element in list_observed_ip]

            # For mail without multipart we will only get the "content....something" headers
            # all other headers are in "header"
            # but we need to convert header tuples in dict..
            # "a","toto"           a: [toto,titi]
            # "a","titi"   --->    c: [truc]
            # "c","truc"
            ch: dict[str, list] = {}
            for header_key, header_value in body_multhead:
                # make sure we are working with strings only
                v = str(header_value)

                # We are using replace . to : for avoiding issue in mongo
                k = header_key.lower().replace('.', ':')  # Lot of lowers, pre-compute :) .

                if multipart:
                    if k in ch:
                        ch[k].append(v)
                    else:
                        ch[k] = [v]
                elif k.startswith('content'):  # otherwise, we got all header headers
                    # if not multipart, store only content-xx related header with part
                    if k in ch:
                        ch[k].append(v)
                    else:
                        ch[k] = [v]

            bodie['content_header'] = ch  # Store content headers dict

            if self.include_raw_body:
                bodie['content'] = body

            # Sometimes bad people play with multiple header instances.
            # We "display" the "LAST" one .. as does thunderbird
            val = ch.get('content-type')
            if val:
                header_val = val[-1]
                bodie['content_type'] = header_val.split(';', 1)[0].strip()

            # Hash the body
            bodie['hash'] = hashlib.sha256(body.encode('utf-8')).hexdigest()

            if boundary is not None:
                # only include boundary key if there is a value set
                bodie['boundary'] = boundary

            uid = str(uuid.uuid4())
            bodys[uid] = bodie

        bodys_struc = bodys

        # Get all other bulk raw headers
        # "a","toto"           a: [toto,titi]
        # "a","titi"   --->    c: [truc]
        # "c","truc"
        #
        # Group the raw header fields by lower-cased name in a single pass over the header list, then iterate
        # over the groups in the order of each name's first occurrence (dicts keep insertion order).
        # Grouping case-insensitively keeps names differing only in case (e.g. "X-Foo" and "x-foo") in one
        # entry, and a stable order keeps the output independent of PYTHONHASHSEED.
        # Do not call get_all() per name here: each call scans the whole header list, which makes collection
        # quadratic in the number of header fields and lets a message with many small fields stall the parser.
        raw_fields_by_name: dict[str, list[tuple[str, str]]] = {}
        for raw_name, raw_value in self.msg.raw_items():
            raw_fields_by_name.setdefault(raw_name.lower(), []).append((raw_name, raw_value))

        for k, raw_fields in raw_fields_by_name.items():
            decoded_values = []

            try:
                for value in (self.msg.policy.header_fetch_parse(n, v) for n, v in raw_fields):
                    if value:
                        decoded_values.append(value)
            except (IndexError, AttributeError, TypeError):
                # We have hit a field value parsing error.
                # Try to work around this by using a relaxed policy, if possible.
                # Parsing might not give meaningful results in this case!
                logger.error('ERROR: Field value parsing error, trying to work around this!')
                decoded_values = eml_parser.decode.workaround_field_value_parsing_errors(self.msg, k)
            except ValueError:
                # extract values using a relaxed policy
                for _field in eml_parser.decode.workaround_field_value_parsing_errors(self.msg, k):
                    # check if this is a RFC2047 encoded field
                    if eml_parser.regexes.email_regex_rfc2047.search(str(_field)):
                        decoded_values.append(eml_parser.decode.rfc2047_decode(str(_field)))
                    else:
                        logger.error('ERROR: Field value parsing error, trying to work around this! - %s', _field)

            if decoded_values:
                if k in header:
                    header[k] += decoded_values
                else:
                    header[k] = decoded_values

        headers_struc['header'] = header

        authentication = self.parse_authentication_results(header)
        if authentication:
            headers_struc['authentication'] = authentication

        # parse attachments
        if self.parse_attachments:
            try:
                report_struc['attachment'] = self.traverse_multipart(self.msg, itertools.count())
            except (binascii.Error, AssertionError):
                # we hit this exception if the payload contains invalid data
                logger.exception('Exception occurred while parsing attachment data. Collected data will not be complete!')
                report_struc['attachment'] = None

            # Dirty hack... transform hash into list.. need to be done in the function.
            # Mandatory to search efficiently in mongodb
            # See Bug 11 of eml_parser
            if not report_struc['attachment']:
                del report_struc['attachment']
            else:
                report_struc['attachment'] = list(report_struc['attachment'].values())

        report_struc['body'] = list(bodys_struc.values())
        # End of dirty hack

        # Get all other bulk headers
        report_struc['header'] = headers_struc

        return report_struc

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
            for method, result in eml_parser.regexes.authentication_result_regex.findall(eml_parser.decode.noparenthesis(str(value), ' ')):
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
            url = unescape(url)

        if '.' not in url and '[' not in url and not eml_parser.regexes.url_numeric_host_regex.match(url.lstrip(' \t\n\r\f\v\'"«»“”‘’')):
            # if we found a URL like e.g. http://afafasasfasfas; that makes no
            # sense, thus skip it, but include http://[2001:db8::1] and http://3232235777 (a numeric host is an IPv4 address)
            return None

        try:
            # Remove leading spaces and quote characters
            url = url.lstrip(' \t\n\r\f\v\'"«»“”‘’').replace('\r', '').replace('\n', '').replace('\t', '')
            url = urllib.parse.urlparse(url).geturl()
            scheme_url = url
            if url.startswith('//'):
                # protocol-relative URL, i.e. the scheme of the document is used
                scheme_url = 'noscheme:' + url
            elif ':/' not in scheme_url:
                scheme_url = 'noscheme://' + url

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
        url = re.split(r"""[', ")}\\]""", url, maxsplit=1)[0]

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
        list_observed_urls: dict[str, int] = {}

        if self.include_www:
            for found_url in eml_parser.regexes.url_regex_www.findall(body):
                for found_url_split in eml_parser.regexes.url_regex_www_comma.split(found_url):
                    clean_uri = self.clean_found_uri(found_url_split)
                    if clean_uri is not None:
                        list_observed_urls[clean_uri] = 1
        else:
            for found_url in eml_parser.regexes.url_regex_simple.findall(body):
                for found_url_split in eml_parser.regexes.url_regex_comma.split(found_url):
                    clean_uri = self.clean_found_uri(found_url_split)
                    if clean_uri is not None:
                        list_observed_urls[clean_uri] = 1

        if self.include_href:
            for found_url in eml_parser.regexes.findall_href(body):
                clean_uri = self.clean_found_uri(eml_parser.decode.normalize_attribute_url(found_url))
                if clean_uri is not None:
                    list_observed_urls[clean_uri] = 1

        return list(list_observed_urls)

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
            _field = eml_parser.decode.workaround_field_value_parsing_errors(self.msg, header)
            field = []

            for raw_value in _field:
                v = eml_parser.decode.rfc2047_decode(raw_value).replace('\n', '').replace('\r', '')

                try:
                    parsing_result: dict[str, typing.Any] = {}
                    parser_cls = typing.cast('email.headerregistry.AddressHeader', email.headerregistry.HeaderRegistry()[header])
                    parser_cls.parse(v, parsing_result)
                    for _group in parsing_result['groups']:
                        for _address in _group.addresses:
                            field.append((_address.display_name, _address.addr_spec))
                except (AttributeError, IndexError, ValueError):
                    # The stdlib address/header parser can itself raise on certain malformed
                    # values (e.g. an unquoted display name ending in a bare period, such as
                    # "Test.<test@example.com>"). The exact exception type raised for this
                    # case has varied across Python versions, so we defensively catch it here
                    # too and fall back to a best-effort regex extraction of e-mail addresses.
                    logger.exception('Field value parsing error while parsing "%s", falling back to regex extraction!', v)

                    for m in self.email_regex.findall(v):
                        field.append(('', m))

        return_field = []

        for m in field:
            if not m[1] == '':
                if self.email_force_tld:
                    if eml_parser.regexes.email_force_tld_regex.match(m[1]):
                        return_field.append(m[1].lower())
                else:
                    return_field.append(m[1].lower())

        return return_field

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

        if is_text and is_attachment and len(msg.get_payload()) > eml_parser.constants.MAX_TEXT_ATTACHMENT_SIZE:
            logger.warning('Text attachment "%s" is larger than %d bytes, it is not scanned.', filename, eml_parser.constants.MAX_TEXT_ATTACHMENT_SIZE)
            return False

        return is_text

    def get_raw_body_text(
        self, msg: email.message.Message, boundary: str | None = None, depth: int = 0
    ) -> list[tuple[typing.Any, typing.Any, typing.Any, str | None]]:
        """This method recursively retrieves all e-mail body parts and returns them as a list.

        Args:
            msg (email.message.Message): The actual e-mail message or sub-message.
            boundary: Used for passing the boundary marker of multipart messages, and used to easier distinguish different parts.
            depth: Parameter used to track the current recursion level.

        Returns:
            list: Returns a list of sets which are in the form of "set(encoding, raw_body_string, message field headers, possible boundary marker)"

        Raises:
            RecursionError: If recursion limit exceeded.
        """
        raw_body: list[tuple[typing.Any, typing.Any, typing.Any, str | None]] = []

        if depth > EmlParser.MULTIPART_RECURSION_LIMIT:
            logger.warning('multi-part nesting limit (%d) exceeded, aborting', EmlParser.MULTIPART_RECURSION_LIMIT)
            raise RecursionError('Recursion limit exceeded')

        if msg.is_multipart():
            boundary = msg.get_boundary(failobj=None)
            for part in msg.get_payload():
                raw_body.extend(self.get_raw_body_text(typing.cast('email.message.Message', part), boundary=boundary, depth=depth + 1))
        else:
            # Treat text document attachments as belonging to the body of the mail.
            # Attachments with a file-extension of .htm/.html are implicitly treated
            # as text as well in order not to escape later checks (e.g. URL scan).

            try:
                filename = msg.get_filename('').lower()
            except (binascii.Error, AssertionError):
                logger.exception('Exception occurred while trying to parse the content-disposition header. Collected data will not be complete.')
                filename = ''

            if self.is_text_part(msg, filename):
                encoding = msg.get('content-transfer-encoding', '').lower()

                raw_body_str = eml_parser.decode.decode_body(typing.cast('bytes', msg.get_payload(decode=True)), msg.get_content_charset())

                # In case we hit bug 27257 or any other parsing error, try to downgrade the used policy
                try:
                    raw_body.append((encoding, raw_body_str, msg.items(), boundary))
                except (AttributeError, TypeError, ValueError):
                    former_policy: email.policy.Policy = msg.policy
                    msg.policy = email.policy.compat32
                    raw_body.append((encoding, raw_body_str, msg.items(), boundary))
                    msg.policy = former_policy

        return raw_body

    @staticmethod
    def get_file_hash(data: bytes) -> dict[str, str]:
        """Generate hashes of various types (``MD5``, ``SHA-1``, ``SHA-256``, ``SHA-512``) for the provided data.

        Args:
          data (bytes): The data to calculate the hashes on.

        Returns:
          dict: Returns a dict with as key the hash-type and value the calculated hash.
        """
        hashalgo = ['md5', 'sha1', 'sha256', 'sha512']
        return {k: EmlParser.get_hash(data, k) for k in hashalgo}

    @staticmethod
    def get_hash(value: str | bytes, hash_type: str) -> str:
        """Generate a hash of type *hash_type* for a given value.

        Args:
            value: String or bytes object to calculate the hash on.
            hash_type: Hash type to use, can be any of 'md5', 'sha1', 'sha256', 'sha512'.

        Returns:
            str: Returns the calculated hash as a string.
        """
        if hash_type not in ('md5', 'sha1', 'sha256', 'sha512'):
            raise ValueError(f'Invalid hash type requested - "{hash_type}"')

        if isinstance(value, str):
            _value = value.encode('utf-8')
        else:
            _value = value

        hash_algo = getattr(hashlib, hash_type)

        return hash_algo(_value).hexdigest()

    def traverse_multipart(self, msg: email.message.Message, counter: collections.abc.Iterator[int], depth: int = 0) -> dict[str, typing.Any]:
        """Recursively traverses all e-mail message multi-part elements and returns in a parsed form as a dict.

        Args:
            msg (email.message.Message): An e-mail message object.
            counter (Iterator[int]): Iterator shared by all parts of one message, used for generating attachments
                file-names in case there are none found in the header.
            depth: Parameter used to track the current recursion level.

        Returns:
            dict: Returns a dict with all original multi-part headers as well as generated hash check-sums,
                date size, file extension, real mime-type.

        Raises:
            RecursionError: If recursion limit exceeded.
        """
        attachments = {}

        if depth > EmlParser.MULTIPART_RECURSION_LIMIT:
            logger.warning('multi-part nesting limit (%d) exceeded, aborting', EmlParser.MULTIPART_RECURSION_LIMIT)
            raise RecursionError('Recursion limit exceeded')

        if msg.is_multipart():
            if 'content-type' in msg:
                if msg.get_content_type() == 'message/rfc822':
                    # This is an e-mail message attachment, add it to the attachment list apart from parsing it
                    attachments.update(self.prepare_multipart_part_attachment(msg, counter))

            for part in msg.get_payload():
                attachments.update(self.traverse_multipart(typing.cast('email.message.EmailMessage', part), counter=counter, depth=depth + 1))
        else:
            return self.prepare_multipart_part_attachment(msg, counter)

        return attachments

    def prepare_multipart_part_attachment(self, msg: email.message.Message, counter: collections.abc.Iterator[int]) -> dict[str, typing.Any]:
        """Extract meta-information from a multipart-part.

        Args:
            msg (email.message.Message): An e-mail message object.
            counter (Iterator[int]): Iterator shared by all parts of one message, used for generating attachments
                file-names in case there are none found in the header.

        Returns:
            dict: Returns a dict with original multi-part headers as well as generated hash check-sums,
                date size, file extension, real mime-type.
        """
        attachment: dict[str, typing.Any] = {}

        # In case we hit bug 27257, try to downgrade the used policy
        try:
            lower_keys = [k.lower() for k in msg.keys()]
        except AttributeError:
            former_policy: email.policy.Policy = msg.policy
            msg.policy = email.policy.compat32
            lower_keys = [k.lower() for k in msg.keys()]
            msg.policy = former_policy

        if ('content-disposition' in lower_keys and msg.get_content_disposition() != 'inline') or msg.get_content_maintype() != 'text':
            # if it's an attachment-type, pull out the filename
            # and calculate the size in bytes
            if msg.get_content_type() == 'message/rfc822':
                payload = msg.get_payload()
                if len(payload) > 1:
                    logger.warning('More than one payload for "message/rfc822" part detected. This is not supported, please report!')

                embedded_message = typing.cast('list[email.message.EmailMessage]', payload)[0]
                try:
                    custom_policy: email.policy.Policy = email.policy.default.clone(max_line_length=0)
                    data = embedded_message.as_bytes(policy=custom_policy)
                except UnicodeEncodeError:
                    custom_policy = email.policy.compat32.clone(max_line_length=0)
                    try:
                        data = embedded_message.as_bytes(policy=custom_policy)
                    except UnicodeEncodeError:
                        # Text which cannot be encoded as declared (lone surrogates, a wrong charset): keep what can be.
                        data = embedded_message.as_string(policy=custom_policy).encode('utf-8', 'replace')

                file_size = len(data)
            else:
                data = typing.cast('bytes', msg.get_payload(decode=True))
                file_size = len(data)

            part_number = next(counter)

            filename = msg.get_filename('')
            if filename == '':
                filename = f'part-{part_number:03d}'
            else:
                filename = eml_parser.decode.decode_field(filename)

            file_id = str(uuid.uuid4())
            attachment[file_id] = {}
            attachment[file_id]['filename'] = filename
            attachment[file_id]['size'] = file_size

            # in case there is no extension pathlib.Path(filename).suffix returns an empty string
            extension = pathlib.Path(filename).suffix
            if extension:
                # strip leading dot and lower-case
                attachment[file_id]['extension'] = extension[1:].lower()

            attachment[file_id]['hash'] = self.get_file_hash(data)

            mime_type, mime_type_short = self.get_mime_type(data)

            anomalies = eml_parser.anomalies.find_filename_anomalies(filename, data, mime_type_short)
            if anomalies:
                attachment[file_id]['anomaly'] = anomalies

            if not (mime_type is None or mime_type_short is None):
                attachment[file_id]['mime_type'] = mime_type
                # attachments[file_id]['mime_type_short'] = attachments[file_id]['mime_type'].split(",")[0]
                attachment[file_id]['mime_type_short'] = mime_type_short
            elif magic is not None:
                logger.warning('Error determining attachment mime-type - "%s"', str(file_id))

            if self.include_attachment_data:
                attachment[file_id]['raw'] = base64.b64encode(data)

            ch: dict[str, list[str]] = {}
            for header_key, header_value in msg.items():
                k = header_key.lower()
                v = str(header_value)

                if k in ch:
                    ch[k].append(v)
                else:
                    ch[k] = [v]

            attachment[file_id]['content_header'] = ch

        return attachment

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
