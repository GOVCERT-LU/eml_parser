"""eml_parser serves as a python module for parsing eml files and returning various information found in the e-mail as well as computed information."""

import binascii
import collections
import dataclasses
import datetime as dt
import email
import email.message
import email.policy
import hashlib
import logging
import os
import pathlib
import re
import typing

import eml_parser.attachments
import eml_parser.decode
import eml_parser.headers
import eml_parser.hosts
import eml_parser.indicators
import eml_parser.mime
import eml_parser.policy
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

__author__ = 'Toth Georges, Jung Paul'
__email__ = 'georges@trypill.org, georges.toth@govcert.etat.lu'
__copyright__ = 'Copyright 2013-2014 Georges Toth, Copyright 2013-present GOVCERT Luxembourg'
__license__ = 'AGPL v3+'

# The policy callers pass to `EmlParser` as `eml_parser.parser.CustomPolicy`.
CustomPolicy = eml_parser.policy.CustomPolicy

_WHITESPACE_RUN_REGEX = re.compile(r"""\s+""")


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
        self.parse_attachments = parse_attachments
        self.part_hook = part_hook

        self.email_regex = eml_parser.regexes.email_force_tld_regex if email_force_tld else eml_parser.regexes.email_no_force_tld_regex
        self.policy = policy or CustomPolicy(email_regex=self.email_regex)
        self._hosts = eml_parser.hosts.HostValidator(domain_force_tld, ip_force_routable)
        self._indicators = eml_parser.indicators.IndicatorFinder(self._hosts, self.email_regex, include_www, include_href)

        # The message being parsed, and the IP addresses of pconf['whiteip'], read at the start of each message (pconf may change between messages).
        self.msg = email.message.Message()
        self._whitelist = eml_parser.hosts.IpWhitelist.from_entries(())

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
            eml_file = eml_file[eml_parser.mime.find_header_start(eml_file) :]

        self.msg = email.message_from_bytes(eml_file, policy=self.policy)
        eml_parser.mime.repair_multipart(self.msg, self.policy)
        eml_parser.policy.limit_header_parsing(self.msg)

        return self._parse_email()

    def _parse_email(self) -> dict:
        """Parse the message in `self.msg` into the result of `decode_email_bytes()`."""
        self._whitelist = eml_parser.hosts.IpWhitelist.from_entries(self.pconf.get('whiteip', []))
        headers_struc = self._parse_header()

        body_parts = eml_parser.mime.text_parts(self.msg, self.MULTIPART_RECURSION_LIMIT)
        is_multipart = len(body_parts) != 1
        bodies = [self._parse_body_part(body_part, is_multipart) for body_part in body_parts]

        header = eml_parser.headers.fields(self.msg)
        headers_struc['header'] = header

        if authentication := eml_parser.headers.authentication_results(header):
            headers_struc['authentication'] = authentication

        report_struc: dict[str, typing.Any] = {}

        if self.parse_attachments and (attachments := self._parse_attachments()):
            report_struc['attachment'] = attachments

        report_struc['body'] = bodies

        if self.include_raw_body:
            # As up to v0.5: the content transfer encoding and the decoded text of each text part.
            report_struc['raw_body'] = [(body_part.encoding, body_part.text) for body_part in body_parts]

        report_struc['header'] = headers_struc

        return report_struc

    def _parse_header(self) -> dict[str, typing.Any]:
        """Build the header of the result from the subject to the received lines: defects, sender, recipients, date and path of the message."""
        headers_struc: dict[str, typing.Any] = {'subject': eml_parser.decode.decode_field(self.msg.get('subject', ''))}

        # If parsing had problems, report it.
        if defects := eml_parser.headers.defects(self.msg):
            headers_struc['defect'] = defects

        sender = eml_parser.headers.sender(self.msg, self.email_regex)
        if sender is not None:
            headers_struc['from'] = sender

        headers_struc['to'] = eml_parser.headers.addresses(self.msg, 'to', self.email_regex, self.email_force_tld)
        for key, field_name in (('cc', 'cc'), ('delivered_to', 'delivered-to')):
            if addresses := eml_parser.headers.addresses(self.msg, field_name, self.email_regex, self.email_force_tld):
                headers_struc[key] = addresses

        # The default date is used if the field is absent.
        date_value: str | None = self.msg.get('date')

        if date_value is None:
            headers_struc['date'] = eml_parser.decode.DEFAULT_DATE
        else:
            headers_struc['date'] = dt.datetime.fromisoformat(date_value)

        headers_struc.update(self._parse_received())

        return headers_struc

    def _parse_received(self) -> dict[str, typing.Any]:
        """Parse the *Received* header fields, i.e. the path of the e-mail, and collect the hosts and addresses in them.

        Returns:
            dict: The parsed lines in *received*, and the unique e-mail addresses, domains, IP addresses and recipients found in them in
                *received_email*, *received_domain*, *received_ip* and *received_foremail* (if any). The *from* part of the most external
                line passing a server of `pconf['byhostentry']` is *received_src*.
        """
        received: list[dict[str, typing.Any]] = []
        found: dict[str, list[str]] = {'received_email': [], 'received_domain': [], 'received_ip': []}
        source: dict[str, list[str] | None] = {}

        found_smtpin: collections.Counter[str] = collections.Counter()  # Counter for storing potential duplicate "HOP"

        try:
            for received_line in self.msg.get_all('received', []):
                received_line_flat = _WHITESPACE_RUN_REGEX.sub(' ', str(received_line).lower())
                parsed_routing = eml_parser.routing.parserouting(received_line_flat, self.email_regex)

                if self.pconf.get('byhostentry'):
                    self._track_byhostentry(parsed_routing, found_smtpin, source)

                received.append(parsed_routing)
                self._collect_received_hosts(received_line_flat, parsed_routing.get('for', []), found)
        except TypeError:
            # pconf['byhostentry'] is no list, e.g. a number. The lines parsed so far are kept.
            logger.exception('Exception occurred while parsing received lines.')

        # Unique values, keys without values are left out.
        result: dict[str, typing.Any] = {'received': received}
        for key, values in found.items():
            if values:
                result[key] = list(dict.fromkeys(values))

        result.update(source)

        if recipients := self._received_recipients(received):
            result['received_foremail'] = recipients

        return result

    def _collect_received_hosts(self, received_line: str, recipients: list[str], found: dict[str, list[str]]) -> None:
        """Add the IP addresses, domains and e-mail addresses (other than the recipients) of a received line to *found*."""
        for ip in eml_parser.regexes.findall_ipv6(received_line) + eml_parser.regexes.ipv4_regex.findall(received_line):
            if ip in self._whitelist:
                continue

            if valid_ip := self._hosts.valid_domain_or_ip(ip):
                found['received_ip'].append(valid_ip)
            else:
                logger.debug('Invalid IP in received line - "%s"', ip)

        # search for domain (the last label contains a letter, so IPs are never matched; they are found above)
        found['received_domain'] += eml_parser.regexes.recv_dom_regex.findall(received_line)

        for mail_candidate in self.email_regex.findall(received_line):
            # The host of the address must be a valid domain or IP address, the address itself is reported.
            if self.email_force_tld and self._hosts.valid_domain_or_ip(mail_candidate) is None:
                continue

            if mail_candidate not in recipients:
                found['received_email'].append(mail_candidate)

    def _received_recipients(self, received: list[dict[str, typing.Any]]) -> list[str]:
        """The recipients of all received lines, unique and without the ones in `pconf['whitefor']`, for a rapid search."""
        whitefor = self.pconf.get('whitefor', [])
        recipients: dict[str, None] = {}

        for parsed_routing in received:
            for recipient in parsed_routing.get('for', []):
                if recipient not in whitefor:
                    recipients[recipient] = None

        return list(recipients)

    def _track_byhostentry(self, parsed_routing: dict[str, typing.Any], found_smtpin: collections.Counter[str], source: dict[str, list[str] | None]) -> None:
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

    def _parse_body_part(self, body_part: eml_parser.mime.BodyPart, multipart: bool) -> dict[str, typing.Any]:
        """Build the entry of a text part in the parse result: its indicators (or their hashes), header fields and hash.

        Args:
            body_part: The text part.
            multipart: Whether the e-mail has several text parts. If not, only the *Content-* header fields of the message are stored
                with the part, the others are in the header of the result anyway.

        Returns:
            dict: The entry.
        """
        entry: dict[str, typing.Any] = {}
        indicators = self._indicators.find(body_part.text, self._whitelist)

        # The field names of BodyIndicators are the keys of the entry, e.g. "uri" or "uri_hash".
        for key, values in vars(indicators).items():
            if not values:
                continue

            if self.include_raw_body:
                entry[key] = list(values)
            else:
                entry[f'{key}_hash'] = [hashlib.sha256(value.lower().encode('utf-8')).hexdigest() for value in values]

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

    def _parse_attachments(self) -> list[dict[str, typing.Any]]:
        """Build the entries of the attachments of the message, see `attachments.describe()`.

        Returns:
            list: The entries, in the order of the message, or none if an attachment contains invalid data.

        Raises:
            RecursionError: If the parts are nested deeper than `MULTIPART_RECURSION_LIMIT`.
        """
        entries = []

        try:
            for number, part in enumerate(eml_parser.attachments.attachment_parts(self.msg, self.MULTIPART_RECURSION_LIMIT)):
                attachment, data = eml_parser.attachments.describe(part, number, self.include_attachment_data)
                entries.append(attachment)

                if self.part_hook is not None:
                    self.part_hook(
                        PartData(
                            kind='attachment',
                            data=data,
                            sha256=attachment['hash']['sha256'],
                            content_type=part.get_content_type(),
                            filename=attachment['filename'],
                            content_headers=attachment['content_header'],
                            boundary=None,
                        )
                    )
        except (binascii.Error, AssertionError):
            # we hit this exception if the payload contains invalid data
            logger.exception('Exception occurred while parsing attachment data. Collected data will not be complete!')
            return []

        return entries
