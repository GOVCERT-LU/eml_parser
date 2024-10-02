"""eml_parser serves as a python module for parsing eml files and returning various information found in the e-mail as well as computed information."""

import base64
import binascii
import collections
import collections.abc
import datetime
import email
import email.headerregistry
import email.message
import email.policy
import email.utils
import hashlib
import ipaddress
import logging
import os.path
import pathlib
import re
import typing
import urllib.parse
import uuid
from collections import Counter
from html import unescape

import publicsuffixlist

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
        logger.warning('You are using python-magic, though this module requires file-magic. Disabling magic usage due to incompatibilities.')

        magic = None

__author__ = 'Toth Georges, Jung Paul'
__email__ = 'georges@trypill.org, georges.toth@govcert.etat.lu'
__copyright__ = 'Copyright 2013-2014 Georges Toth, Copyright 2013-present GOVCERT Luxembourg'
__license__ = 'AGPL v3+'


class CustomPolicy(email.policy.EmailPolicy):
    """Custom parsing policy based on the default policy but relaxing some checks and early fixing invalid values."""

    def __init__(self) -> None:
        """Constructor."""
        super().__init__(max_line_length=0, refold_source='none')

    def header_fetch_parse(self, name: str, value: str) -> str:
        """Early fix parsing issues and pass the name/value to the parent header_fetch_parse method for proper parsing."""
        header = name.lower()

        if header == 'message-id':
            if '[' in value and not eml_parser.regexes.email_regex.match(value):
                # try workaround for bad message-id formats
                m = eml_parser.regexes.email_regex.search(value)
                if m:
                    value = f'<{m.group(1)}>'
                else:
                    value = ''
                    logger.warning('Header field "message-id" is in an invalid format and cannot be fixed, it will be dropped.')
        elif header == 'date':
            try:
                value = super().header_fetch_parse(name, value)
            except TypeError:
                logger.warning('Error parsing date.', exc_info=True)
                return eml_parser.decode.default_date

            return eml_parser.decode.robust_string2date(value).isoformat()

        return super().header_fetch_parse(name, value)


class EmlParser:
    """eml-parser class."""

    # pylint: disable=too-many-arguments
    def __init__(
        self,
        include_raw_body: bool = False,
        include_attachment_data: bool = False,
        pconf: typing.Optional[dict] = None,
        policy: typing.Optional[email.policy.Policy] = None,
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
            ignore_bad_start (bool, optional): Ignore invalid file start. This has a considerable performance impact.
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
        self.policy = policy or CustomPolicy()
        self.ignore_bad_start = ignore_bad_start
        self.email_force_tld = email_force_tld
        self.domain_force_tld = domain_force_tld
        self.ip_force_routable = ip_force_routable
        self.parse_attachments = parse_attachments
        self.include_www = include_www
        self.include_href = include_href
        self._psl = publicsuffixlist.PublicSuffixList(accept_unknown=not self.domain_force_tld)

        if self.email_force_tld:
            eml_parser.regexes.email_regex = eml_parser.regexes.email_force_tld_regex

        # If no whitelisting is required, set to emtpy list
        if 'whiteip' not in self.pconf:
            self.pconf['whiteip'] = []
        # If no whitelisting is required, set to emtpy list
        if 'whitefor' not in self.pconf:
            self.pconf['whitefor'] = []

        self.msg: typing.Optional[email.message.Message] = None

    def decode_email(self, eml_file: os.PathLike, ignore_bad_start: bool = False) -> dict:
        """Function for decoding an EML file into an easily parsable structure.

        Some intelligence is applied while parsing the file in order to work around
        broken files.
        Besides just parsing, this function also computes hashes and extracts meta
        information from the source file.

        Args:
            eml_file: Path to the file to be parsed. os.PathLike objects are supported.
            ignore_bad_start: Ignore invalid file start for this run. This has a considerable performance impact.

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
            ignore_bad_start: Ignore invalid file start for this run. This has a considerable performance impact.

        Returns:
            dict: A dictionary with the content of the EML parsed and broken down into
                  key-value pairs.
        """
        if self.ignore_bad_start or ignore_bad_start:
            # Skip invalid start of file
            # Note that this has a considerable performance impact, which is why it is disabled by default.
            _eml_file = b''

            if b':' not in eml_file.split(b'\n', 1):
                start = True
                for line in eml_file.split(b'\n'):
                    if start and b':' not in line:
                        continue

                    start = False

                    _eml_file += line
            else:
                _eml_file = eml_file
        else:
            _eml_file = eml_file

        self.msg = email.message_from_bytes(_eml_file, policy=self.policy)

        return self.parse_email()

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
                headers_struc['defect'].append(str(exception))

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

            _from = eml_parser.decode.workaround_bug_27257(self.msg, 'from')
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
                m = eml_parser.regexes.email_regex.search(msg_header_field)
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
        if 'date' in self.msg and self.msg.get('date') is not None:
            headers_struc['date'] = datetime.datetime.fromisoformat(typing.cast(str, self.msg.get('date')))
        else:
            # If date field is absent...
            headers_struc['date'] = datetime.datetime.fromisoformat(eml_parser.decode.default_date)

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

                received_line_flat = re.sub(r'(\r|\n|\s|\t)+', ' ', line, flags=re.UNICODE)

                # Parse and split routing headers.
                # Return dict of list
                #   date string
                #   from list
                #   for list
                #   by list
                #   with string
                #   warning list
                parsed_routing = eml_parser.routing.parserouting(received_line_flat)

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
                ips_in_received_line = eml_parser.regexes.ipv6_regex.findall(received_line_flat) + eml_parser.regexes.ipv4_regex.findall(received_line_flat)
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
                for mail_candidate in eml_parser.regexes.email_regex.findall(received_line_flat):
                    if self.email_force_tld:
                        mail_candidate = self.get_valid_domain_or_ip(mail_candidate)
                    if mail_candidate is not None and mail_candidate not in parsed_routing.get('for', []):
                        headers_struc['received_email'] += [mail_candidate]

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
        headers_struc['received_email'] = list(set(headers_struc['received_email']))
        headers_struc['received_domain'] = list(set(headers_struc['received_domain']))
        headers_struc['received_ip'] = list(set(headers_struc['received_ip']))

        # Clean up if empty
        if not headers_struc['received_email']:
            del headers_struc['received_email']

        if 'received_foremail' in headers_struc:
            if not headers_struc['received_foremail']:
                del headers_struc['received_foremail']
            else:
                headers_struc['received_foremail'] = list(set(headers_struc['received_foremail']))

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
            list_observed_email: typing.Counter[str] = Counter()
            list_observed_dom: typing.Counter[str] = Counter()
            list_observed_ip: typing.Counter[str] = Counter()

            # If we start directly a findall on 500K+ body we got time and memory issues...
            # if more than 4K.. lets cheat, we will cut around the thing we search "://, @, ."
            # in order to reduce regex complexity.
            for body_slice in self.string_sliding_window_loop(body):
                for url_match in self.get_uri_ondata(body_slice):
                    if ':/' in url_match[:10]:
                        list_observed_urls.append(url_match)
                    else:
                        list_observed_urls_noscheme.append(url_match)

                for match in eml_parser.regexes.email_regex.findall(body_slice):
                    valid_email = self.get_valid_domain_or_ip(match.lower())
                    if valid_email:
                        list_observed_email[match.lower()] = 1

                for match in eml_parser.regexes.dom_regex.findall(body_slice):
                    valid_domain = self.get_valid_domain_or_ip(match.lower())
                    if valid_domain:
                        list_observed_dom[match.lower()] = 1

                for ip_regex in (eml_parser.regexes.ipv4_regex, eml_parser.regexes.ipv6_regex):
                    for match in ip_regex.findall(body_slice):
                        valid_ip = self.get_valid_domain_or_ip(match.lower())
                        if valid_ip in self.pconf['whiteip']:
                            continue
                        if valid_ip:
                            list_observed_ip[valid_ip] = 1

            # Report uri,email and observed domain or hash if no raw body
            if self.include_raw_body:
                if list_observed_urls:
                    bodie['uri'] = list(set(list_observed_urls))

                if list_observed_urls_noscheme:
                    bodie['uri_noscheme'] = list(set(list_observed_urls_noscheme))

                if list_observed_email:
                    bodie['email'] = list(list_observed_email)

                if list_observed_dom:
                    bodie['domain'] = list(list_observed_dom)

                if list_observed_ip:
                    bodie['ip'] = list(list_observed_ip)

            else:
                if list_observed_urls:
                    bodie['uri_hash'] = []
                    for element in list_observed_urls:
                        bodie['uri_hash'].append(self.get_hash(element.lower(), 'sha256'))
                if list_observed_email:
                    bodie['email_hash'] = []
                    for element in list_observed_email:
                        # Email already lowered
                        bodie['email_hash'].append(self.get_hash(element, 'sha256'))
                if list_observed_dom:
                    bodie['domain_hash'] = []
                    # for uri in list(set(list_observed_dom)):
                    for element in list_observed_dom:
                        bodie['domain_hash'].append(self.get_hash(element, 'sha256'))
                if list_observed_ip:
                    bodie['ip_hash'] = []
                    for element in list_observed_ip:
                        # IP (v6) already lowered
                        bodie['ip_hash'].append(self.get_hash(element, 'sha256'))

            # For mail without multipart we will only get the "content....something" headers
            # all other headers are in "header"
            # but we need to convert header tuples in dict..
            # "a","toto"           a: [toto,titi]
            # "a","titi"   --->    c: [truc]
            # "c","truc"
            ch: dict[str, list] = {}
            for k, v in body_multhead:
                # make sure we are working with strings only
                v = str(v)

                # We are using replace . to : for avoiding issue in mongo
                k = k.lower().replace('.', ':')  # Lot of lowers, pre-compute :) .

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

            uid = str(uuid.uuid1())
            bodys[uid] = bodie

        bodys_struc = bodys

        # Get all other bulk raw headers
        # "a","toto"           a: [toto,titi]
        # "a","titi"   --->    c: [truc]
        # "c","truc"
        #
        for k in set(self.msg.keys()):
            k = k.lower()  # Lot of lower, pre-compute...
            decoded_values = []

            try:
                for value in self.msg.get_all(k, []):
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
                    if eml_parser.regexes.email_regex_rfc2047.search(_field):
                        decoded_values.append(eml_parser.decode.rfc2047_decode(_field))
                    else:
                        logger.error('ERROR: Field value parsing error, trying to work around this! - %s', _field)

            if decoded_values:
                if k in header:
                    header[k] += decoded_values
                else:
                    header[k] = decoded_values

        headers_struc['header'] = header

        # parse attachments
        if self.parse_attachments:
            try:
                report_struc['attachment'] = self.traverse_multipart(self.msg, 0)
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
                newattach = []
                for attachment in report_struc['attachment']:
                    newattach.append(report_struc['attachment'][attachment])
                report_struc['attachment'] = newattach

        newbody = []
        for _, body in bodys_struc.items():
            newbody.append(body)
        report_struc['body'] = newbody
        # End of dirty hack

        # Get all other bulk headers
        report_struc['header'] = headers_struc

        return report_struc

    @staticmethod
    def string_sliding_window_loop(body: str, slice_step: int = 500, max_distance: int = 100) -> typing.Iterator[str]:
        """Yield a more or less constant slice of a large string.

        If we directly do a *regex* findall on 500K+ body we get time and memory issues.
        If more than the configured slice step, lets cheat, we will cut around the thing we search "://, @, ."
        in order to reduce regex complexity.

        In case we find a *://* at the first 8 characters of a sliced body window, we rewind the window by 16 characters.
        If we find the same string at the end of a sliced body window we try to look for invalid URL characters up to *max_distance*
        length, until which we give up and return the sliced body part. This is done in order to return a maximum possible
        correct URLs.

        The choice for 8 character is because *https://* is 8 characters, which is the maximum size we accept for schemes.

        Args:
            body: Body to slice into smaller pieces.
            slice_step: Slice this number or characters.
            max_distance: In case we find a *://* in a string window towards the end, we try our best to enlarge the window
                            as to not cut off URLs. This variable sets the maximum permitted additional window size to consider.

        Returns:
            typing.Iterator[str]: Sliced body string.
        """
        body_length = len(body)

        if body_length <= slice_step:
            yield body

        else:
            ptr_start = 0

            for ptr_end in range(slice_step, body_length + slice_step, slice_step):
                if ' ' in body[ptr_end - 1 : ptr_end]:
                    while not (eml_parser.regexes.window_slice_regex.match(body[ptr_end - 1 : ptr_end]) or ptr_end > body_length):
                        if ptr_end > body_length:
                            ptr_end = body_length
                            break

                        ptr_end += 1

                # Found a :// near the start of the slice, rewind
                if ptr_start > 16 and '://' in body[ptr_start - 8 : ptr_start + 8]:
                    ptr_start -= 16

                # Found a :// near the end of the slice, rewind from that location
                if ptr_end < body_length and '://' in body[ptr_end - 8 : ptr_end + 8]:
                    pos = body.rfind('://', ptr_end - 8, ptr_end + 8)
                    ptr_end = pos - 8

                # Found a :// within the slice; try to expand the slice until we find an invalid
                # URL character in order to avoid cutting off URLs
                if '://' in body[ptr_start:ptr_end] and not body[ptr_end - 1 : ptr_end] == ' ':
                    distance = 1

                    while body[ptr_end - 1 : ptr_end] not in (' ', '>') and distance < max_distance and ptr_end <= body_length:
                        distance += 1
                        ptr_end += 1

                yield body[ptr_start:ptr_end]

                ptr_start = ptr_end

    def get_valid_domain_or_ip(self, data: str) -> typing.Optional[str]:
        """Function to determine if an IP address, Email address, or Domain is valid.

        Args:
            data (str): Text input which should be validated.

        Returns:
            str: Returns a string of the validated IP address or the host.
        """
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
            # _psl uses self.domain_force_tld
            valid_domain = self._psl.publicsuffix(host)
            if valid_domain:
                return host

        return None

    def clean_found_uri(self, url: str) -> typing.Optional[str]:
        """Function for validating URLs from the input string.

        Args:
            url (str): Text input which should have a single URL validated.

        Returns:
            str: Returns a valid URL, if found in the input string.
        """
        if '.' not in url and '[' not in url:
            # if we found a URL like e.g. http://afafasasfasfas; that makes no
            # sense, thus skip it, but include http://[2001:db8::1]
            return None

        try:
            # Remove leading spaces and quote characters
            url = url.lstrip(' \t\n\r\f\v\'"«»“”‘’').replace('\r', '').replace('\n', '')
            url = urllib.parse.urlparse(url).geturl()
            scheme_url = url
            if ':/' not in scheme_url:
                scheme_url = 'noscheme://' + url

            _hostname = urllib.parse.urlparse(scheme_url).hostname

            if _hostname is None:
                return None

            host = _hostname.rstrip('.')

            if self.get_valid_domain_or_ip(host) is None:
                return None
        except ValueError:
            logger.warning('Unable to parse URL - %s', url)
            return None

        # let's try to be smart by stripping of noisy bogus parts
        url = re.split(r"""[', ")}\\]""", url, maxsplit=1)[0]

        # filter bogus URLs
        if url.endswith('://'):
            return None

        if '&' in url:
            url = unescape(url)

        return url

    def get_uri_ondata(self, body: str) -> list[str]:
        """Function for extracting URLs from the input string.

        Args:
            body (str): Text input which should be searched for URLs.

        Returns:
            list: Returns a list of URLs found in the input string.
        """
        list_observed_urls: typing.Counter[str] = Counter()

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
            for found_url in eml_parser.regexes.url_regex_href.findall(body):
                clean_uri = self.clean_found_uri(found_url)
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
            field = email.utils.getaddresses(eml_parser.decode.workaround_bug_27257(self.msg, header))
        except ValueError:
            _field = eml_parser.decode.workaround_field_value_parsing_errors(self.msg, header)
            field = []

            for v in _field:
                v = eml_parser.decode.rfc2047_decode(v).replace('\n', '').replace('\r', '')

                parsing_result: dict[str, typing.Any] = {}
                parser_cls = typing.cast(email.headerregistry.AddressHeader, email.headerregistry.HeaderRegistry()[header])
                parser_cls.parse(v, parsing_result)
                for _group in parsing_result['groups']:
                    for _address in _group.addresses:
                        field.append((_address.display_name, _address.addr_spec))

        return_field = []

        for m in field:
            if not m[1] == '':
                if self.email_force_tld:
                    if eml_parser.regexes.email_force_tld_regex.match(m[1]):
                        return_field.append(m[1].lower())
                else:
                    return_field.append(m[1].lower())

        return return_field

    def get_raw_body_text(
        self, msg: email.message.Message, boundary: typing.Optional[str] = None
    ) -> list[tuple[typing.Any, typing.Any, typing.Any, typing.Optional[str]]]:
        """This method recursively retrieves all e-mail body parts and returns them as a list.

        Args:
            msg (email.message.Message): The actual e-mail message or sub-message.
            boundary: Used for passing the boundary marker of multipart messages, and used to easier distinguish different parts.

        Returns:
            list: Returns a list of sets which are in the form of "set(encoding, raw_body_string, message field headers, possible boundary marker)"
        """
        raw_body: list[tuple[typing.Any, typing.Any, typing.Any, typing.Optional[str]]] = []

        if msg.is_multipart():
            boundary = msg.get_boundary(failobj=None)
            for part in msg.get_payload():
                raw_body.extend(self.get_raw_body_text(typing.cast(email.message.Message, part), boundary=boundary))
        else:
            # Treat text document attachments as belonging to the body of the mail.
            # Attachments with a file-extension of .htm/.html are implicitly treated
            # as text as well in order not to escape later checks (e.g. URL scan).

            try:
                filename = msg.get_filename('').lower()
            except (binascii.Error, AssertionError):
                logger.exception('Exception occurred while trying to parse the content-disposition header. Collected data will not be complete.')
                filename = ''

            # pylint: disable=too-many-boolean-expressions
            if (
                ('content-disposition' not in msg and msg.get_content_maintype() == 'text')
                or (filename.endswith(('.html', '.htm')))
                or ('content-disposition' in msg and msg.get_content_disposition() == 'inline' and msg.get_content_maintype() == 'text')
            ):
                encoding = msg.get('content-transfer-encoding', '').lower()

                charset = msg.get_content_charset()
                if charset is None:
                    raw_body_b = typing.cast(bytes, msg.get_payload(decode=True))
                    raw_body_str = eml_parser.decode.decode_string(raw_body_b, None)
                else:
                    try:
                        raw_body_str = typing.cast(bytes, msg.get_payload(decode=True)).decode(charset, 'ignore')
                    except (LookupError, ValueError):
                        logger.debug('An exception occurred while decoding the payload!', exc_info=True)
                        raw_body_str = typing.cast(bytes, msg.get_payload(decode=True)).decode('ascii', 'ignore')

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
    def get_hash(value: typing.Union[str, bytes], hash_type: str) -> str:
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

    def traverse_multipart(self, msg: email.message.Message, counter: int = 0) -> dict[str, typing.Any]:
        """Recursively traverses all e-mail message multi-part elements and returns in a parsed form as a dict.

        Args:
            msg (email.message.Message): An e-mail message object.
            counter (int, optional): A counter which is used for generating attachments
                file-names in case there are none found in the header. Default = 0.

        Returns:
            dict: Returns a dict with all original multi-part headers as well as generated hash check-sums,
                date size, file extension, real mime-type.
        """
        attachments = {}

        if msg.is_multipart():
            if 'content-type' in msg:
                if msg.get_content_type() == 'message/rfc822':
                    # This is an e-mail message attachment, add it to the attachment list apart from parsing it
                    attachments.update(self.prepare_multipart_part_attachment(msg, counter))

            for part in msg.get_payload():
                attachments.update(self.traverse_multipart(typing.cast(email.message.EmailMessage, part), counter))
        else:
            return self.prepare_multipart_part_attachment(msg, counter)

        return attachments

    def prepare_multipart_part_attachment(self, msg: email.message.Message, counter: int = 0) -> dict[str, typing.Any]:
        """Extract meta-information from a multipart-part.

        Args:
            msg (email.message.Message): An e-mail message object.
            counter (int, optional): A counter which is used for generating attachments
                file-names in case there are none found in the header. Default = 0.

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

                try:
                    custom_policy: email.policy.Policy = email.policy.default.clone(max_line_length=0)
                    data = typing.cast(list[email.message.EmailMessage], payload)[0].as_bytes(policy=custom_policy)
                except UnicodeEncodeError:
                    custom_policy = email.policy.compat32.clone(max_line_length=0)
                    data = typing.cast(list[email.message.EmailMessage], payload)[0].as_bytes(policy=custom_policy)

                file_size = len(data)
            else:
                data = typing.cast(bytes, msg.get_payload(decode=True))
                file_size = len(data)

            filename = msg.get_filename('')
            if filename == '':
                filename = f'part-{counter:03d}'
            else:
                filename = eml_parser.decode.decode_field(filename)

            file_id = str(uuid.uuid1())
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

            if not (mime_type is None or mime_type_short is None):
                attachment[file_id]['mime_type'] = mime_type
                # attachments[file_id]['mime_type_short'] = attachments[file_id]['mime_type'].split(",")[0]
                attachment[file_id]['mime_type_short'] = mime_type_short
            elif magic is not None:
                logger.warning('Error determining attachment mime-type - "%s"', str(file_id))

            if self.include_attachment_data:
                attachment[file_id]['raw'] = base64.b64encode(data)

            ch: dict[str, list[str]] = {}
            for k, v in msg.items():
                k = k.lower()
                v = str(v)

                if k in ch:
                    ch[k].append(v)
                else:
                    ch[k] = [v]

            attachment[file_id]['content_header'] = ch

            counter += 1

        return attachment

    @staticmethod
    def get_mime_type(data: bytes) -> typing.Union[tuple[str, str], tuple[None, None]]:
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
