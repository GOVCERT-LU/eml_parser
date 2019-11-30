# -*- coding: utf-8 -*-
# pylint: disable=line-too-long

"""eml_parser serves as a python module for parsing eml files and returning various
information found in the e-mail as well as computed information.
"""

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

import base64
import binascii
import collections
import email
import email.message
import email.policy
import email.utils
import hashlib
import ipaddress
import logging
import os.path
import re
import typing
import urllib.parse
import uuid

import dateutil.parser

import eml_parser.decode
import eml_parser.regex
import eml_parser.routing

logger = logging.getLogger(__name__)

try:
    import magic
except ImportError:
    magic = None
    magic_mime = None
    magic_none = None
else:
    if hasattr(magic, 'open'):
        # MAGIC_MIME_TYPE gives the real mime-type
        magic_mime = magic.open(magic.MAGIC_MIME_TYPE)
        magic_mime.load()
        # MAGIC_NONE gives the meta-information on the analysed file
        magic_none = magic.open(magic.MAGIC_NONE)
        magic_none.load()
    else:
        logger.warning(
            'You are using python-magic, though this module requires file-magic. Disabling magic usage due to incompatibilities.')

        magic = None
        magic_mime = None
        magic_none = None

__author__ = 'Toth Georges, Jung Paul'
__email__ = 'georges@trypill.org, georges.toth@govcert.etat.lu'
__copyright__ = 'Copyright 2013-2014 Georges Toth, Copyright 2013-present GOVCERT Luxembourg'
__license__ = 'AGPL v3+'


def get_raw_body_text(msg: email.message.Message) -> typing.List[typing.Tuple[typing.Any, typing.Any, typing.Any]]:
    """This method recursively retrieves all e-mail body parts and returns them as a list.

    Args:
        msg (email.message.Message): The actual e-mail message or sub-message.

    Returns:
        list: Returns a list of sets which are in the form of "set(encoding, raw_body_string, message field headers)"
    """
    raw_body = []  # type: typing.List[typing.Tuple[typing.Any, typing.Any,typing.Any]]

    if msg.is_multipart():
        for part in msg.get_payload():  # type: ignore
            raw_body.extend(get_raw_body_text(part))  # type: ignore
    else:
        # Treat text document attachments as belonging to the body of the mail.
        # Attachments with a file-extension of .htm/.html are implicitly treated
        # as text as well in order not to escape later checks (e.g. URL scan).

        try:
            filename = msg.get_filename('').lower()
        except (binascii.Error, AssertionError):
            logger.exception(
                'Exception occured while trying to parse the content-disposition header. Collected data will not be complete.')
            filename = ''

        if ('content-disposition' not in msg and msg.get_content_maintype() == 'text') \
                or (filename.endswith('.html') or filename.endswith('.htm')) \
                or ('content-disposition' in msg and msg.get_content_disposition() == 'inline'
                    and msg.get_content_maintype() == 'text'):
            encoding = msg.get('content-transfer-encoding', '').lower()

            charset = msg.get_content_charset()
            if charset is None:
                raw_body_str = msg.get_payload(decode=True)
                raw_body_str = eml_parser.decode.decode_string(raw_body_str, None)
            else:
                try:
                    raw_body_str = msg.get_payload(decode=True).decode(charset, 'ignore')
                except Exception:
                    logger.debug('An exception occured while decoding the payload!', exc_info=True)
                    raw_body_str = msg.get_payload(decode=True).decode('ascii', 'ignore')

            # In case we hit bug 27257, try to downgrade the used policy
            try:
                raw_body.append((encoding, raw_body_str, msg.items()))
            except AttributeError:
                former_policy = msg.policy
                msg.policy = email.policy.compat32
                raw_body.append((encoding, raw_body_str, msg.items()))
                msg.policy = former_policy

    return raw_body


def get_file_hash(data: bytes) -> typing.Dict[str, str]:
    """Generate hashes of various types (``MD5``, ``SHA-1``, ``SHA-256``, ``SHA-512``)
    for the provided data.

    Args:
      data (bytes): The data to calculate the hashes on.

    Returns:
      dict: Returns a dict with as key the hash-type and value the calculated hash.
    """
    hashalgo = ['md5', 'sha1', 'sha256', 'sha512']
    hash_ = {}

    for k in hashalgo:
        ha = getattr(hashlib, k)
        h = ha()
        h.update(data)
        hash_[k] = h.hexdigest()

    return hash_


def wrap_hash_sha256(string: str) -> str:
    """Generate a SHA256 hash for a given string.

    Args:
        string (str): String to calculate the hash on.

    Returns:
        str: Returns the calculated hash as a string.
    """
    _string = string.encode('utf-8')

    return hashlib.sha256(_string).hexdigest()


def traverse_multipart(msg: email.message.Message, counter: int = 0, include_attachment_data: bool = False) -> \
        typing.Dict[str, typing.Any]:
    """Recursively traverses all e-mail message multi-part elements and returns in a parsed form as a dict.

    Args:
        msg (email.message.Message): An e-mail message object.
        counter (int, optional): A counter which is used for generating attachments
            file-names in case there are none found in the header. Default = 0.
        include_attachment_data (bool, optional): If true, method includes the raw attachment data when
            returning. Default = False.

    Returns:
        dict: Returns a dict with all original multi-part headers as well as generated hash check-sums,
            date size, file extension, real mime-type.
    """
    attachments = {}

    if msg.is_multipart():
        if 'content-type' in msg:
            if msg.get_content_type() == 'message/rfc822':
                # This is an e-mail message attachment, add it to the attachment list apart from parsing it
                attachments.update(
                    prepare_multipart_part_attachment(msg, counter, include_attachment_data))  # type: ignore

        for part in msg.get_payload():  # type: ignore
            attachments.update(traverse_multipart(part, counter, include_attachment_data))  # type: ignore
    else:
        return prepare_multipart_part_attachment(msg, counter, include_attachment_data)

    return attachments


def prepare_multipart_part_attachment(msg: email.message.Message, counter: int = 0,
                                      include_attachment_data: bool = False) -> typing.Dict[str, typing.Any]:
    """Extract meta-information from a multipart-part.

    Args:
        msg (email.message.Message): An e-mail message object.
        counter (int, optional): A counter which is used for generating attachments
            file-names in case there are none found in the header. Default = 0.
        include_attachment_data (bool, optional): If true, method includes the raw attachment data when
            returning. Default = False.

    Returns:
        dict: Returns a dict with original multi-part headers as well as generated hash check-sums,
            date size, file extension, real mime-type.
    """
    attachment = {}

    # In case we hit bug 27257, try to downgrade the used policy
    try:
        lower_keys = dict((k.lower(), v) for k, v in msg.items())
    except AttributeError:
        former_policy = msg.policy
        msg.policy = email.policy.compat32
        lower_keys = dict((k.lower(), v) for k, v in msg.items())
        msg.policy = former_policy

    if ('content-disposition' in lower_keys and msg.get_content_disposition() != 'inline') \
            or msg.get_content_maintype() != 'text':
        # if it's an attachment-type, pull out the filename
        # and calculate the size in bytes
        if msg.get_content_type() == 'message/rfc822':
            payload = msg.get_payload()
            if len(payload) > 1:
                logger.warning(
                    'More than one payload for "message/rfc822" part detected. This is not supported, please report!')

            try:
                data = payload[0].as_bytes()
            except UnicodeEncodeError:
                data = payload[0].as_bytes(policy=email.policy.compat32)

            file_size = len(data)
        else:
            data = msg.get_payload(decode=True)  # type: bytes  # type is always bytes here
            file_size = len(data)

        filename = msg.get_filename('')
        if filename == '':
            filename = 'part-{0:03d}'.format(counter)
        else:
            filename = eml_parser.decode.decode_field(filename)

        file_id = str(uuid.uuid1())
        attachment[file_id] = {}
        attachment[file_id]['filename'] = filename
        attachment[file_id]['size'] = file_size

        # os.path always returns the extension as second element
        # in case there is no extension it returns an empty string
        extension = os.path.splitext(filename)[1].lower()
        if extension:
            # strip leading dot
            attachment[file_id]['extension'] = extension[1:]

        attachment[file_id]['hash'] = get_file_hash(data)

        if not (magic_mime is None or magic_none is None):
            mime_type = magic_none.buffer(data)
            mime_type_short = magic_mime.buffer(data)

            if not (mime_type is None or mime_type_short is None):
                attachment[file_id]['mime_type'] = mime_type
                # attachments[file_id]['mime_type_short'] = attachments[file_id]['mime_type'].split(",")[0]
                attachment[file_id]['mime_type_short'] = mime_type_short
            else:
                logger.warning('Error determining attachment mime-type - "{}"'.format(file_id))

        if include_attachment_data:
            attachment[file_id]['raw'] = base64.b64encode(data)

        ch = {}  # type: typing.Dict[str, typing.List[str]]
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


def decode_email(eml_file: str, include_raw_body: bool = False, include_attachment_data: bool = False,
                 pconf: typing.Optional[dict] = None, policy: email.policy.Policy = email.policy.default,
                 ignore_bad_start: bool = False, email_force_tld: bool = False, parse_attachments: bool = True) -> dict:
    """Function for decoding an EML file into an easily parsable structure.
    Some intelligence is applied while parsing the file in order to work around
    broken files.
    Besides just parsing, this function also computes hashes and extracts meta
    information from the source file.

    Args:
      eml_file (str): Full absolute path to the file to be parsed.
      include_raw_body (bool, optional): Boolean paramter which indicates whether
                                         to include the original file contents in
                                         the returned structure. Default is False.
      include_attachment_data (bool, optional): Boolean paramter which indicates whether
                                                to include raw attachment data in the
                                                returned structure. Default is False.
      pconf (dict, optional): A dict with various optional configuration parameters,
                              e.g. whitelist IPs, whitelist e-mail addresses, etc.

      policy (email.policy.Policy, optional): Policy to use when parsing e-mails.
            Default = email.policy.default.

      ignore_bad_start (bool, optional): Ignore invalid file start. This has a considerable performance impact.

      email_force_tld (bool, optional): Only match e-mail addresses with a TLD. I.e exclude something like
                                        john@doe. By default this is disabled.

      parse_attachments (bool, optional): Set this to false if you want to disable the parsing of attachments.
                                          Please note that HTML attachments as well as other text data marked to be
                                          in-lined, will always be parsed.

    Returns:
      dict: A dictionary with the content of the EML parsed and broken down into
            key-value pairs.
    """
    with open(eml_file, 'rb') as fp:
        raw_email = fp.read()

    return decode_email_b(eml_file=raw_email,
                          include_raw_body=include_raw_body,
                          include_attachment_data=include_attachment_data,
                          pconf=pconf,
                          policy=policy,
                          ignore_bad_start=ignore_bad_start,
                          email_force_tld=email_force_tld,
                          parse_attachments=parse_attachments)


def decode_email_b(eml_file: bytes, include_raw_body: bool = False, include_attachment_data: bool = False,
                   pconf: typing.Optional[dict] = None, policy: email.policy.Policy = email.policy.default,
                   ignore_bad_start: bool = False, email_force_tld: bool = False,
                   parse_attachments: bool = True) -> dict:
    """Function for decoding an EML file into an easily parsable structure.
    Some intelligence is applied while parsing the file in order to work around
    broken files.
    Besides just parsing, this function also computes hashes and extracts meta
    information from the source file.

    Args:
        eml_file (bytes): Contents of the raw EML file passed to this function as string.
        include_raw_body (bool, optional): Boolean paramter which indicates whether
                                           to include the original file contents in
                                           the returned structure. Default is False.
        include_attachment_data (bool, optional): Boolean paramter which indicates whether
                                                  to include raw attachment data in the
                                                  returned structure. Default is False.
        pconf (dict, optional): A dict with various optional configuration parameters,
                                e.g. whitelist IPs, whitelist e-mail addresses, etc.

        policy (email.policy.Policy, optional): Policy to use when parsing e-mails.
              Default = email.policy.default.

        ignore_bad_start (bool, optional): Ignore invalid file start. This has a considerable performance impact.

        email_force_tld (bool, optional): Only match e-mail addresses with a TLD. I.e exclude something like
                                          john@doe. By default this is disabled.

      parse_attachments (bool, optional): Set this to false if you want to disable the parsing of attachments.
                                          Please note that HTML attachments as well as other text data marked to be
                                          in-lined, will always be parsed.

    Returns:
        dict: A dictionary with the content of the EML parsed and broken down into
              key-value pairs.
    """
    if email_force_tld:
        eml_parser.regex.email_regex = eml_parser.regex.email_force_tld_regex
        eml_parser.regex.parsing_email_force_tld = True

    if ignore_bad_start:
        # Skip invalid start of file
        # Note that this has a considerable performance impact, which is why it is disabled by default.
        _eml_file = b''

        if not b':' in eml_file.split(b'\n', 1):
            start = True
            for line in eml_file.split(b'\n'):
                if start and not b':' in line:
                    continue
                else:
                    start = False

                _eml_file += line
        else:
            _eml_file = eml_file
    else:
        _eml_file = eml_file

    msg = email.message_from_bytes(_eml_file, policy=policy)

    return parse_email(msg, include_raw_body, include_attachment_data, pconf, parse_attachments=parse_attachments)


def get_uri_ondata(body: str) -> typing.List[str]:
    """Function for extracting URLs from the input string.

    Args:
        body (str): Text input which should be searched for URLs.

    Returns:
        list: Returns a list of URLs found in the input string.
    """
    list_observed_urls = []  # type: typing.List[str]

    for match in eml_parser.regex.url_regex_simple.findall(body):
        found_url = match[0].replace('hxxp', 'http')
        found_url = urllib.parse.urlparse(found_url).geturl()
        # let's try to be smart by stripping of noisy bogus parts
        found_url = re.split(r'''[', ")}\\]''', found_url)[0]
        list_observed_urls.append(found_url)

    return list_observed_urls


def headeremail2list(mail: email.message.Message, header: str) -> typing.List[str]:
    """Parses a given header field with e-mail addresses to a list of e-mail addresses.

    Args:
        mail (email.message.Message): An e-mail message object.
        header (str): The header field to decode.

    Returns:
        list: Returns a list of strings which represent e-mail addresses.
    """
    try:
        field = email.utils.getaddresses(mail.get_all(header, []))
    except (IndexError, AttributeError):
        field = email.utils.getaddresses(eml_parser.decode.workaround_bug_27257(mail, header))

    return_field = []

    for m in field:
        if not m[1] == '':
            if eml_parser.regex.parsing_email_force_tld:
                if eml_parser.regex.email_force_tld_regex.match(m[1]):
                    return_field.append(m[1].lower())
            else:
                return_field.append(m[1].lower())

    return return_field


# Iterator that give all position of a given pattern (no regex)
# @FIXME: Is this still required
# Error may occurs when using unicode-literals or python 3 on dirty emails
# Need to check if buffer is a clean one
# may be tested with this byte code:
# -> 00000b70  61 6c 20 32 39 b0 20 6c  75 67 6c 69 6f 20 32 30  |al 29. luglio 20|
# Should crash on "B0".
def findall(pat: str, data: str) -> typing.Iterator[int]:
    """Iterator that give all position of a given pattern (no regex).

    Args:
        pat (str): Pattern to seek
        data (str): buffer

    Yields:
        int: Yields the next position
    """
    i = data.find(pat)
    while i != -1:
        yield i
        i = data.find(pat, i + 1)


def parse_email(msg: email.message.Message, include_raw_body: bool = False, include_attachment_data: bool = False,
                pconf: typing.Optional[dict] = None, parse_attachments: bool = True) -> dict:
    """Parse an e-mail and return a dictionary containing the various parts of
    the e-mail broken down into key-value pairs.

    Args:
      msg (str): Raw EML e-mail string.
      include_raw_body (bool, optional): If True, includes the raw body in the resulting
                               dictionary. Defaults to False.
      include_attachment_data (bool, optional): If True, includes the full attachment
                                                data in the resulting dictionary.
                                                Defaults to False.
      pconf (dict, optional): A dict with various optional configuration parameters,
                              e.g. whitelist IPs, whitelist e-mail addresses, etc.

      parse_attachments (bool, optional): Set this to false if you want to disable the parsing of attachments.
                                          Please note that HTML attachments as well as other text data marked to be
                                          in-lined, will always be parsed.

    Returns:
      dict: A dictionary with the content of the EML parsed and broken down into
            key-value pairs.
    """
    header = {}  # type: typing.Dict[str, typing.Any]
    report_struc = {}  # type: typing.Dict[str, typing.Any]  # Final structure
    headers_struc = {}  # type: typing.Dict[str, typing.Any]  # header_structure
    bodys_struc = {}  # type: typing.Dict[str, typing.Any]  # body structure

    # If no pconf was specified, default to empty dict
    pconf = pconf or {}

    # If no whitelisting is required, set to emtpy list
    if 'whiteip' not in pconf:
        pconf['whiteip'] = []
    # If no whitelisting is required, set to emtpy list
    if 'whitefor' not in pconf:
        pconf['whitefor'] = []

    # parse and decode subject
    subject = msg.get('subject', '')
    headers_struc['subject'] = eml_parser.decode.decode_field(subject)

    # If parsing had problems, report it
    if msg.defects:
        headers_struc['defect'] = []
        for exception in msg.defects:
            headers_struc['defect'].append(str(exception))

    # parse and decode "from"
    # @TODO verify if this hack is necessary for other e-mail fields as well
    try:
        msg_header_field = str(msg.get('from', '')).lower()
    except (IndexError, AttributeError):
        # We have hit current open issue #27257
        # https://bugs.python.org/issue27257
        # The field will be set to emtpy as a workaround.
        #
        logger.exception('We hit bug 27257!')

        _from = eml_parser.decode.workaround_bug_27257(msg, 'from')
        msg.__delitem__('from')

        if _from:
            msg.add_header('from', _from[0])
            __from = _from[0].lower()
        else:
            msg.add_header('from', '')
            __from = ''

        msg_header_field = __from

    if msg_header_field != '':
        m = eml_parser.regex.email_regex.search(msg_header_field)
        if m:
            headers_struc['from'] = m.group(1)
        else:
            from_ = email.utils.parseaddr(msg.get('from', '').lower())
            headers_struc['from'] = from_[1]

    # parse and decode "to"
    headers_struc['to'] = headeremail2list(msg, 'to')
    # parse and decode "cc"
    headers_struc['cc'] = headeremail2list(msg, 'cc')
    if not headers_struc['cc']:
        headers_struc.pop('cc')

    # parse and decode delivered-to
    headers_struc['delivered_to'] = headeremail2list(msg, 'delivered-to')
    if not headers_struc['delivered_to']:
        headers_struc.pop('delivered_to')

    # parse and decode Date
    # If date field is present
    if 'date' in msg:
        try:
            headers_struc['date'] = eml_parser.decode.robust_string2date(msg.get('date'))
        except (TypeError, Exception):
            logger.warning('Error parsing date.')
            headers_struc['date'] = dateutil.parser.parse('1970-01-01T00:00:00+0000')
            msg.replace_header('date', headers_struc['date'])
    else:
        # If date field is absent...
        headers_struc['date'] = dateutil.parser.parse('1970-01-01T00:00:00+0000')

    # mail receiver path / parse any domain, e-mail
    # @TODO parse case where domain is specified but in parentheses only an IP
    headers_struc['received'] = []
    headers_struc['received_email'] = []
    headers_struc['received_domain'] = []
    headers_struc['received_ip'] = []
    try:
        found_smtpin = collections.Counter()  # type: collections.Counter  # Array for storing potential duplicate "HOP"

        for received_line in msg.get_all('received', []):
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

            if pconf.get('byhostentry'):
                for by_item in parsed_routing.get('by', []):  # type: ignore
                    for byhostentry_ in pconf['byhostentry']:
                        byhostentry = byhostentry_.lower()
                        # print ("%s %s" % (byhostentry, by_item))
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
            ips_in_received_line = eml_parser.regex.ipv6_regex.findall(received_line_flat) + \
                                   eml_parser.regex.ipv4_regex.findall(received_line_flat)
            for ip in ips_in_received_line:
                try:
                    ip_obj = ipaddress.ip_address(
                        ip)  # type: ignore  # type of findall is list[str], so this is correct
                except ValueError:
                    logger.debug('Invalid IP in received line - "{}"'.format(ip))
                else:
                    if not (ip_obj.is_private or str(ip_obj) in pconf['whiteip']):
                        headers_struc['received_ip'].append(str(ip_obj))

            # search for domain
            for m in eml_parser.regex.recv_dom_regex.findall(received_line_flat):
                try:
                    ip_obj = ipaddress.ip_address(m)  # type: ignore  # type of findall is list[str], so this is correct
                except ValueError:
                    # we find IPs using the previous IP crawler, hence we ignore them
                    # here.
                    # iff the regex fails, we add the entry
                    headers_struc['received_domain'].append(m)

            # search for e-mail addresses
            for mail_candidate in eml_parser.regex.email_regex.findall(received_line_flat):
                if mail_candidate not in parsed_routing.get('for', []):
                    headers_struc['received_email'] += [mail_candidate]

    except TypeError:  # Ready to parse email without received headers.
        logger.exception('Exception occured while parsing received lines.')

    # Concatenate for emails into one array | uniq
    # for rapid "find"
    headers_struc['received_foremail'] = []
    if 'received' in headers_struc:
        for _parsed_routing in headers_struc['received']:
            for itemfor in _parsed_routing.get('for', []):
                if itemfor not in pconf['whitefor']:
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
    raw_body = get_raw_body_text(msg)

    if include_raw_body:
        bodys_struc['raw_body'] = raw_body

    bodys = {}

    # Is it a multipart email ?
    if len(raw_body) == 1:
        multipart = False
    else:
        multipart = True

    for body_tup in raw_body:
        bodie = {}  # type: typing.Dict[str, typing.Any]
        _, body, body_multhead = body_tup
        # Parse any URLs and mail found in the body
        list_observed_urls = []  # type: typing.List[str]
        list_observed_email = []  # type: typing.List[str]
        list_observed_dom = []  # type: typing.List[str]
        list_observed_ip = []  # type: typing.List[str]

        # If we start directly a findall on 500K+ body we got time and memory issues...
        # if more than 4K.. lets cheat, we will cut around the thing we search "://, @, ."
        # in order to reduce regex complexity.
        if len(body) < 4096:
            list_observed_urls = get_uri_ondata(body)
            for match in eml_parser.regex.email_regex.findall(body):
                list_observed_email.append(match.lower())
            for match in eml_parser.regex.dom_regex.findall(body):
                list_observed_dom.append(match.lower())
            for match in eml_parser.regex.ipv4_regex.findall(body):
                if not eml_parser.regex.priv_ip_regex.match(match):
                    if match not in pconf['whiteip']:
                        list_observed_ip.append(match)
            for match in eml_parser.regex.ipv6_regex.findall(body):
                if not eml_parser.regex.priv_ip_regex.match(match):
                    if match.lower() not in pconf['whiteip']:
                        list_observed_ip.append(match.lower())
        else:
            for scn_pt in findall('://', body):
                list_observed_urls = get_uri_ondata(body[scn_pt - 16:scn_pt + 4096]) + list_observed_urls

            for scn_pt in findall('@', body):
                # RFC 3696, 5322, 5321 for email size limitations
                for match in eml_parser.regex.email_regex.findall(body[scn_pt - 64:scn_pt + 255]):
                    list_observed_email.append(match.lower())

            for scn_pt in findall('.', body):
                # The maximum length of a fqdn, not a hostname, is 1004 characters RFC1035
                # The maximum length of a hostname is 253 characters. Imputed from RFC952, RFC1123 and RFC1035.
                for match in eml_parser.regex.dom_regex.findall(body[scn_pt - 253:scn_pt + 1004]):
                    list_observed_dom.append(match.lower())

                # Find IPv4 addresses
                for match in eml_parser.regex.ipv4_regex.findall(body[scn_pt - 11:scn_pt + 3]):
                    if not eml_parser.regex.priv_ip_regex.match(match):
                        if match not in pconf['whiteip']:
                            list_observed_ip.append(match)

            for scn_pt in findall(':', body):
                # The maximum length of IPv6 is 32 Char + 7 ":"
                for match in eml_parser.regex.ipv6_regex.findall(body[scn_pt - 4:scn_pt + 35]):
                    if not eml_parser.regex.priv_ip_regex.match(match):
                        if match.lower() not in pconf['whiteip']:
                            list_observed_ip.append(match.lower())

        # Report uri,email and observed domain or hash if no raw body
        if include_raw_body:
            if list_observed_urls:
                bodie['uri'] = list(set(list_observed_urls))

            if list_observed_email:
                bodie['email'] = list(set(list_observed_email))

            if list_observed_dom:
                bodie['domain'] = list(set(list_observed_dom))

            if list_observed_ip:
                bodie['ip'] = list(set(list_observed_ip))

        else:
            if list_observed_urls:
                bodie['uri_hash'] = []
                for uri in list(set(list_observed_urls)):
                    bodie['uri_hash'].append(wrap_hash_sha256(uri.lower()))
            if list_observed_email:
                bodie['email_hash'] = []
                for emel in list(set(list_observed_email)):
                    # Email already lowered
                    bodie['email_hash'].append(wrap_hash_sha256(emel))
            if list_observed_dom:
                bodie['domain_hash'] = []
                for uri in list(set(list_observed_dom)):
                    bodie['domain_hash'].append(wrap_hash_sha256(uri.lower()))
            if list_observed_ip:
                bodie['ip_hash'] = []
                for fip in list(set(list_observed_ip)):
                    # IP (v6) already lowered
                    bodie['ip_hash'].append(wrap_hash_sha256(fip))

        # For mail without multipart we will only get the "content....something" headers
        # all other headers are in "header"
        # but we need to convert header tuples in dict..
        # "a","toto"           a: [toto,titi]
        # "a","titi"   --->    c: [truc]
        # "c","truc"
        ch = {}  # type: typing.Dict[str, typing.List]
        for k, v in body_multhead:
            # make sure we are working with strings only
            v = str(v)

            # We are using replace . to : for avoiding issue in mongo
            k = k.lower().replace('.', ':')  # Lot of lowers, pre-compute :) .
            # print v
            if multipart:
                if k in ch:
                    ch[k].append(v)
                else:
                    ch[k] = [v]
            else:  # if not multipart, store only content-xx related header with part
                if k.startswith('content'):  # otherwise, we got all header headers
                    if k in ch:
                        ch[k].append(v)
                    else:
                        ch[k] = [v]
        bodie['content_header'] = ch  # Store content headers dict

        if include_raw_body:
            bodie['content'] = body

        # Sometimes bad people play with multiple header instances.
        # We "display" the "LAST" one .. as does thunderbird
        val = ch.get('content-type')
        if val:
            header_val = val[-1]
            bodie['content_type'] = header_val.split(';', 1)[0].strip()

        # Hash the body
        bodie['hash'] = hashlib.sha256(body.encode('utf-8')).hexdigest()

        uid = str(uuid.uuid1())
        bodys[uid] = bodie

    bodys_struc = bodys

    # Get all other bulk raw headers
    # "a","toto"           a: [toto,titi]
    # "a","titi"   --->    c: [truc]
    # "c","truc"
    #
    for k in set(msg.keys()):
        # We are using replace . to : for avoiding issue in mongo
        k = k.lower()  # Lot of lower, precompute...
        decoded_values = []

        try:
            for value in msg.get_all(k, []):
                if value:
                    decoded_values.append(value)
        except (IndexError, AttributeError):
            # We have hit current open issue #27257
            # https://bugs.python.org/issue27257
            # The field will be set to emtpy as a workaround.
            logger.exception('We hit bug 27257!')

            decoded_values = eml_parser.decode.workaround_bug_27257_field_value(msg, k)

            if k in header:
                header[k] += decoded_values
            else:
                header[k] = decoded_values

        if decoded_values:
            if k in header:
                header[k] += decoded_values
            else:
                header[k] = decoded_values

    headers_struc['header'] = header

    # parse attachments
    if parse_attachments:
        try:
            report_struc['attachment'] = traverse_multipart(msg, 0, include_attachment_data)
        except (binascii.Error, AssertionError):
            # we hit this exception if the payload contains invalid data
            logger.exception('Exception occured while parsing attachment data. Collected data will not be complete!')
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
    for body in bodys_struc:
        newbody.append(bodys_struc[body])
    report_struc['body'] = newbody
    # End of dirty hack

    # Get all other bulk headers
    report_struc['header'] = headers_struc

    return report_struc
