#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
from __future__ import print_function

#
# Georges Toth (c) 2013-2014 <georges@trypill.org>
# GOVCERT.LU (c) 2013-2017 <info@govcert.etat.lu>
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

import sys
import json
import email
import argparse
import re
import uuid
import datetime
import calendar
import dateutil.tz
import dateutil.parser
import base64
import hashlib
import quopri
import collections

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

try:
    try:
        import cchardet as chardet
    except ImportError:
        import chardet
except ImportError:
    chardet = None

try:
    import magic
except ImportError:
    magic = None


__author__ = 'Toth Georges, Jung Paul'
__email__ = 'georges@trypill.org, georges.toth@govcert.etat.lu'
__copyright__ = 'Copyright 2013-2014 Georges Toth, Copyright 2013-2017 GOVCERT Luxembourg'
__license__ = 'AGPL v3+'


# regex compilation
# W3C HTML5 standard recommended regex for e-mail validation
email_regex = re.compile(r'''([a-zA-Z0-9.!#$%&'*+-/=?\^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*)''', re.MULTILINE)
#                 /^[a-zA-Z0-9.!#$%&'*+-/=?\^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/
recv_dom_regex = re.compile(r'''(?:(?:from|by)\s+)([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]{2,})+)''', re.MULTILINE)

dom_regex = re.compile(r'''(?:\s|[\(\/<>|@'=])([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]{2,})+)(?:$|\?|\s|#|&|[\/<>'\)])''', re.MULTILINE)
ipv4_regex = re.compile(r'''((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))''', re.MULTILINE)


# From https://gist.github.com/mnordhoff/2213179 : IPv6 with zone ID (RFC 6874)
ipv6_regex = re.compile('((?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)')

b_d_regex = re.compile(r'(localhost|[a-z0-9.\-]+(?:[.][a-z]{2,4})?)')

f_d_regex = re.compile(r'from(?:\s+(localhost|[a-z0-9\-]+|[a-z0-9.\-]+' +
                       r'[.][a-z]{2,4}))?\s+(?:\(?(localhost|[a-z0-9.\-]+[.][a-z]{2,4})' +
                       r'?\s*\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\)?)?')

for_d_regex = re.compile(r'for\s+<?([a-z0-9.\-]+@[a-z0-9.\-]+[.][a-z]{2,4})>?')

# note: depending on the text this regex blocks in an infinite loop !
url_regex = re.compile(r'''(?i)\b((?:(hxxps?|https?|ftps?)://|www\d{0,3}[.]|[a-z:0-9.\-]+[.]' +
                       r'[a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+' +
                       r'(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?]))''',
                       re.VERBOSE | re.MULTILINE)

# simple version for searching for URLs
# character set based on http://tools.ietf.org/html/rfc3986
# url_regex_simple = re.compile(r'''(?i)\b((?:(hxxps?|https?|ftps?)://)[^ ]+)''', re.VERBOSE | re.MULTILINE)
url_regex_simple = re.compile(r'''(([a-z]{3,}s?:\/\/)[a-z0-9\-_:]+(\.[a-z0-9\-_]+)*''' +
                              r'''(\/[a-z0-9_\-\.~!*'();:@&=+$,\/  ?%#\[\]]*)?)''',
                              re.VERBOSE | re.MULTILINE | re.I)

# encoded string =?<encoding>?[QB]?<string>?=
re_encoded_string = re.compile(r'\=\?[^?]+\?[QB]\?[^?]+?\?\=', (re.X | re.M | re.I))

re_quoted_string = re.compile(r'''(                               # Group around entire regex to include it in matches
                                   \=\?[^?]+\?([QB])\?[^?]+?\?\=  # Quoted String with subgroup for encoding method
                                   |                              # or
                                   .+?(?=\=\?|$)                  # Plain String
                                  )''', (re.X | re.M | re.I))

re_q_value = re.compile(r'\=\?(.+)?\?[Qq]\?(.+)?\?\=')
re_b_value = re.compile(r'\=\?(.+)?\?[Bb]\?(.+)?\?\=')

priv_ip_regex = re.compile(r"^(((10(\.\d{1,3}){3})|(192\.168(\.\d{1,3}){2})|(172\.(([1][6-9])|([2]\d)|([3][0-1]))(\.\d{1,3}){2}))|(127(\.\d{1,3}){3})|(::1))")

reg_date = re.compile(r';[ \w\s:,+\-\(\)]+$')
no_par = re.compile(r'\([^()]*\)')


################################################


def get_raw_body_text(msg):
    raw_body = []
    # FIXME comprend pas, si pas multipart pas d'attachement...
    if msg.is_multipart():
        for part in msg.get_payload():
            raw_body.extend(get_raw_body_text(part))
    else:
        # Treat text document attachments as belonging to the body of the mail.
        # Attachments with a file-extension of .htm/.html are implicitely treated
        # as text as well in order not to escape later checks (e.g. URL scan).
        if ('content-disposition' not in msg and msg.get_content_maintype() == 'text') \
           or (msg.get_filename('').lower().endswith('.html') or
           msg.get_filename('').lower().endswith('.htm')):
            encoding = msg.get('content-transfer-encoding', '').lower()

            charset = msg.get_content_charset()
            if not charset:
                raw_body_str = msg.get_payload(decode=True)
            else:
                try:
                    raw_body_str = msg.get_payload(decode=True).decode(charset, 'ignore')
                except:
                    raw_body_str = msg.get_payload(decode=True).decode('ascii', 'ignore')

            raw_body.append((encoding, raw_body_str, msg.items()))
    return raw_body


def get_file_extension(filename):
    """Return the file extention of a given filename

    Args:
      filename (str): The file name.

    Returns:
      str: The lower-case file extension
    """
    extension = ''
    dot_idx = filename.rfind('.')

    if dot_idx != -1:
        extension = filename[dot_idx + 1:]

    return extension.lower()


def get_file_hash(data):
    """Generate hashes of various types (``MD5``, ``SHA-1``, ``SHA-256``, ``SHA-512``)
    for the provided data.

    Args:
      data (str): The data to calculate the hashes on.

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


def ascii_decode(string):
    """Ascii Decode a given string; useful with dirty headers.

    Args:
      string (str): The string to be converted.

    Returns:
      str: Returns the decoded string.
    """
    try:
        return string.decode('latin-1').encode('utf-8')
    except:
        return string.encode('utf-8', 'replace')


def traverse_multipart(msg, counter=0, include_attachment_data=False):
    attachments = {}

    if magic:
        ms = magic.open(magic.NONE)
        ms.load()

    if msg.is_multipart():
        for part in msg.get_payload():
            attachments.update(traverse_multipart(part, counter, include_attachment_data))
    else:
        lower_keys = dict((k.lower(), v) for k, v in msg.items())

        if 'content-disposition' in lower_keys or not msg.get_content_maintype() == 'text':
            # if it's an attachment-type, pull out the filename
            # and calculate the size in bytes
            data = msg.get_payload(decode=True)
            file_size = len(data)

            filename = msg.get_filename('')
            if filename == '':
                filename = 'part-{0:03d}'.format(counter)
            else:
                filename = decode_field(filename)

            extension = get_file_extension(filename)
            hash_ = get_file_hash(data)

            file_id = str(uuid.uuid1())
            attachments[file_id] = {}
            attachments[file_id]['filename'] = ascii_decode(filename)
            attachments[file_id]['size'] = file_size

            if extension:
                attachments[file_id]['extension'] = ascii_decode(extension)
            attachments[file_id]['hash'] = hash_

            if magic:
                attachments[file_id]['mime_type'] = ms.buffer(data).decode('utf-8')
                # attachments[file_id]['mime_type_short'] = attachments[file_id]['mime_type'].split(",")[0]
                ms = magic.open(magic.MAGIC_MIME_TYPE)
                ms.load()
                attachments[file_id]['mime_type_short'] = ms.buffer(data).decode('utf-8')

            if include_attachment_data:
                attachments[file_id]['raw'] = base64.b64encode(data)

            ch = {}
            for k, v in msg.items():
                k = ascii_decode(k.lower())
                if k in ch:
                    # print "%s<<<>>>%s" % (k, v)
                    ch[k].append(ascii_decode(v))
                else:
                    ch[k] = [ascii_decode(v)]

            attachments[file_id]['content_header'] = ch

            counter += 1
    return attachments


def force_string_decode(string):
    if string is None:
        return ''

    encodings = ('latin1', 'utf-8')
    text = ''

    for e in encodings:
        try:
            test = string.decode(e)
            text = test
            break
        except UnicodeDecodeError:
            pass

    if text == '':
        text = string.decode('ascii', 'ignore')

    return text


def decode_field(field):
    """Try to get the specified field using the Header module.
     If there is also an associated encoding, try to decode the
     field and return it, else return a specified default value."""

    text = field

    try:
        Header = email.Header
    except AttributeError:
        # Python3 support
        Header = email.header

    try:
        _decoded = Header.decode_header(field)
        _text, charset = _decoded[0]
    except (email.errors.HeaderParseError, UnicodeEncodeError):
        _text, charset = None, None

    if charset:
        try:
            text = decode_string(_text, charset)
        except UnicodeDecodeError:
            pass

    try:
        text = decode_value(text)
    except UnicodeDecodeError:
        text = decode_string(text, 'latin-1')

    return text


def decode_string(string, encoding):
    try:
        value = string.decode(encoding)
    except (UnicodeDecodeError, LookupError):
        if chardet:
            enc = chardet.detect(string)
            try:
                if not (enc['confidence'] == 1 and enc['encoding'] == 'ascii'):
                    value = string.decode(enc['encoding'])
                else:
                    value = string.decode('ascii', 'ignore')
            except UnicodeDecodeError:
                value = force_string_decode(string)

    return value


def q_value_decode(string):
    m = re_q_value.match(string)
    if m:
        encoding, e_string = m.groups()
        if encoding.lower() != 'unknown':
            d_string = quopri.decodestring(e_string).decode(encoding, 'ignore')
        else:
            d_string = e_string.decode('utf-8', 'ignore')
    else:
        d_string = e_string.decode('utf-8', 'ignore')
    return d_string


def b_value_decode(string):
    m = re_b_value.match(string)
    if m:
        encoding, e_string = m.groups()
        d_string = base64.decodestring(e_string).decode(encoding, 'ignore')
    else:
        d_string = e_string.decode('utf-8', 'ignore')

    return d_string


def decode_value(string):
    '''
    Decodes a given string as Base64 or Quoted Printable, depending on what
    type it is.

    String has to be of the format =?<encoding>?[QB]?<string>?=
    '''
    # Optimization: If there's no encoded-words in the stringing, just return it
    if not re_encoded_string.search(string):
        return string

    # First, convert CRLF to CR
    strings = []
    for line in string.replace('\r', '').split('\n'):
        strings.append(line)

    # Detect Invalide encoding !! and return as-is (as do thunderbird)
    for line in strings:
        if line.startswith("=?") and not line.endswith("?="):
            return "".join(strings)

    # Detect if space in it, in not do no split on space
    csplit = r'([ \t])'
    if line.startswith("=?") and line.endswith("?=") and " " in line:
        csplit = r'('')'

    # Split on white-space boundaries with capture, so we capture the white-space as well
    string_ = u''
    for line in string.replace('\r', '').split('\n'):
        line_ = u''

        for text in re.split(csplit, line):
            if '=?' in text:
                # Search for occurences of quoted stringings or plain stringings
                for m in re_quoted_string.finditer(text):
                    match_s, method = m.groups()

                    if '=?' in match_s:
                        if method is None:
                            raise Exception('NOTIMPLEMENTED: Unknown method "{0}"'.format(method))
                        elif method.lower() == 'q':
                            text = q_value_decode(match_s)
                        elif method.lower() == 'b':
                            text = b_value_decode(match_s)
                        else:
                            raise Exception('NOTIMPLEMENTED: Unknown method "{0}"'.format(method))

                        text = text.replace('_', ' ')

                        if text[0] == ' ':
                            text = text[1:]
                    else:
                        line_ += match_s

                line_ += text

            if len(string_) > 0 and not (string_[-1] == ' ' or line_[0] == ' '):
                string_ += ' '

            string_ += line_

        return string_


def decode_email(eml_file, include_raw_body=False, include_attachment_data=False, pconf=False):
    fp = open(eml_file)
    msg = email.message_from_file(fp)
    fp.close()
    return parse_email(msg, include_raw_body, include_attachment_data, pconf)


def decode_email_s(eml_file, include_raw_body=False, include_attachment_data=False, pconf=False):
    msg = email.message_from_string(eml_file)
    return parse_email(msg, include_raw_body, include_attachment_data, pconf)


# Regex extract uri from data, return list
def get_uri_ondata(body):
    list_observed_urls = []
    found_url = []
    for match in url_regex_simple.findall(body):
        found_url = match[0].replace('hxxp', 'http')
        found_url = urlparse(found_url).geturl()
        # let's try to be smart by stripping of noisy bogus parts
        found_url = re.split(r'''[\', ", \,, \), \}, \\]''', found_url)[0]
        list_observed_urls.append(found_url)
    return list_observed_urls


# Convert email to a list from a given header field.
def headeremail2list(mail, header):
    # parse and decode to
    field = email.utils.getaddresses(mail.get_all(header, []))
    return_field = []
    for m in field:
        if not m[1] == '':
            return_field.append(m[1].lower())
    return return_field


# Iterator that give all position of a given pattern (no regex)
def findall(pat, data):
    i = data.find(pat)
    while i != -1:
        yield i
        i = data.find(pat, i + 1)


# Remove nested parenthesis, until they're are present
def noparenthesis(line):
    idem = False
    while not idem:
        lline = line
        line = re.sub(no_par, '', line)
        if lline == line:
            idem = True
    return line


def getkey(item):
    return item[0]


def regprep(line):
    for ch in '^$[]()+?.':
        line = re.sub("\\" + ch, '\\\\' + ch, line)
    return line


# Remove space and ; from start/end of line until it is not possible.
def cleanline(line):
    idem = False
    while not idem:
        lline = line
        line = line.strip(";")
        line = line.strip(" ")
        if lline == line:
            idem = True
    return line


def robust_string2date(line):
    # "." -> ":" replacement is for fixing bad clients (e.g. outlook express)
    default_date = '1970-01-01 00:00:00 +0000'
    msg_date = line.replace('.', ':')
    date_ = email.utils.parsedate_tz(msg_date)

    if date_ and date_[9] is not None:
        ts = email.utils.mktime_tz(date_)
        date_ = datetime.datetime.utcfromtimestamp(ts)
    else:
        date_ = email.utils.parsedate(msg_date)
        if date_:
            ts = calendar.timegm(date_)
            date_ = datetime.datetime.utcfromtimestamp(ts)
        else:
            # Now we are facing an invalid date.
            date_ = dateutil.parser.parse(default_date)

    if date_.tzname() is None:
        date_ = date_.replace(tzinfo=dateutil.tz.tzutc())
        return date_
    else:
        # If date field is absent...
        return dateutil.parser.parse(default_date)


def parserouting(line):
    #    if re.findall(reg_date, line):
    #        return 'date\n'
    # Preprocess the line to simplify from/by/with/for border detection.
    out = {}  # Result
    out['src'] = line
    line = line.lower()  # Convert everything to lowercase
    npline = re.sub(r'\)', ' ) ', line)  # nORMALISE sPACE # Re-space () ")by " exists often
    npline = re.sub(r'\(', ' ( ', npline)  # nORMALISE sPACE # Re-space ()
    npline = re.sub(';', ' ; ', npline)  # nORMALISE sPACE # Re-space ;
    npline = noparenthesis(npline)  # Remove any "()"
    npline = re.sub('  *', ' ', npline)  # nORMALISE sPACE
    npline = npline.strip('\n')  # Remove any NL
    npdate = re.findall(reg_date, npline)  # eXTRACT date on end line.

    # Detect "sticked lines"
    if " received: " in npline:
        out['warning'] = ['Merged Received headers']
        return out

    if npdate:
        npdate = npdate[0]  # Remove spaces and starting ;
    else:
        npdate = ""
    npline = npline.replace(npdate, "")  # Remove date from input line
    npline = npline.strip(' ')  # Remove any border WhiteSpace
    npdate = npdate.lstrip(";")  # Remove Spaces and stating ; from date
    npdate = npdate.strip(" ")

    borders = ['from ', 'by ', 'with ', 'for ']
    candidate = []
    result = []

    # Scan the line to determine the order, and presence of each "from/by/with/for" words
    for word in borders:
        candidate = list(borders)
        candidate.remove(word)
        for endword in candidate:
            if word in npline:
                loc = npline.find(word)
                end = npline.find(endword)
                if end < loc or end == -1:
                    end = 0xfffffff   # Kindof MAX 31 bits
                result.append({'name_in': word, 'pos': loc, 'name_out': endword, 'weight': end + loc})
                # print {'name_in': word, 'pos': loc, 'name_out': endword, 'weight': end+loc}

    # Create the word list... "from/by/with/for" by sorting the list.
    if len(result) == 0:
        out['warning'] = ['Nothing Parsable']
        return out

    tout = []
    for word in borders:
        result_max = 0xffffffff
        line_max = {}
        for eline in result:
            if eline['name_in'] == word and eline['weight'] <= result_max:
                result_max = eline['weight']
                line_max = eline

        if len(line_max) is not 0:
            tout.append([line_max.get('pos'), line_max.get('name_in')])

    tout = sorted(tout, key=getkey)

    # build rexex.
    reg = ""
    for item in tout:
        reg = reg + item[1] + "(?P<" + item[1].strip() + ">.*)"
    if npdate:
        reg = reg + regprep(npdate)

    reparse = re.compile(reg)
    reparseg = reparse.search(line)

    # Fill the data
    for item in borders:
        try:
            out[item.strip()] = cleanline(reparseg.group(item.strip()))
        except:
            pass
    out['date'] = robust_string2date(npdate)

    # Fixup for "From" in "for" field
    # ie google, do that...
    if out.get('for'):
        if 'from' in out.get('for'):
            temp = re.split(' from ', out['for'])
            out['for'] = temp[0]
            out['from'] = '{0} {1}'.format(out['from'], " ".join(temp[1:]))

        m = email_regex.findall(out['for'])
        if m:
            out['for'] = list(set(m))
        else:
            del out['for']

    # Now.. find IP and Host in from
    if out.get('from'):
        out['from'] = give_dom_ip(out['from'])
        if len(out.get('from')) < 1:  # if array is empty remove
            del out['from']

    # Now.. find IP and Host in from
    if out.get('by'):
        out['by'] = give_dom_ip(out['by'])
        if len(out.get('by')) < 1:  # If array is empty remove
            del out['by']

    return out


def give_dom_ip(line):
    m = dom_regex.findall(" " + line) + ipv4_regex.findall(line) + ipv6_regex.findall(line)
    return list(set(m))


#  Parse an email an return a structure.
#
def parse_email(msg, include_raw_body=False, include_attachment_data=False, pconf=None):
    """Parse an e-mail and return a dictionary containing the various parts of
    the e-mail broken down into key-value pairs.

    Args:
      msg (str): Raw EML e-mail string.
      include_raw_body (bool, optional): If True, includes the raw body in the resulting
                               dictionary. Defaults to False.
      include_attachment_data (bool, optional): If True, includes the full attachment
                                                data in the resulting dictionary.
                                                Defaults to False.
      pconf (dict, optional): A dict with various optinal configuration parameters,
                              e.g. whitelist IPs, whitelist e-mail addresses, etc.

    Returns:
      dict: A dictionary with the content of the EML parsed and broken down into
            key-value pairs.
    """
    header = {}
    report_struc = {}  # Final structure
    headers_struc = {}  # header_structure
    bodys_struc = {}  # body structure

    # If no pconf was specified, default to empty dict
    pconf = pconf or {}

    # If no whitelisting of if is required initiate the empty variable arry
    if 'whiteip' not in pconf:
        pconf['whiteip'] = []
    # If no whitelisting of if is required initiate the empty variable arry
    if 'whitefor' not in pconf:
        pconf['whitefor'] = []

    # parse and decode subject
    subject = msg.get('subject', '')
    headers_struc['subject'] = ascii_decode(decode_field(subject))

    # If parsing had problem... report it...
    if msg.defects:
        headers_struc['defect'] = []
        for exception in msg.defects:
            headers_struc['defect'].append(str(exception))

    # parse and decode from
    # @TODO verify if this hack is necessary for other e-mail fields as well
    m = email_regex.search(msg.get('from', '').lower())
    if m:
        headers_struc['from'] = ascii_decode(m.group(1))
    else:
        from_ = email.utils.parseaddr(msg.get('from', '').lower())
        headers_struc['from'] = ascii_decode(from_[1])

    # parse and decode to
    headers_struc['to'] = headeremail2list(msg, 'to')
    # parse and decode Cc
    headers_struc['cc'] = headeremail2list(msg, 'cc')
    if len(headers_struc['cc']) == 0:
        headers_struc.pop('cc')

    # parse and decode delivered-to
    headers_struc['delivered_to'] = headeremail2list(msg, 'delivered-to')
    if len(headers_struc['delivered_to']) == 0:
        headers_struc.pop('delivered_to')

    # parse and decode Date
    # If date field is present
    if 'date' in msg:
        headers_struc['date'] = robust_string2date(msg.get('date'))
    else:
        # If date field is absent...
        headers_struc['date'] = dateutil.parser.parse('1970-01-01 00:00:00 +0000')
    headers_struc['parse_date'] = datetime.datetime.utcnow()

    # mail receiver path / parse any domain, e-mail
    # @TODO parse case where domain is specified but in parantheses only an IP
    headers_struc['received'] = []
    headers_struc['received_email'] = []
    headers_struc['received_domain'] = []
    headers_struc['received_ip'] = []
    try:
        found_smtpin = collections.Counter()  # Array for storing potential duplicate "HOP"

        for l in msg.get_all('received', []):

            l = re.sub(r'(\r|\n|\s|\t)+', ' ', l.lower())

            # Parse and split routing headers.
            # Return dict of array
            #   date string
            #   from array
            #   for array
            #   by array
            #   with string
            #   warning array
            current_line = parserouting(l)

            # If required collect the IP of the gateway that have injected the mail.
            # Iterate all parsed item and find IP
            # It is parsed from the MOST recent to the OLDEST (from IN > Out)
            # We match external IP from the most "OUT" Found.
            # Warning .. It may be spoofed !!
            # It add a warning if multiple identical items are found.

            if 'byhostentry' in pconf:
                if current_line.get('by'):
                    for by_item in current_line.get('by'):
                        for byhostentry in pconf['byhostentry']:
                            # print ("%s %s" % (byhostentry, by_item))
                            if byhostentry.lower() in by_item:
                                # Save the last Found.. ( most external )
                                headers_struc['received_src'] = current_line.get('from')

                                # Increment watched by detection counter, and warn if needed
                                found_smtpin[byhostentry.lower()] += 1
                                if found_smtpin[byhostentry.lower()] > 1:  # Twice found the header...
                                    if current_line.get('warning'):
                                        current_line['warning'].append(['Duplicate SMTP by entrypoint'])
                                    else:
                                        current_line['warning'] = ['Duplicate SMTP by entrypoint']

            headers_struc['received'].append(current_line)

            # Parse IP in "received headers"
            for ips in ipv6_regex.findall(l):
                if not priv_ip_regex.match(ips):
                    if ips.lower() not in pconf['whiteip']:
                        headers_struc['received_ip'].append(ips.lower())
            for ips in ipv4_regex.findall(l):
                if not priv_ip_regex.match(ips):
                    if ips not in pconf['whiteip']:
                        headers_struc['received_ip'].append(ips.lower())

            # search for domain / e-mail addresses
            for m in recv_dom_regex.findall(l):
                checks = True
                if '.' in m:
                    try:
                        if ipv4_regex.match(m) or m == '127.0.0.1':
                            checks = False
                    except ValueError:
                        pass
                if checks:
                    headers_struc['received_domain'].append(m)

            # Extracts emails, but not the ones in the FOR on this received headers line.
            # Process Here line per line not finally to not miss a email not in from
            m = email_regex.findall(l)
            if m:
                for mail_candidate in m:
                    if current_line.get('for'):
                        if mail_candidate not in current_line.get('for'):
                            headers_struc['received_email'] += [mail_candidate]
                    else:
                        headers_struc['received_email'] += [mail_candidate]

    except TypeError:  # Ready to parse email without received headers.
        pass

    # Concatenate for emails into one array | uniq
    # for rapid "find"
    if headers_struc.get('received'):
        headers_struc['received_foremail'] = []
        for line in headers_struc['received']:
            if line.get('for'):
                for itemfor in line.get('for'):
                    if itemfor not in pconf['whitefor']:
                        headers_struc['received_foremail'] += line.get('for')

    # Uniq data found
    headers_struc['received_email'] = list(set(headers_struc['received_email']))
    headers_struc['received_domain'] = list(set(headers_struc['received_domain']))
    headers_struc['received_ip'] = list(set(headers_struc['received_ip']))

    # Clean up if empty
    if len(headers_struc['received_email']) == 0:
        headers_struc.pop('received_email')
    if 'received_foremail' in headers_struc:
        if len(headers_struc['received_foremail']) == 0:
            del(headers_struc['received_foremail'])
        else:
            headers_struc['received_foremail'] = list(set(headers_struc['received_foremail']))
    if len(headers_struc['received_domain']) == 0:
        del(headers_struc['received_domain'])
    if len(headers_struc['received_ip']) == 0:
        del(headers_struc['received_ip'])

    # Parse TEXT BODYS
    # get raw header
    # FIXME. could not get body from non multipart mail.
    # needed for mailm0n project.
    raw_body = get_raw_body_text(msg)
    # include_raw_body = True
    if include_raw_body:
        bodys_struc['raw_body'] = raw_body

    bodys = {}
    multipart = True  # Is it a multipart email ?
    if len(raw_body) == 1:
        multipart = False  # No only "one" Part
    for body_tup in raw_body:
        bodie = {}
        encoding, body, body_multhead = body_tup
        # Parse any URLs and mail found in the body
        list_observed_urls = []
        list_observed_email = []
        list_observed_dom = []
        list_observed_ip = []

        if sys.version_info >= (3, 0) and (isinstance(body, bytes) or isinstance(body, bytearray)):
            body = body.decode('utf-8', 'ignore')

        # If we start directly a findall on 500K+ body we got time and memory issues...
        # if more than 4K.. lets cheat, we will cut around the thing we search "://, @, ."
        # in order to reduce regex complexity.
        if len(body) < 4096:
            list_observed_urls = get_uri_ondata(body)
            for match in email_regex.findall(body):
                list_observed_email.append(match.lower())
            for match in dom_regex.findall(body):
                list_observed_dom.append(match.lower())
            for match in ipv4_regex.findall(body):
                if not priv_ip_regex.match(match):
                    if match not in pconf['whiteip']:
                        list_observed_ip.append(match)
            for match in ipv6_regex.findall(body):
                if not priv_ip_regex.match(match):
                    if match.lower() not in pconf['whiteip']:
                        list_observed_ip.append(match.lower())
        else:
            for scn_pt in findall('://', body):
                list_observed_urls = get_uri_ondata(body[scn_pt - 16:scn_pt + 4096]) + list_observed_urls

            for scn_pt in findall('@', body):
                # RFC 3696, 5322, 5321 for email size limitations
                for match in email_regex.findall(body[scn_pt - 64:scn_pt + 255]):
                    list_observed_email.append(match.lower())

            for scn_pt in findall('.', body):
                # The maximum length of a fqdn, not a hostname, is 1004 characters RFC1035
                # The maximum length of a hostname is 253 characters. Imputed from RFC952, RFC1123 and RFC1035.
                for match in dom_regex.findall(body[scn_pt - 253:scn_pt + 1004]):
                    list_observed_dom.append(match.lower())

                # Find IPv4 addresses
                for match in ipv4_regex.findall(body[scn_pt - 11:scn_pt + 3]):
                    if not priv_ip_regex.match(match):
                        if match not in pconf['whiteip']:
                            list_observed_ip.append(match)

            for scn_pt in findall(':', body):
                # The maximum length of IPv6 is 32 Char + 7 ":"
                for match in ipv6_regex.findall(body[scn_pt - 4:scn_pt + 35]):
                    if not priv_ip_regex.match(match):
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
                    bodie['uri_hash'].append(hashlib.sha256(uri.lower()).hexdigest())
            if list_observed_email:
                bodie['email_hash'] = []
                for emel in list(set(list_observed_email)):
                    # Email already lowered
                    bodie['email_hash'].append(hashlib.sha256(emel).hexdigest())
            if list_observed_dom:
                bodie['domain_hash'] = []
                for uri in list(set(list_observed_dom)):
                    bodie['domain_hash'].append(hashlib.sha256(uri.lower()).hexdigest())
            if list_observed_ip:
                bodie['ip_hash'] = []
                for fip in list(set(list_observed_ip)):
                    # IP (v6) already lowered
                    bodie['ip_hash'].append(hashlib.sha256(fip).hexdigest())

        # For mail without multipart we will only get the "content....something" headers
        # all other headers are in "header"
        # but we need to convert header tuples in dict..
        # "a","toto"           a: [toto,titi]
        # "a","titi"   --->    c: [truc]
        # "c","truc"
        ch = {}
        for k, v in body_multhead:
            # We are using replace . to : for avoiding issue in mongo
            k = ascii_decode(k.lower()).replace('.', ':')  # Lot of lowers, precompute :) .
            # print v
            if multipart:
                if k in ch:
                    ch[k].append(ascii_decode(v))
                else:
                    ch[k] = [ascii_decode(v)]
            else:  # if not multipart, store only content-xx related header with part
                if k.startswith('content'):  # otherwise, we got all header headers
                    k = ascii_decode(k.lower()).replace('.', ':')
                    if k in ch:
                        ch[k].append(ascii_decode(v))
                    else:
                        ch[k] = [ascii_decode(v)]
        bodie['content_header'] = ch  # Store content headers dict

        if include_raw_body:
            bodie['content'] = body

        # Sometimes dirty peoples plays with multiple header.
        # We "display" the "LAST" one .. as do a thunderbird
        val = ch.get('content-type')
        if val:
            if type(val) == list:
                val = val[-1]
            bodie['content_type'] = val.split(';')[0].strip()

        # Try hashing.. with failback for incorrect encoding (non ascii)
        try:
            bodie['hash'] = hashlib.sha256(body).hexdigest()
        except:
            bodie['hash'] = hashlib.sha256(body.encode('UTF-8')).hexdigest()

        uid = str(uuid.uuid1())
        bodys[uid] = bodie

    bodys_struc = bodys

    # Get all other bulk raw headers
    # "a","toto"           a: [toto,titi]
    # "a","titi"   --->    c: [truc]
    # "c","truc"
    #
    for k, v in msg.items():
        # We are using replace . to : for avoiding issue in mongo
        k = ascii_decode(k.lower()).replace('.', ':')  # Lot of lower, precompute...
        if k in header:
            header[k].append(ascii_decode(v))
        else:
            header[k] = [ascii_decode(v)]
    headers_struc['header'] = header

    # parse attachments
    report_struc['attachment'] = traverse_multipart(msg, 0, include_attachment_data)

    # Dirty hack... transphorm hash in list.. need to be done in the function.
    # Mandatory to search efficiently in mongodb
    # See Bug 11 of eml_parser
    if len(report_struc['attachment']) == 0:
        del(report_struc['attachment'])
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


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""

    if isinstance(obj, datetime.datetime):
        serial = obj.isoformat()
        return serial

    raise TypeError("Type not serializable")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-i', dest='msgfile',
                        help='input file', required=True)
    parser.add_argument('-d', dest='debug', action='store_true',
                        help='debug (no hashing)')
    parser.add_argument('-r', dest='fulldata', action='store_true',
                        help='includes raw data of attachments')
    parser.add_argument('-w', dest='whitelist_ip',
                        help='whitelist IPv4 or IPv6 ip from parsing; comma-separated list of IPs, no spaces !')
    parser.add_argument('-f', dest='whitelist_email',
                        help='whitelist an email in routing headers "For"; comma-separated list of e-mail addresses, no spaces !')
    parser.add_argument('-b', dest='byhostentry',
                        help='collect the smtp injector IP using the "by" "host" in routing headers; comma-separated list of IPs, no spaces !')

    options = parser.parse_args()

    msgfile = options.msgfile
    full = options.debug
    fulldata = options.fulldata
    pconf = {}

    if options.whitelist_ip is not None:
        pconf['whiteip'] = options.whitelist_ip.split(',')

    if options.whitelist_email is not None:
        pconf['whitefor'] = options.whitelist_email.split(',')

    if options.byhostentry is not None:
        pconf['byhostentry'] = options.byhostentry.split(',')

    m = decode_email(msgfile, full, fulldata, pconf)
    print (json.dumps(m, default=json_serial))


if __name__ == '__main__':
    main()
