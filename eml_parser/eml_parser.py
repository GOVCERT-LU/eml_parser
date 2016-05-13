#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# Georges Toth (c) 2013 <georges@trypill.org>
# GOVCERT.LU (c) 2014 <georges.toth@govcert.etat.lu>
# GOVCERT.LU (c) 2016 <paul.jung@ext.govcert.etat.lu>
#
# eml_parser is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# eml_parser is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with eml_parser.  If not, see <http://www.gnu.org/licenses/>.
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
import getopt
import re
import uuid
import datetime
import calendar
import dateutil.tz
import dateutil.parser
import base64
import hashlib
import quopri
import pprint
import time
from urlparse import urlparse

try:
    import chardet
except ImportError:
    chardet = None

try:
    import magic
except ImportError:
    magic = None


# regex compilation
# W3C HTML5 standard recommended regex for e-mail validation
email_regex = re.compile(r'''([a-zA-Z0-9.!#$%&'*+-/=?\^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*)''', re.MULTILINE)
#                 /^[a-zA-Z0-9.!#$%&'*+-/=?\^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/
recv_dom_regex = re.compile(r'''(?:(?:from|by)\s+)([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]{2,})+)''', re.MULTILINE)

dom_regex = re.compile(r'''(?:\s|[\/<>'])([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]{2,})+)(?:$|\s|[\/<>'])''', re.MULTILINE)
ipv4_regex = re.compile(r'''((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))''', re.MULTILINE)

b_d_regex = re.compile(r'(localhost|[a-z0-9.\-]+(?:[.][a-z]{2,4})?)')

f_d_regex = re.compile(r'from(?:\s+(localhost|[a-z0-9\-]+|[a-z0-9.\-]+' +
                       '[.][a-z]{2,4}))?\s+(?:\(?(localhost|[a-z0-9.\-]+[.][a-z]{2,4})' +
                       '?\s*\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\)?)?')

for_d_regex = re.compile(r'for\s+<?([a-z0-9.\-]+@[a-z0-9.\-]+[.][a-z]{2,4})>?')

# note: depending on the text this regex blocks in an infinite loop !
url_regex = re.compile(r'''(?i)\b((?:(hxxps?|https?|ftps?)://|www\d{0,3}[.]|[a-z0-9.\-]+[.]' +
                       '[a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+' +
                       '(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?]))''',
                       re.VERBOSE | re.MULTILINE)

# simple version for searching for URLs
# character set based on http://tools.ietf.org/html/rfc3986
# url_regex_simple = re.compile(r'''(?i)\b((?:(hxxps?|https?|ftps?)://)[^ ]+)''', re.VERBOSE | re.MULTILINE)
url_regex_simple = re.compile(r'''(([a-z]{3,}s?://)[a-z0-9\-_]+(\.[a-z0-9\-_]+)*(/[a-z0-9_\-\.~!*'();:@&=+$,/?%#\[\]]*)?)''', re.VERBOSE | re.MULTILINE | re.I)

# encoded string =?<encoding>?[QB]?<string>?=
re_encoded_string = re.compile(r'\=\?[^?]+\?[QB]\?[^?]+?\?\=', (re.X | re.M | re.I))

re_quoted_string = re.compile(r'''(                               # Group around entire regex to include it in matches
                                   \=\?[^?]+\?([QB])\?[^?]+?\?\=  # Quoted String with subgroup for encoding method
                                   |                              # or
                                   .+?(?=\=\?|$)                  # Plain String
                                  )''', (re.X | re.M | re.I))

re_q_value = re.compile(r'\=\?(.+)?\?[Qq]\?(.+)?\?\=')
re_b_value = re.compile(r'\=\?(.+)?\?[Bb]\?(.+)?\?\=')
################################################


def get_raw_body_text(msg):
    raw_body = []
    # FIXME comprend pas, si pas multipart pas d'attachement...
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
    extension = ''
    dot_idx = filename.rfind('.')

    if dot_idx != -1:
        extension = filename[dot_idx + 1:]

    return extension


def get_file_hashes(data):
    hashalgo = ['md5', 'sha1', 'sha256', 'sha512']
    hashes = {}

    for k in hashalgo:
        ha = getattr(hashlib, k)
        h = ha()
        h.update(data)
        hashes[k] = h.hexdigest()

    return hashes


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
                filename = 'part-%03d' % (counter)
            else:
                filename = decode_field(filename)

            extension = get_file_extension(filename)
            hashes = get_file_hashes(data)

            file_id = str(uuid.uuid1())
            attachments[file_id] = {}
            attachments[file_id]['filename'] = filename
            attachments[file_id]['size'] = file_size

            if extension:
                attachments[file_id]['extension'] = extension
            attachments[file_id]['hashes'] = hashes

            if magic:
                attachments[file_id]['mime-type'] = ms.buffer(data).decode('utf-8')
                attachments[file_id]['mime-type-short'] = attachments[file_id]['mime-type'].split(",")[0]

            if include_attachment_data:
                attachments[file_id]['raw'] = base64.b64encode(data)

            ch = {}
            for k, v in msg.items():
                k = k.lower()
                if k in ch:
                    # print "%s %s" % (v, k)
                    ch[k] = ch[k].append(v)
                else:
                    ch[k] = [v]

            attachments[file_id]['content-headers'] = ch

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
    '''Try to get the specified field using the Header module.
     If there is also an associated encoding, try to decode the
     field and return it, else return a specified default value.'''

    text = field

    try:
        _decoded = email.Header.decode_header(field)
        _text, charset = _decoded[0]
    except email.errors.HeaderParseError:
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
    except UnicodeDecodeError:
        if chardet:
            enc = chardet.detect(string)
            try:
                if not (enc['confidence'] == 1 and enc['encoding'] == 'ascii'):
                    value = value.decode(enc['encoding'])
                else:
                    value = value.decode('ascii', 'ignore')
            except UnicodeDecodeError:
                value = force_string_decode(string)

    return value


def q_value_decode(string):
    m = re_q_value.match(string)
    if m:
        encoding, e_string = m.groups()
        d_string = quopri.decodestring(e_string).decode(encoding, 'ignore')
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


# Decodes a given string as Base64 or Quoted Printable, depending on what
# type it is.
#
# String has to be of the format =?<encoding>?[QB]?<string>?=
def decode_value(string):
    # Optimization: If there's no encoded-words in the stringing, just return it
    if not re_encoded_string.search(string):
        return string

    # Split on white-space boundaries with capture, so we capture the white-space as well
    string_ = u''
    for line in string.replace('\r', '').split('\n'):
        line_ = u''

        for text in re.split(r'([ \t])', line):
            if '=?' in text:
                # Search for occurences of quoted stringings or plain stringings
                for m in re_quoted_string.finditer(text):
                    match_s, method = m.groups()

                    if '=?' in match_s:
                        if method.lower() == 'q':
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


def decode_email(eml_file, include_raw_body=False, include_attachment_data=False):
    fp = open(eml_file)
    msg = email.message_from_file(fp)
    fp.close()
    return parse_email(msg, include_raw_body, include_attachment_data)


def decode_email_s(eml_file, include_raw_body=False, include_attachment_data=False):
    msg = email.message_from_string(eml_file)
    return parse_email(msg, include_raw_body, include_attachment_data)


# Convert emails to a list from a given header field.
def headeremail2list(mail, header):
    # parse and decode to
    field = email.utils.getaddresses(mail.get_all(header, []))
    return_field = []
    for m in field:
        if not m[1] == '':
            return_field.append(m[1].lower())
    return return_field


#  Parse an email an return a structure.
#
def parse_email(msg, include_raw_body=False, include_attachment_data=False):
    maila = {}
    header = {}
    report_struc = {}  # Final structure
    headers_struc = {}  # header_structure
    attachements_struc = {}  # attachements structure
    bodys_struc = {}  # body structure

    # parse and decode subject
    subject = msg.get('subject', '')
    headers_struc['subject'] = decode_field(subject)

    # If parsing had problem... report it...
    if msg.defects:
        headers_struc['defect'] = msg.defects

    # messageid
    headers_struc['message-id'] = msg.get('message-id', '')

    # parse and decode from
    # @TODO verify if this hack is necessary for other e-mail fields as well
    m = email_regex.search(msg.get('from', '').lower())
    if m:
        headers_struc['from'] = m.group(1)
    else:
        from_ = email.utils.parseaddr(msg.get('from', '').lower())
        headers_struc['from'] = from_[1]

    # parse and decode to
    headers_struc['to'] = headeremail2list(msg, 'to')
    # parse and decode Cc
    headers_struc['cc'] = headeremail2list(msg, 'cc')
    if len(headers_struc['cc']) == 0:
        headers_struc.pop('cc')

    # parse and decode delivered-to
    headers_struc['delivered-to'] = headeremail2list(msg, 'delivered-to')
    if len(headers_struc['delivered-to']) == 0:
        headers_struc.pop('delivered-to')

    # parse and decode Date
    # If date field is present
    if msg.get('date'):

        # "." -> ":" replacement is for fixing bad clients (e.g. outlook express)
        msg_date = msg.get('date').replace('.', ':')
        date_ = email.utils.parsedate_tz(msg_date)

        if date_ and not date_[9] is None:
            ts = email.utils.mktime_tz(date_)
            date_ = datetime.datetime.utcfromtimestamp(ts)
        else:
            date_ = email.utils.parsedate(msg_date)
            if date_:
                ts = calendar.timegm(date_)
                date_ = datetime.datetime.utcfromtimestamp(ts)
            else:
                # Now we are facing an invalid date.
                date_ = dateutil.parser.parse('1970-01-01 00:00:00 +0000')

        if date_.tzname() is None:
            date_ = date_.replace(tzinfo=dateutil.tz.tzutc())
        headers_struc['date'] = date_
    else:
        # If date field is absent...
        headers_struc['date'] = dateutil.parser.parse('1970-01-01 00:00:00 +0000')
    headers_struc['parse_date'] = datetime.datetime.utcnow()

    # TODO ...
    # x-originating IP suspended.
    # header['x-originating-ip'] = msg.get('x-originating-ip', '').strip('[]')

    # mail receiver path / parse any domain, e-mail
    # @TODO parse case where domain is specified but in parantheses only an IP
    headers_struc['received'] = []
    headers_struc['received_emails'] = []
    headers_struc['received_domains'] = []

    for l in msg.get_all('received'):
        l = re.sub(r'(\r|\n|\s|\t)+', ' ', l.lower())
        headers_struc['received'].append(l)

        # search for domains / e-mail addresses
        for m in recv_dom_regex.findall(l):
            checks = True
            if '.' in m:
                try:
                    test = int(re.sub(r'[.-]', '', m))

                    if not ipv4_regex.match(m) or m == '127.0.0.1':
                        checks = False
                except ValueError:
                    pass

            if checks:
                headers_struc['received_domains'].append(m)

        m = email_regex.findall(l)
        if m:
            headers_struc['received_emails'] += m

    # ----------------------------------------------

        # try to parse received lines and normalize them
        try:
            f, b = l.split('by')
            b, undef = b.split('for')
        except:
            continue

        b_d = b_d_regex.search(b)

        '''
        # Catch of for emails in received.. we catch all email for now
        for_d = for_d_regex.search(l)
        # Add to TO address from routing headers "for xxxx@xxxx"
        if for_d:
            headers_struc['received_emails'].append(for_d.group(1))
            headers_struc['received_emails'] = list(set(headers_struc['to']))
        '''
        '''
        # Catch FROM --- TO tuple .. but still with (detail)...
        f_d = f_d_regex.search(f)
        if f_d:
            if not f_d.group(2):
                f_d_2 = ''
            else:
                f_d_2 = f_d.group(2)
            if not f_d.group(3):
                f_d_3 = ''
            else:
                f_d_3 = f_d.group(3)

            f = '{0} ({1} [{2}])'.format(f_d.group(1), f_d_2, f_d_3)

            if b_d is None:
                b = ''
            else:
                b = b_d.group(1)
            headers_struc['received'].append([f, b])

        headers_struc['received'] = tuple(headers_struc['received'])
        '''
    headers_struc['received_emails'] = list(set(headers_struc['received_emails']))
    headers_struc['received_domains'] = list(set(headers_struc['received_domains']))

    # Clean up if empty
    if len(headers_struc['received_emails']) == 0:
        headers_struc.pop('received_emails')
    if len(headers_struc['received_domains']) == 0:
        headers_struc.pop('received_domains')

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
        list_observed_emails = []
        list_observed_dom = []

        if sys.version_info >= (3, 0) and (isinstance(body, bytes) or isinstance(body, bytearray)):
            body = body.decode('utf-8', 'ignore')

        for match in url_regex_simple.findall(body):
            found_url = match[0].replace('hxxp', 'http')
            found_url = urlparse(found_url).geturl()
            # let's try to be smart by stripping of noisy bogus parts
            found_url = re.split(r'''[\', ", \,, \), \}, \\]''', found_url)[0]

            if found_url not in list_observed_urls:
                list_observed_urls.append(found_url)

        for match in email_regex.findall(body):
            list_observed_emails.append(match.lower())

        for match in dom_regex.findall(body):
            list_observed_dom.append(match.lower())

        # Report uris,email and observed domains or hashes if no raw body
        if include_raw_body:
            if list_observed_urls:
                bodie['uris'] = list(set(list_observed_urls))

            if list_observed_emails:
                bodie['emails'] = list(set(list_observed_emails))

            if list_observed_dom:
                bodie['domains'] = list(set(list_observed_dom))
        else:
            if list_observed_urls:
                bodie['uris-hashes'] = []
                for uri in list(set(list_observed_urls)):
                    bodie['uris-hashes'].append(hashlib.sha256(uri.lower()).hexdigest())
            if list_observed_emails:
                bodie['emails-hashes'] = []
                for uri in list(set(list_observed_emails)):
                    # Email already lowered
                    bodie['emails-hashes'].append(hashlib.sha256(uri).hexdigest())
            if list_observed_dom:
                bodie['dom-hashes'] = []
                for uri in list(set(list_observed_dom)):
                    bodie['dom-hashes'].append(hashlib.sha256(uri.lower()).hexdigest())

        # For mail without multipart we will only get the "content....something" headers
        # all other headers are in "header"
        # but we need to convert header tuples in dict..
        # "a","toto"           a: [toto,titi]
        # "a","titi"   --->    c: truc
        # "c","truc"
        ch = {}
        for k, v in body_multhead:
            k = k.lower()  # Lot of lowers, precompute :) .
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
        bodie['content_headers'] = ch  # Store content headers dict

        if include_raw_body:
            bodie['content'] = body

        # Sometimes dirty peoples plays with multiple header.
        # We "display" the "LAST" .. as do a thunderbird
        val = ch.get('content-type')
        if val:
            if type(val) == list:
                val = str(val[-1:])
            bodie['content-type'] = val.split(';')[0].strip()
        bodie['hash'] = hashlib.sha256(body.encode('utf-8')).hexdigest()
        bodys[str(uuid.uuid1())] = bodie

    bodys_struc = bodys

    # Get all other bulk raw headers
    # "a","toto"           a: [toto,titi]
    # "a","titi"   --->    c: [truc]
    # "c","truc"
    #
    for k, v in msg.items():
        k = k.lower()  # Lot of lower, precompute...
        if k in header:
            header[k].append(v)
        else:
            header[k] = [v]
    headers_struc['header'] = header

    # parse attachments
    report_struc['attachment'] = traverse_multipart(msg, 0, include_attachment_data)
    if len(report_struc['attachment']) == 0:
        report_struc.pop('attachment')

    # Get all other bulk headers
    report_struc['header'] = headers_struc
    report_struc['body'] = bodys_struc
    # report_struc['attachment'] = attachements_struc

    return report_struc


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""

    if isinstance(obj, datetime.datetime):
        serial = obj.isoformat()
        return serial
    raise TypeError("Type not serializable")


def main():
    opts, args = getopt.getopt(sys.argv[1:], 'i:')
    msgfile = None

    for o, k in opts:
        if o == '-i':
            msgfile = k

    m = decode_email(msgfile, False)
    print json.dumps(m, default=json_serial)
    '''if m.get('date'):
        m.get('date').isoformat()
    # print decode_email(msgfile, include_raw_body=True, include_attachment_data=True)
    '''

if __name__ == '__main__':
    main()
