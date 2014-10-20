#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# Georges Toth (c) 2013 <georges@trypill.org>
# GOVCERT.LU (c) 2014 <georges.toth@govcert.etat.lu>
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
import time
from urlparse import urlparse

try:
  import chardet
except ImportError:
  chardet = None

try:
  from python_magic import magic
except ImportError:
  magic = None


# regex compilation
# W3C HTML5 standard recommended regex for e-mail validation
email_regex = re.compile(r'''([a-zA-Z0-9.!#$%&'*+-/=?\^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*)''', re.MULTILINE)
#                 /^[a-zA-Z0-9.!#$%&'*+-/=?\^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/
domain_regex = re.compile(r'''(?:(?:from|by)\s+)?([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)''', re.MULTILINE)
ipv4_regex = re.compile(r'''((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))''', re.MULTILINE)

b_d_regex = re.compile(r'(localhost|[a-z0-9.\-]+(?:[.][a-z]{2,4})?)')
f_d_regex = re.compile(r'from(?:\s+(localhost|[a-z0-9\-]+|[a-z0-9.\-]+[.][a-z]{2,4}))?\s+(?:\(?(localhost|[a-z0-9.\-]+[.][a-z]{2,4})?\s*\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\)?)?')
for_d_regex = re.compile(r'for\s+<?([a-z0-9.\-]+@[a-z0-9.\-]+[.][a-z]{2,4})>?')

# note: depending on the text this regex blocks in an infinite loop !
url_regex = re.compile(r'''(?i)\b((?:(hxxps?|https?|ftps?)://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?]))''', re.VERBOSE | re.MULTILINE)

# simple version for searching for URLs
url_regex_simple = re.compile(r'''(?i)\b((?:(hxxps?|https?|ftps?)://)[^ ]+)''', re.VERBOSE | re.MULTILINE)

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

  if not msg.is_multipart():
    # Treat text document attachments as belonging to the body of the mail.
    # Attachments with a file-extension of .htm/.html are implicitely treated
    # as text as well in order not to escape later checks (e.g. URL scan).
    if (not 'content-disposition' in msg and msg.get_content_maintype() == 'text') or\
       (msg.get_filename('').lower().endswith('.html') or msg.get_filename('').lower().endswith('.htm')):
      encoding = msg.get('content-transfer-encoding', '').lower()

      charset = msg.get_content_charset()
      if not charset:
        raw_body_str = msg.get_payload(decode=True)
      else:
        try:
          raw_body_str = msg.get_payload(decode=True).decode(charset, 'ignore')
        except:
          raw_body_str = msg.get_payload(decode=True).decode('ascii', 'ignore')

      raw_body.append((encoding, raw_body_str))
  else:
    for part in msg.get_payload():
      raw_body.extend(get_raw_body_text(part))

  return raw_body


def get_file_extension(filename):
  extension = ''
  dot_idx = filename.rfind('.')

  if dot_idx != -1:
    extension = filename[dot_idx + 1:]

  return extension


def get_file_hashes(data):
  hashalgo = ['md5', 'sha1', 'sha256', 'sha384', 'sha512']
  hashes = {}

  for k in hashalgo:
    ha = getattr(hashlib, k)
    h = ha()
    h.update(data)
    hashes[k] = h.hexdigest()

  return hashes


def traverse_multipart(msg, counter=0, include_attachment_data=False):
  attachments = {}

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
      attachments[file_id]['extension'] = extension
      attachments[file_id]['hashes'] = hashes

      if magic:
        attachments[file_id]['mime-type'] = magic.from_buffer(data, mime=True).decode('utf-8')
      else:
        attachments[file_id]['mime-type'] = 'undetermined'

      if include_attachment_data:
        attachments[file_id]['raw'] = base64.b64encode(data)

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


def parse_email(msg, include_raw_body=False, include_attachment_data=False):
  maila = {}
  header = {}

  # parse and decode subject
  subject = msg.get('subject', '')
  header['subject'] = decode_field(subject)

  # messageid
  header['message-id'] = msg.get('message-id', '')

  # parse and decode from
  # @TODO verify if this hack is necessary for other e-mail fields as well
  m = email_regex.search(msg.get('from', '').lower())
  if m:
    header['from'] = m.group(1)
  else:
    from_ = email.utils.parseaddr(msg.get('from', '').lower())
    header['from'] = from_[1]

  # parse and decode to
  to = email.utils.getaddresses(msg.get_all('to', []))
  header['to'] = []
  for m in to:
    if not m[1] == '':
      header['to'].append(m[1].lower())

  # parse and decode Cc
  cc = email.utils.getaddresses(msg.get_all('cc', []))
  header['cc'] = []
  for m in cc:
    if not m[1] == '':
      header['cc'].append(m[1].lower())

  # parse and decode Date
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
      date_ = dateutil.parser.parse('1970-01-01 00:00:00 +0000')

  if date_.tzname() is None:
    date_ = date_.replace(tzinfo=dateutil.tz.tzutc())

  header['date'] = date_

  # sender ip
  header['x-originating-ip'] = msg.get('x-originating-ip', '').strip('[]')

  # mail receiver path / parse any domain, e-mail
  # @TODO parse case where domain is specified but in parantheses only an IP
  header['received'] = []
  maila['received'] = []
  maila['received_emails'] = []
  maila['received_domains'] = []

  for l in msg.get_all('received'):
    l = re.sub(r'(\r|\n|\s|\t)+', ' ', l.lower())
    header['received'].append(l)

    # search for domains / e-mail addresses
    for m in domain_regex.findall(l):
      checks = True
      if '.' in m:
        try:
          test = int(re.sub(r'[.-]', '', m))

          if not ipv4_regex.match(m) or m == '127.0.0.1':
            checks = False
        except ValueError:
          pass

      if checks:
        maila['received_domains'].append(m)

    m = email_regex.findall(l)
    if m:
      maila['received_emails'] += m

    # ----------------------------------------------

    # try to parse received lines and normalize them
    try:
      f, b = l.split('by')
      b, undef = b.split('for')
    except:
      continue

    b_d = b_d_regex.search(b)
    f_d = f_d_regex.search(f)
    for_d = for_d_regex.search(l)

    if for_d:
      header['to'].append(for_d.group(1))
      header['to'] = list(set(header['to']))

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

      maila['received'].append([f, b])

  header['received'] = tuple(header['received'])
  maila['received_emails'] = list(set(maila['received_emails']))
  maila['received_domains'] = list(set(maila['received_domains']))

  # get raw header
  raw_body = get_raw_body_text(msg)
  if include_raw_body:
    maila['raw_body'] = raw_body
  else:
    maila['raw_body'] = []

  # parse any URLs found in the body
  list_observed_urls = []

  for body_tup in raw_body:
      encoding, body = body_tup

      if sys.version_info >= (3, 0) and (isinstance(body, bytes) or isinstance(body, bytearray)):
        body = body.decode('utf-8', 'ignore')

      for match in url_regex_simple.findall(body):
          found_url = match[0].replace('hxxp', 'http')
          found_url = urlparse(found_url).geturl()
          # let's try to be smart by stripping of noisy bogus parts
          found_url = re.split(r'''[\', ", \,, \), \}, \\]''', found_url)[0]

          if found_url not in list_observed_urls:
              list_observed_urls.append(found_url)

  maila['urls'] = list_observed_urls

  # parse attachments
  maila['attachments'] = traverse_multipart(msg, 0, include_attachment_data)

  for k, v in msg.items():
    if not k.lower() in header:
      if len(v) >= 2 and v[0] == '<' and v[-1] == '>':
        v = v[1:-1]

      header[k.lower()] = v

  maila['header'] = header

  return maila


def main():
  opts, args = getopt.getopt(sys.argv[1:], 'i:')
  msgfile = None

  for o, k in opts:
    if o == '-i':
      msgfile = k

  m = decode_email(msgfile)
  print m
  print
  print m['date'].isoformat()
  #print decode_email(msgfile, include_raw_body=True, include_attachment_data=True)


if __name__ == '__main__':
  main()
