# -*- coding: utf-8 -*-
# pylint: disable=line-too-long

from __future__ import absolute_import, division, print_function, unicode_literals

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
import email
import re
import base64
import quopri

try:
    try:
        import cchardet as chardet
    except ImportError:
        import chardet
except ImportError:
    chardet = None


# encoded string =?<encoding>?[QB]?<string>?=
re_quoted_string = re.compile(r'''(                               # Group around entire regex to include it in matches
                                   \=\?[^?]+\?([QB])\?[^?]+?\?\=  # Quoted String with subgroup for encoding method
                                   |                              # or
                                   .+?(?=\=\?|$)                  # Plain String
                                  )''', (re.X | re.M | re.I))

re_q_value = re.compile(r'\=\?(.+)?\?[Qq]\?(.+)?\?\=')
re_b_value = re.compile(r'\=\?(.+)?\?[Bb]\?(.+)?\?\=')


def ascii_decode(string):
    """Ascii Decode a given string; useful with dirty headers.

    Args:
      string (str): The string to be converted.

    Returns:
      str: Returns the decoded string.
    """
    # pylint: disable=no-else-return

    if sys.version_info >= (3, 0) and isinstance(string, email.header.Header):
        return str(string)

    try:
        if sys.version_info >= (3, 0):
            return string.decode('latin-1')
        else:
            return string.decode('latin-1').encode('utf-8')
    except Exception:
        if sys.version_info >= (3, 0):
            return string
        else:
            return string.encode('utf-8', 'replace')


def force_string_decode(string):
    """Force the decoding of a string.
    It tries latin1 then utf-8, it stop of first win
    It also convert None to empty string

    #TODO this function should be merged with decode_field in order to simpilfy

    Args:
        string(str): Encoded string
    Returns
        str: Decoded string
    """
    if sys.version_info >= (3, 0) and isinstance(string, str):
        return string

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
     field and return it, else return a specified default value.

     Args:
        field (str): String to decode

     Returns
        str: Clean encoded strings
     """

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
        d_string = base64.b64decode(e_string).decode(encoding, 'ignore')
    else:
        d_string = e_string.decode('utf-8', 'ignore')

    return d_string


def splitonqp(string):
    """Split a line on "=?" and "?=" and return an list for quoted style strings

    Args:
        string(str): String to split
    Returns
        list: list of strings splitted by quoted space
    """
    start = 0
    pointer = 0
    outstr = []
    delims = ["=?", "?="]
    toggle = 0
    delim = delims[toggle]
    for pointer in range(len(string) - 1):
        if (pointer + 2) > (len(string) - 1):
            # bounds check
            break

        if string[pointer:pointer + 2] == delim:
            toggle = (toggle + 1) % 2  # Switch betwen separators
            delim = delims[toggle]
            pointer += 2
            if (string[start - 2:start] == "=?") and (string[pointer - 2:pointer] == "?="):
                # Borne par quoted print headers
                outstr.append(string[start - 2:pointer])
            else:
                outstr.append(string[start:pointer - 2])
            start = pointer

    if start != pointer:
        outstr.append(string[start:len(string)])
    return outstr


def decode_value(string):
    """Decodes a given string as Base64 or Quoted Printable, depending on what
    type it is.     String has to be of the format =?<encoding>?[QB]?<string>?=

    Args:
        string(str): Line to decode , mais contains multiple quoted printable
    Returns
        str: Decode string
    """
    # Optimization: If there's no encoded-words in the string, just return it
    if "=?" not in string:
        return string

    # First, remove any CRLF, CR
    input_str = string.replace('\r', '').replace('\n', '')
    string_ = ""
    for subset in splitonqp(input_str):
        if '=?' in subset:
            # Search for occurences of quoted strings or plain strings
            for m in re_quoted_string.finditer(subset):
                match_s, method = m.groups()
                if '=?' in match_s:
                    if not method:
                        # if the encoding is not q or b we just drop the line as is
                        # Bad encoding not q or b... just drop the line as is
                        continue
                    elif method.lower() == 'q':
                        subset = q_value_decode(match_s)
                        subset = subset.replace('_', ' ')
                    elif method.lower() == 'b':
                        subset = b_value_decode(match_s)
                        subset = subset.replace('_', ' ')
        string_ += subset
    return string_
