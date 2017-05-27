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
import typing

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


def force_string_decode(string: str) -> str:
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

    raise Exception('force_string_decode no string!?!')

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


def decode_field(field: str) -> str:
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
        _decoded = email.header.decode_header(field)
    except email.errors.HeaderParseError:
        raise Exception('email.errors.HeaderParseError')
        return field

    string = ''

    for _text, charset in _decoded:
        if charset:
            string += decode_string(_text, charset)
        else:
            # @TODO might be an idea to check with chardet here
            if isinstance(_text, bytes):
                string += _text.decode('utf-8', 'ignore')
            else:
                string += _text

    return string


def decode_string(string: bytes, encoding: typing.Optional[str]) -> str:
    if string == b'':
        return ''

    if encoding is not None:
        try:
            return string.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            pass

    if chardet:
        enc = chardet.detect(string)
        if not (enc['confidence'] == 1 and enc['encoding'] == 'ascii'):
            value = string.decode(enc['encoding'], 'replace')
        else:
            value = string.decode('ascii', 'replace')
    else:
        text = ''

        for e in ('latin1', 'utf-8'):
            try:
                text = string.decode(e)
            except UnicodeDecodeError:
                pass
            else:
                break

        if text == '':
            value = string.decode('ascii', 'ignore')
        else:
            value = text

    return value
