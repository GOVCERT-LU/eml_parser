"""This module contains various string import, check and parse methods."""

import datetime
import email
import email.errors
import email.header
import email.policy
import email.utils
import json
import logging
import typing

import charset_normalizer
import dateutil.parser

import eml_parser.regexes

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

default_date = '1970-01-01T00:00:00+00:00'


def decode_field(field: str) -> str:
    """Try to get the specified field using the Header module.

    If there is also an associated encoding, try to decode the
    field and return it, else return a specified default value.

    Args:
        field (str): String to decode

    Returns:
        str: Clean encoded strings
    """
    try:
        _decoded = email.header.decode_header(field)
    except email.errors.HeaderParseError:
        return field

    string = ''

    for _text, charset in _decoded:
        if charset:
            string += decode_string(_text, charset)
        elif isinstance(_text, bytes):
            # @TODO might be an idea to check with charset-normalizer here
            string += _text.decode('utf-8', 'ignore')
        else:
            string += _text

    return string


def decode_string(string: bytes, encoding: typing.Optional[str] = None) -> str:
    """Try anything possible to parse an encoded bytes string and return the result.

    We do this using the encoding hint, if this fails, we try to detect the correct
    encoding using the charset-normalizer module, if that failed we try latin-1, utf-8 and
    as a last resort ascii.
    In any case we always return something.

    Args:
        string (bytes): The bytes string to be decoded.
        encoding (str, optional): An optional encoding hint.

    Returns:
        str: A decoded form of the string.
    """
    if string == b'':
        return ''

    if encoding is not None:
        try:
            return string.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            pass

    value = str(charset_normalizer.from_bytes(string).best())

    if value is None:
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


def workaround_bug_27257(msg: email.message.Message, header: str) -> list[str]:
    """Function to work around bug 27257 and just tries its best using the compat32 policy to extract any meaningful information, i.e. e-mail addresses.

    Args:
        msg (email.message.Message): An e-mail message object.
        header (str): The header field to decode.

    Returns:
        list: Returns a list of strings which represent e-mail addresses.
    """
    return_value: list[str] = []

    for value in workaround_field_value_parsing_errors(msg, header):
        if value != '':
            m = eml_parser.regexes.email_regex.findall(value)
            if m:
                return_value += list(set(m))

    return return_value


def workaround_field_value_parsing_errors(msg: email.message.Message, header: str) -> list[str]:
    """Function to work around field value parsing errors by trying a best effort parsing using the compat32 policy to extract any meaningful information.

    Args:
        msg (email.message.Message): An e-mail message object.
        header (str): The header field to decode.

    Returns:
        list: Return an extracted list of strings.
    """
    if msg.policy == email.policy.compat32:
        new_policy = None
    else:
        new_policy = msg.policy

    msg.policy = email.policy.compat32
    return_value = []

    for value in msg.get_all(header, []):
        if value != '':
            return_value.append(value)

    if new_policy is not None:
        msg.policy = new_policy

    return return_value


def robust_string2date(line: str) -> datetime.datetime:
    """Parses a date string to a datetime.datetime object using different methods.

    It is guaranteed to always return a valid datetime.datetime object.
    If first tries the built-in email module method for parsing the date according
    to related RFC's.
    If this fails it returns, dateutil is tried. If that fails as well, a datetime.datetime
    object representing "1970-01-01 00:00:00 +0000" is returned.
    In case there is no timezone information in the parsed date, we set it to UTC.

    Args:
        line (str): A string which should be parsed.

    Returns:
        datetime.datetime: Returns a datetime.datetime object.
    """
    # "." -> ":" replacement is for fixing bad clients (e.g. outlook express)

    # if the input is empty, we return a default date
    if line == '':
        return datetime.datetime.fromisoformat(default_date)

    try:
        date_ = email.utils.parsedate_to_datetime(line)
    except (TypeError, ValueError, LookupError):
        logger.debug('Exception parsing date "%s"', line, exc_info=True)

        try:
            date_ = dateutil.parser.parse(line)
        except (AttributeError, ValueError, OverflowError):
            # Now we are facing an invalid date.
            return datetime.datetime.fromisoformat(default_date)

    if date_.tzname() is None:
        return date_.replace(tzinfo=datetime.timezone.utc)

    return date_


def json_serial(obj: typing.Any) -> typing.Optional[str]:
    """JSON serializer for objects not serializable by default json code."""
    if isinstance(obj, datetime.datetime):
        if obj.tzinfo is not None:
            serial = obj.astimezone(datetime.timezone.utc).isoformat()
        else:
            serial = obj.isoformat()

        return serial

    raise TypeError(f'Type not serializable - {str(type(obj))}')


def export_to_json(parsed_msg: dict, sort_keys: bool = False) -> str:
    """Function to convert a parsed e-mail dict to a JSON string.

    Args:
        parsed_msg (dict): The parsed e-mail dict which is the result of
                           one of the decode_email functions.
        sort_keys (bool, optional): If True, sorts the keys in the JSON output.
                                    Default: False.

    Returns:
        str: Returns the JSON string.
    """
    return json.dumps(parsed_msg, default=json_serial, sort_keys=sort_keys, indent=2)


def rfc2047_decode(value: str) -> str:
    """Use the standard library decode_header function for decoding RFC2047 encoded values.

    Args:
        value: The value to be decoded

    Returns:
        str: Decoded string
    """
    if not value:
        return value

    parsed = ''

    for k, v in email.header.decode_header(value):
        if v is None:
            parsed += k.decode('ascii', errors='ignore')

        else:
            parsed += k.decode(v, errors='replace')

    return parsed
