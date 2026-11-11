"""This module contains various string import, check and parse methods."""

import datetime as dt
import decimal
import email
import email.errors
import email.header
import email.utils
import html
import json
import logging
import typing

import charset_normalizer
import dateutil.parser
import regex

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
DEFAULT_DATE = dt.datetime.fromisoformat(default_date)
_DATEUTIL_DEFAULT = dt.datetime(1970, 1, 1)  # noqa: DTZ001
_LONE_SURROGATE_REGEX = regex.compile('[\ud800-\udfff]')

# The charset detection is slow, bodies larger than this are decoded with the declared charset only, even if that is wrong.
MAX_CHARSET_DETECTION_SIZE = 256 * 1024


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
        _decoded = decode_header(field)
    except email.errors.HeaderParseError:
        return field

    decoded_parts = []

    for text, charset in _decoded:
        if isinstance(text, str):
            decoded_parts.append(text)
        elif charset:
            decoded_parts.append(decode_string(text, charset))
        else:
            # @TODO might be an idea to check with charset-normalizer here
            decoded_parts.append(text.decode('utf-8', 'replace'))

    return ''.join(decoded_parts)


def decode_body(data: bytes, charset: str | None) -> str:
    """Decode a text body without dropping undecodable bytes.

    Dropping bytes (the *ignore* error handler) glues the neighbouring characters together and can create indicators which are not in the message,
    e.g. `http://good<invalid byte>.evil.com` would become `http://good.evil.com`. Keeping the replacement character U+FFFD would make it part of
    URLs and e-mail addresses instead. Undecodable bytes are therefore replaced with a space, i.e. they act as a separator between indicators.

    Args:
        data (bytes): The body.
        charset (str, optional): The charset declared in the Content-Type header. If it is missing or unknown, or if decoding with it
            loses bytes, the encoding is detected.

    Returns:
        str: The decoded body.
    """
    if charset:
        try:
            text = _redetect_if_damaged(data, data.decode(charset, 'replace'))
        except (LookupError, ValueError):
            logger.debug('Unknown charset "%s", trying to detect the encoding', charset, exc_info=True)
            text = decode_string(data)
    else:
        text = decode_string(data)

    # Some codecs (e.g. UTF-7, unicode_escape) decode to lone surrogates, which are no text either and cannot be encoded again.
    return _LONE_SURROGATE_REGEX.sub(' ', text.replace('\ufffd', ' '))


def _redetect_if_damaged(data: bytes, text: str) -> str:
    """Return the detected decoding of data instead of text, if text lost bytes (U+FFFD) because the declared charset is wrong.

    Declared charsets are often wrong (e.g. *us-ascii* for UTF-8 text). The detection is slow, so it is only run if needed and not for huge bodies.
    """
    damage = text.count('\ufffd')

    if not damage or len(data) > MAX_CHARSET_DETECTION_SIZE:
        return text

    detected = decode_string(data)

    return detected if detected.count('\ufffd') < damage else text


def decode_string(string: bytes, encoding: str | None = None) -> str:
    """Try anything possible to parse an encoded bytes string and return the result.

    We do this using the encoding hint, if this fails, we try to detect the correct
    encoding using the charset-normalizer module, if that failed we try utf-8 and as a
    last resort latin-1, which can decode any byte sequence and thereby always preserves
    the ASCII parts of the input.
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
            logger.debug('Unable to decode with the provided encoding hint "%s"', encoding, exc_info=True)

    best_match = charset_normalizer.from_bytes(string).best()

    if best_match is not None:
        return str(best_match)

    try:
        return string.decode('utf-8')
    except UnicodeDecodeError:
        logger.debug('Unable to detect the encoding, falling back to latin-1', exc_info=True)

    return string.decode('latin-1')


def normalize_attribute_url(value: str) -> str:
    """Normalise the value of an HTML attribute containing an URL the way a browser does before using it.

    Character references are resolved, tabs and line feeds (which browsers drop from URLs anywhere) are removed and backslashes
    after the scheme are treated as slashes, so an obfuscated `ht&#9;tp:` followed by backslashes becomes a plain `http://` URL.

    Args:
        value (str): The raw attribute value, possibly with the opening quote.

    Returns:
        str: The normalised value.
    """
    if '&' in value:
        value = html.unescape(value)

    value = value.translate(eml_parser.regexes.url_drop_chars_table)

    if eml_parser.regexes.url_backslash_scheme_regex.match(value):
        # Backslashes are treated like slashes up to the query string or fragment.
        end = min((pos for pos in (value.find('?'), value.find('#')) if pos != -1), default=len(value))
        value = value[:end].replace('\\', '/') + value[end:]

    return value


def robust_string2date(line: str) -> dt.datetime:
    """Parses a date string to a datetime.datetime object using different methods.

    It is guaranteed to always return a valid datetime.datetime object.
    If first tries the built-in email module method for parsing the date according
    to related RFC's.
    If this fails, dateutil is tried (missing parts of the date are taken from 1970-01-01 and not from the current date).
    If that fails as well, a datetime.datetime
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
        return DEFAULT_DATE

    try:
        date_ = email.utils.parsedate_to_datetime(line)
    except (TypeError, ValueError, LookupError):
        logger.debug('Exception parsing date "%s"', line, exc_info=True)

        try:
            # dateutil takes missing parts (e.g. the year) from the current date by default, which would make the
            # result depend on the time of the analysis. Use a fixed default instead.
            date_ = dateutil.parser.parse(line, default=_DATEUTIL_DEFAULT)
        except (AttributeError, ValueError, OverflowError, decimal.InvalidOperation):
            # Now we are facing an invalid date.
            return DEFAULT_DATE

    if date_.utcoffset() is None:
        return date_.replace(tzinfo=dt.UTC)

    return date_


def json_serial(obj: object) -> str:
    """JSON serializer for objects not serializable by default json code.

    Supported are datetime objects (exported as ISO 8601 strings, converted to UTC if timezone aware and possible) and
    ASCII bytes objects, i.e. the base64 encoded attachment data added by the *include_attachment_data* option.

    Args:
        obj: The object to serialize.

    Returns:
        str: The string representation of the object.

    Raises:
        TypeError: If the type of the object is not supported.
        UnicodeDecodeError: If a bytes object is not ASCII, i.e. not base64.
    """
    if isinstance(obj, dt.datetime):
        if obj.tzinfo is not None:
            try:
                return obj.astimezone(dt.UTC).isoformat()
            except OverflowError:
                # Dates close to datetime.min/max (e.g. 9999-12-31 23:59:59 -0500) can not be converted to UTC.
                logger.debug('Unable to convert "%s" to UTC, exporting it with its original offset', obj, exc_info=True)

        return obj.isoformat()

    if isinstance(obj, bytes):
        return obj.decode('ascii')

    raise TypeError(f'Type not serializable - {str(type(obj))}')


def export_to_json(parsed_msg: dict[str, typing.Any], sort_keys: bool = False) -> str:
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


def rfc2047_decode(value: str | email.header.Header) -> str:
    """Use the standard library decode_header function for decoding RFC2047 encoded values.

    Args:
        value: The value to be decoded, a compat32 `email.header.Header` object for values with 8-bit bytes.

    Returns:
        str: Decoded string, or the value as is if an encoded word cannot be decoded (e.g. invalid base64).
    """
    if not value:
        return ''

    try:
        fragments = decode_header(value)
    except email.errors.HeaderParseError:
        logger.warning('RFC2047 encoded word cannot be decoded, keeping the value as is: %r', value)
        return str(value)

    return ''.join(_decode_rfc2047_fragment(fragment, charset) for fragment, charset in fragments)


def _decode_rfc2047_fragment(fragment: str | bytes, charset: str | None) -> str:
    """Decode one fragment returned by `decode_header()`, see `rfc2047_decode()`."""
    if isinstance(fragment, str):
        # decode_header returns str (not bytes) for fragments which did not
        # need RFC2047 decoding, e.g. when the whole value is plain ASCII.
        return fragment

    if charset is None:
        return fragment.decode('ascii', errors='replace')

    try:
        return fragment.decode(charset, errors='replace')
    except LookupError:
        # Unknown charset name, e.g. "=?foo-bar?q?x?=". Never fail on attacker controlled input.
        logger.debug('Unknown charset "%s" in RFC2047 encoded word, trying to detect the encoding', charset, exc_info=True)
        return decode_string(fragment)


class _NextOccurrence:
    """The next occurrence of a substring at or after a position, for positions which never decrease: each part of the text is searched once."""

    def __init__(self, text: str, substring: str) -> None:
        self._text = text
        self._substring = substring
        self._found = text.find(substring)

    def at_or_after(self, position: int) -> int:
        """Position of the next occurrence at or after *position* (not before the previous query), or -1."""
        if self._found != -1 and self._found < position:
            self._found = self._text.find(self._substring, position)

        return self._found


def _split_encoded_words(text: str) -> list[str]:
    """Split a text at its RFC 2047 encoded words like `email.header.ecre.split()`, in linear time.

    The result is the text in front of the first encoded word, then charset, encoding, encoded text and the text up to the next
    encoded word for each. An encoded word is `=?charset?encoding?encoded?=`: the charset runs up to the first "?" (it may contain
    a line feed), the encoding is one of "qQbB", and the encoded text runs up to the first "?=" before the next line feed. The
    regular expression of the stdlib finds the same words, but it searches to the end of the line from every "=?" without a
    closing "?=", which is quadratic in their number.
    """
    parts: list[str] = []
    closings = _NextOccurrence(text, '?=')
    line_feeds = _NextOccurrence(text, '\n')
    text_start = 0
    start = text.find('=?')

    while start != -1:
        charset_end = text.find('?', start + 2)
        if charset_end == -1:
            break

        closing = closings.at_or_after(charset_end + 3)
        line_feed = line_feeds.at_or_after(charset_end + 3)
        is_word = text[charset_end + 1 : charset_end + 2] in ('q', 'Q', 'b', 'B') and text[charset_end + 2 : charset_end + 3] == '?'

        if not is_word or closing == -1 or line_feed != -1 and line_feed < closing:
            # A word starting later has its charset end no earlier, so the positions asked from closings and line_feeds never decrease.
            start = text.find('=?', start + 1)
            continue

        parts.extend((text[text_start:start], text[start + 2 : charset_end], text[charset_end + 1], text[charset_end + 3 : closing]))
        text_start = closing + 2
        start = text.find('=?', text_start)

    parts.append(text[text_start:])
    return parts


def decode_header(value: str | email.header.Header) -> list[tuple[bytes | str, str | None]]:
    """Split a header value into its encoded words and the text between them, like `email.header.decode_header()`, in linear time.

    The stdlib function is quadratic in the number of encoded words (it removes the parts from the front of a list and
    concatenates the bytes of consecutive words one at a time), so a megabyte of encoded words in a subject takes minutes.
    This is the same algorithm with the same result; each encoded word is still decoded by the stdlib function.

    Args:
        value: The header value, or a compat32 `email.header.Header` object.

    Returns:
        list: The (text, charset) pairs, see `email.header.decode_header()`.

    Raises:
        email.errors.HeaderParseError: If an encoded word cannot be decoded, e.g. invalid base64.
    """
    if isinstance(value, email.header.Header):
        return email.header.decode_header(value)

    if len(_split_encoded_words(value)) == 1:
        return [(value, None)]

    # (text, encoding, charset) per word, unencoded text with None as encoding and charset
    words: list[tuple[str, str | None, str | None]] = []
    for line in value.splitlines():
        parts = _split_encoded_words(line)
        for index in range(0, len(parts), 4):
            unencoded = parts[index].lstrip() if index == 0 else parts[index]
            if unencoded:
                words.append((unencoded, None, None))
            if index + 1 < len(parts):
                words.append((parts[index + 3], parts[index + 2].lower(), parts[index + 1].lower()))

    # White space between two encoded words is dropped.
    kept_words = []
    for index, word in enumerate(words):
        between_encoded_words = 0 < index < len(words) - 1 and words[index - 1][1] and words[index + 1][1]
        if not (between_encoded_words and word[0].isspace()):
            kept_words.append(word)

    # Consecutive words of the same charset are joined, the unencoded ones with a space.
    runs: list[tuple[str | None, list[bytes]]] = []
    for text, encoding, charset in kept_words:
        if encoding is None:
            data = bytes(text, 'raw-unicode-escape')
        else:
            data = typing.cast('bytes', email.header.decode_header(f'=?{charset}?{encoding}?{text}?=')[0][0])

        if runs and runs[-1][0] == charset:
            runs[-1][1].append(data)
        else:
            runs.append((charset, [data]))

    return [((b' ' if charset is None else b'').join(chunks), charset) for charset, chunks in runs]


def noparenthesis(line: str, replacement: str = '') -> str:
    """Remove nested parentheses, until no pairs of matching parentyheses are present.

    Args:
        line (str): Input text to search in for parentheses.
        replacement (str): Inserted in place of every removed pair, e.g. a space so that the text around it is not glued together.

    Returns:
        str: Return a string with all text in matching parentheses removed. For example,
        noparenthesis('a((b)c(d') == 'a(c(d'
    """
    fragments: list[list[str]] = [[]]
    for ch in line:
        if ch == '(':
            fragments.append([ch])
        else:
            fragments[-1].append(ch)
        if ch == ')' and len(fragments) > 1:
            fragments.pop()
            fragments[-1].append(replacement)
    return ''.join(ch for w in fragments for ch in w)
