"""Reading the header fields of a message, working around the values the stdlib parsers fail on."""

import collections.abc
import contextlib
import email.header
import email.headerregistry
import email.message
import email.policy
import email.utils
import logging
import typing

import regex

import eml_parser.decode
import eml_parser.regexes

logger = logging.getLogger(__name__)

# Bounds for the stdlib address parser, see `_is_cheap_for_address_parser()`: a group of 32 KiB takes at most about 0.2 s,
# 500 nested groups stay below the default recursion limit of 1 000.
_MAX_ADDRESS_PARSER_GROUP_TEXT = 32 * 1024
_MAX_ADDRESS_PARSER_COLONS = 500


class _RawPolicy(email.policy.Compat32):
    """Returns the header values as they are stored, see `raw_items()`."""

    def header_fetch_parse(self, name: str, value: str) -> str:
        """Return the stored value unchanged."""
        return value


_RAW_POLICY = _RawPolicy()


@contextlib.contextmanager
def using_policy(msg: email.message.Message, policy: email.policy.Policy) -> collections.abc.Iterator[email.message.Message]:
    """Temporarily read the header fields of a message with another policy, restored on exit, also if an exception is raised."""
    former_policy = msg.policy
    msg.policy = policy

    try:
        yield msg
    finally:
        msg.policy = former_policy


def raw_items(msg: email.message.Message) -> list[tuple[str, str]]:
    """Return the header fields of a message or MIME part as they are stored, without parsing their values.

    Args:
        msg (email.message.Message): An e-mail message object or MIME part.

    Returns:
        list: The (name, value) pairs of all header fields, in order.
    """
    with using_policy(msg, _RAW_POLICY):
        return msg.items()


def header_items(msg: email.message.Message) -> collections.abc.Sequence[tuple[str, str | email.header.Header]]:
    """Return the header fields of a message or MIME part, falling back to the compat32 policy if parsing a value fails.

    The stdlib address parser fails with an IndexError on some malformed values (e.g. `Cc: "`) and with an
    AttributeError or TypeError on 8-bit values (bug 27257). Values parsed with compat32 may be `email.header.Header` objects.

    Args:
        msg (email.message.Message): An e-mail message object or MIME part.

    Returns:
        list: The (name, value) pairs of all header fields, in order.
    """
    try:
        return msg.items()
    except (AttributeError, IndexError, TypeError, ValueError):
        logger.warning('Error parsing the header fields of a MIME part, falling back to the compat32 policy.')

    with using_policy(msg, email.policy.compat32):
        return msg.items()


def compat32_values(msg: email.message.Message, name: str) -> list[str | email.header.Header]:
    """Return the non-empty values of a header field parsed with the lenient compat32 policy, for values the default policy fails on.

    Args:
        msg (email.message.Message): An e-mail message object.
        name (str): The name of the header field.

    Returns:
        list: The values, as `email.header.Header` objects if they contain 8-bit bytes.
    """
    with using_policy(msg, email.policy.compat32):
        return [value for value in msg.get_all(name, []) if value != '']


def regex_addresses(msg: email.message.Message, name: str, email_regex: regex.Pattern[str]) -> list[str]:
    """Extract the e-mail addresses of a header field by regex, for values the stdlib address parser fails on (bug 27257).

    Args:
        msg (email.message.Message): An e-mail message object.
        name (str): The name of the header field.
        email_regex (regex.Pattern[str]): Pattern used to extract e-mail addresses.

    Returns:
        list: The addresses, unique per value, in order of appearance.
    """
    addresses: list[str] = []

    for value in compat32_values(msg, name):
        # compat32 returns values with 8-bit bytes as Header objects, the regex needs their decoded text
        text = eml_parser.decode.rfc2047_decode(value) if isinstance(value, email.header.Header) else value
        addresses.extend(dict.fromkeys(email_regex.findall(text)))

    return addresses


def _is_cheap_for_address_parser(text: str) -> bool:
    """Whether the stdlib address parser (`email.utils.getaddresses()`, `parseaddr()`) handles *text* in reasonable time.

    It is linear for lists of addresses, but quadratic in the number of members of a group (`team: a, b, ...;`, members
    need no commas) and recursive for each nested group, so a long group takes minutes and deep nesting raises
    RecursionError. A text without a colon has no group; otherwise its length bounds the members and its colons the nesting.
    """
    return ':' not in text or (len(text) <= _MAX_ADDRESS_PARSER_GROUP_TEXT and text.count(':') <= _MAX_ADDRESS_PARSER_COLONS)


def _getaddresses(values: list[str], email_regex: regex.Pattern[str]) -> list[tuple[str, str]]:
    """Return the (display name, address) pairs of header values like `email.utils.getaddresses()`.

    Values the stdlib address parser cannot handle in reasonable time (see `_is_cheap_for_address_parser()`) are searched
    for addresses by regex instead.
    """
    # The stdlib parses the values joined by ", ", which is what has to be cheap.
    if _is_cheap_for_address_parser(', '.join(values)):
        return email.utils.getaddresses(values)

    logger.warning('Address header field too complex for the address parser, extracting the addresses by regex.')
    pairs: list[tuple[str, str]] = []
    for value in values:
        pairs.extend(('', address) for address in email_regex.findall(value))

    return pairs


def _parse_address_value(name: str, value: str | email.header.Header, email_regex: regex.Pattern[str]) -> list[tuple[str, str]]:
    """Return the (display name, address) pairs of one raw value of an address header field, with the header class of the stdlib.

    The stdlib address/header parser can itself raise on certain malformed values (e.g. an unquoted display name ending in a bare
    period, such as "Test.<test@example.com>"). The exception type has varied across Python versions, in that case the
    addresses are extracted by regex.
    """
    text = eml_parser.decode.rfc2047_decode(value).replace('\n', '').replace('\r', '')
    parsing_result: dict[str, typing.Any] = {}
    header_class = typing.cast('email.headerregistry.AddressHeader', email.headerregistry.HeaderRegistry()[name])

    try:
        header_class.parse(text, parsing_result)
    except (AttributeError, IndexError, ValueError):
        logger.exception('Field value parsing error while parsing "%s", falling back to regex extraction!', text)
        return [('', address) for address in email_regex.findall(text)]

    pairs: list[tuple[str, str]] = []
    for group in parsing_result['groups']:
        pairs.extend((address.display_name, address.addr_spec) for address in group.addresses)

    return pairs


def addresses(msg: email.message.Message, name: str, email_regex: regex.Pattern[str], email_force_tld: bool) -> list[str]:
    """Return the e-mail addresses of a header field, lower-cased.

    Args:
        msg (email.message.Message): An e-mail message object.
        name (str): The name of the header field.
        email_regex (regex.Pattern[str]): Pattern used to extract e-mail addresses from values the stdlib cannot parse.
        email_force_tld (bool): Only report addresses with a top level domain.

    Returns:
        list: The addresses, in order.
    """
    try:
        pairs = _getaddresses(msg.get_all(name, []), email_regex)
    except (IndexError, AttributeError):
        pairs = email.utils.getaddresses(regex_addresses(msg, name, email_regex))
    except ValueError:
        pairs = []
        for value in compat32_values(msg, name):
            pairs.extend(_parse_address_value(name, value, email_regex))

    found = []

    for _, address in pairs:
        if address == '':
            continue

        if email_force_tld and not eml_parser.regexes.email_force_tld_regex.match(address):
            continue

        found.append(address.lower())

    return found


def sender(msg: email.message.Message, email_regex: regex.Pattern[str]) -> str | None:
    """Extract the address of the sender from the *From* header field, working around values the stdlib fails to parse.

    Args:
        msg (email.message.Message): The message, its *From* field is replaced if it cannot be parsed.
        email_regex (regex.Pattern[str]): Pattern used to extract e-mail addresses.

    Returns:
        str: The lower-cased address (or the raw value if it contains none), or None if the field is missing or empty.
    """
    try:
        field = str(msg.get('from', '')).lower()
    except (IndexError, AttributeError):
        # We have hit current open issue #27257
        # https://bugs.python.org/issue27257
        # The field is replaced by the first address found in it, or emptied, as a workaround.
        logger.exception('We hit bug 27257!')

        found = regex_addresses(msg, 'from', email_regex)
        first_address = found[0] if found else ''

        del msg['from']
        msg.add_header('from', first_address)
        field = first_address.lower()
    except ValueError:
        field = eml_parser.decode.rfc2047_decode(compat32_values(msg, 'from')[0]).lower()

    if field == '':
        return None

    # Values the stdlib address parser cannot handle in reasonable time are searched by regex only.
    if _is_cheap_for_address_parser(field):
        address = email.utils.parseaddr(field)

        if address != ('', ''):
            return address[1]

    if m := email_regex.search(field):
        return m.group(1)

    logger.warning('FROM header parsing failed.')
    return field


def _decoded_values(msg: email.message.Message, name: str, raw_fields: list[tuple[str, str]]) -> list[str]:
    """The non-empty decoded values of the fields of one name, see `fields()`."""
    decoded_values = []

    try:
        for raw_name, raw_value in raw_fields:
            value = msg.policy.header_fetch_parse(raw_name, raw_value)
            if value:
                decoded_values.append(value)
    except (IndexError, AttributeError, TypeError):
        # We have hit a field value parsing error.
        # Try to work around this by using a relaxed policy, if possible.
        # Parsing might not give meaningful results in this case!
        logger.error('Field value parsing error, trying to work around this!')
        # compat32 returns values with 8-bit bytes as Header objects, which are no JSON values
        return [str(value) for value in compat32_values(msg, name)]
    except ValueError:
        # extract values using a relaxed policy, after the ones decoded so far
        for compat32_value in compat32_values(msg, name):
            text = str(compat32_value)
            # check if this is a RFC2047 encoded field
            if eml_parser.regexes.email_regex_rfc2047.search(text):
                decoded_values.append(eml_parser.decode.rfc2047_decode(text))
            else:
                logger.error('Field value parsing error, trying to work around this! - %s', text)

    return decoded_values


def fields(msg: email.message.Message) -> dict[str, list[str]]:
    """Collect the decoded values of all header fields of a message, working around values the stdlib fails to parse.

    Args:
        msg (email.message.Message): The message.

    Returns:
        dict: The non-empty values per lower-cased field name, the names in the order of their first occurrence.
    """
    # Group the raw header fields by lower-cased name in a single pass over the header list. Grouping case-insensitively keeps names
    # differing only in case (e.g. "X-Foo" and "x-foo") in one entry, and a stable order keeps the output independent of PYTHONHASHSEED.
    # Do not call get_all() per name here: each call scans the whole header list, which makes collection
    # quadratic in the number of header fields and lets a message with many small fields stall the parser.
    raw_fields_by_name: dict[str, list[tuple[str, str]]] = {}
    for raw_name, raw_value in raw_items(msg):
        raw_fields_by_name.setdefault(raw_name.lower(), []).append((raw_name, raw_value))

    header: dict[str, list[str]] = {}
    for name, raw_fields in raw_fields_by_name.items():
        if decoded_values := _decoded_values(msg, name, raw_fields):
            header[name] = decoded_values

    return header


def defects(msg: email.message.Message) -> list[str]:
    """The problems the stdlib found while parsing a message: the class name of each defect, with its description if it has one.

    Args:
        msg (email.message.Message): The message.

    Returns:
        list: The defects, in order.
    """
    found = []

    for defect in msg.defects:
        # str() of most stdlib defects is empty, the class name identifies the problem.
        defect_name = type(defect).__name__
        found.append(f'{defect_name}: {defect}' if str(defect) else defect_name)

    return found


def authentication_results(header: dict[str, list[str]]) -> dict[str, list[str]]:
    """Extract the results of the e-mail authentication methods (SPF, DKIM, DMARC, ARC, ...) reported by the receiving servers.

    The headers *Authentication-Results* (RFC 8601) and *Received-SPF* (RFC 7208) are evaluated. Comments are ignored and
    so are properties like `header.d=` of a method. Note that these headers are only meaningful if they were added by
    a server you trust; a sender can forge them, and mail from outside of your infrastructure may carry anything.

    Args:
        header: The parsed headers (lower-cased names, list of values).

    Returns:
        dict: The results per method, in the order of occurrence, e.g. `{'spf': ['pass'], 'dkim': ['pass', 'fail']}`.
    """
    results: dict[str, list[str]] = {}

    for value in header.get('authentication-results', []):
        without_comments = eml_parser.decode.noparenthesis(str(value), ' ')
        for method, result in eml_parser.regexes.authentication_result_regex.findall(without_comments):
            results.setdefault(method.lower(), []).append(result.lower())

    for value in header.get('received-spf', []):
        spf_result = eml_parser.regexes.received_spf_regex.match(str(value))
        if spf_result:
            results.setdefault('spf', []).append(spf_result.group(1).lower())

    return results
