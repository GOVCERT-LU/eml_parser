"""The policy which parses the header fields of a message, and the limits up to which they are parsed in structured form."""

import collections
import email.errors
import email.message
import email.policy
import functools
import logging
import typing

import regex

import eml_parser.constants
import eml_parser.decode
import eml_parser.regexes

logger = logging.getLogger(__name__)

# Header fields which contain e-mail addresses, they are parsed by the stdlib address parser.
_ADDRESS_HEADERS = frozenset(('sender', 'resent-sender', 'to', 'resent-to', 'cc', 'resent-cc', 'bcc', 'resent-bcc', 'from', 'resent-from', 'reply-to'))

# Header fields with MIME parameters, and the length up to which the stdlib parses them in reasonable time (about 20 ms),
# see `CustomPolicy.unparsed_header_value()`.
_MIME_PARAMETER_HEADERS = frozenset(('content-type', 'content-disposition'))
_MAX_PARAMETER_TEXT = 32 * 1024


class HeaderParsingLimitDefect(email.errors.HeaderDefect):
    """The message has more header fields or header bytes than are parsed in structured form, see `limit_header_parsing()`."""


class UnparsedHeaderValue(str):
    """A raw header value which is kept as it is instead of being run through the structured header parsers of the stdlib."""

    __slots__ = ()


class CustomPolicy(email.policy.EmailPolicy):
    """Custom parsing policy based on the default policy but relaxing some checks and early fixing invalid values."""

    email_regex: regex.Pattern[str] = eml_parser.regexes.email_no_force_tld_regex

    def __init__(self, email_regex: regex.Pattern[str] = eml_parser.regexes.email_no_force_tld_regex) -> None:
        """Constructor.

        Args:
            email_regex (regex.Pattern[str], optional): Pattern used to extract e-mail addresses from malformed headers.
        """
        # Policies are immutable; the stdlib accepts any declared class attribute as keyword. The typeshed stubs do not know ours.
        custom: dict[str, typing.Any] = {'email_regex': email_regex}
        super().__init__(max_line_length=0, refold_source='none', **custom)

    def header_fetch_parse(self, name: str, value: str) -> str:
        """Pass the name/value to the parent header_fetch_parse method for proper parsing, unless the value is too long to be parsed in reasonable time.

        Values beyond the header parsing limits of the message (`UnparsedHeaderValue`, see `limit_header_parsing()`) are not parsed either.
        """
        if isinstance(value, UnparsedHeaderValue):
            return self.unparsed_header_value(name, value)

        if len(value) <= eml_parser.constants.MAX_PARSED_HEADER_SIZE:
            return self.fetch_fixed_header(name, value)

        # The recursive descent parsers of the stdlib are quadratic in the length of a value, a megabyte of words takes seconds.
        logger.warning('Header field "%s" is %d characters long, it is not parsed.', name.lower(), len(value))
        return self.unparsed_header_value(name, value)

    @staticmethod
    def unparsed_header_value(name: str, value: str) -> str:
        """The raw value of a header field which is not run through the structured header parsers.

        The parameters of Content-Type and Content-Disposition are still parsed by the stdlib on every access (`get_param()`,
        `get_boundary()`, ...), quadratic in their number: 4 MB take minutes. Such values are cut after `_MAX_PARAMETER_TEXT`.
        """
        header = name.lower()
        if header == 'date':
            return eml_parser.decode.default_date

        raw = str(email.policy.compat32.header_fetch_parse(name, value))
        if header not in _MIME_PARAMETER_HEADERS or len(raw) <= _MAX_PARAMETER_TEXT:
            return raw

        logger.warning('Header field "%s" is %d characters long, only its first %d characters are used.', header, len(raw), _MAX_PARAMETER_TEXT)
        cut = raw.rfind(';', 0, _MAX_PARAMETER_TEXT)
        return raw[: cut if cut > 0 else _MAX_PARAMETER_TEXT]

    def fetch_fixed_header(self, name: str, value: str) -> str:
        """Early fix parsing issues and pass the name/value to the parent header_fetch_parse method for proper parsing.

        The stdlib parses a header again on every access (`get()`, `get_all()`, `items()`), which are several per header, so the results are cached in `_fetch_fixed_header`.
        The warning is logged here, once per access, because the cached method must stay pure and would otherwise only warn on the first occurrence of a value.
        """
        result, warning = self._fetch_fixed_header(name, value)

        if warning is not None:
            logger.warning(warning)

        return result

    @functools.lru_cache(maxsize=1024)  # noqa: B019 - the cache is bounded, so it keeps at most 1024 policies alive
    def _fetch_fixed_header(self, name: str, value: str) -> tuple[str, str | None]:
        """Cached pure variant of `fetch_fixed_header` which reports its warning as the second return value instead of logging it."""
        header = name.lower()

        if header == 'message-id' and '[' in value and not self.email_regex.match(value):
            # try workaround for bad message-id formats
            m = self.email_regex.search(value)
            if m is None:
                return '', 'Header field "message-id" is in an invalid format and cannot be fixed, it will be dropped.'

            value = f'<{m.group(1)}>'
        elif header == 'date':
            return self._fetch_date(name, value)
        elif header in _ADDRESS_HEADERS:
            try:
                return super().header_fetch_parse(name, value), None
            except RecursionError:
                # This can happen when the recursion gets too deep in the stdlib recursive descent parser.
                # In this case, the header is certainly pathological. We still try to extract some addresses.
                return ', '.join(self.email_regex.findall(value)), None

        try:
            return super().header_fetch_parse(name, value), None
        except (IndexError, ValueError):
            # The stdlib parsers fail on some malformed values, e.g. on a parameter `name*` without a value (IndexError) or with a
            # NUL in its RFC 2231 charset (ValueError) in Content-Type or Content-Disposition. This happens while the stdlib
            # parses the message, so the raw value is used instead.
            return self.unparsed_header_value(name, value), f'Header field "{header}" cannot be parsed, its raw value is used.'

    def _fetch_date(self, name: str, value: str) -> tuple[str, str | None]:
        """The date of a *Date* field in ISO format, see `_fetch_fixed_header()`."""
        try:
            value = super().header_fetch_parse(name, value)
        except TypeError as exc:
            return eml_parser.decode.default_date, f'Error parsing date: {exc!s}.'

        return eml_parser.decode.robust_string2date(value).isoformat(), None


def limit_header_parsing(msg: email.message.Message) -> None:
    """Keep the header fields beyond the parsing limits of a message with their raw value, without structured parsing.

    Defence in depth against messages made of huge numbers of header fields: the header fields of the message and of all its MIME parts are
    counted in order, and once `constants.MAX_PARSED_HEADER_FIELDS` fields or `constants.MAX_PARSED_HEADER_BYTES` bytes of values are reached,
    the remaining values are marked as `UnparsedHeaderValue`. They stay in the output as raw text, so no evidence is lost, but they cost no
    more than copying them. The first occurrence of each field in `constants.ALWAYS_PARSED_HEADERS` is parsed in every part regardless, so that
    junk fields in front of them cannot hide the sender, the subject or the MIME structure. A `HeaderParsingLimitDefect` is added to the
    defects of the message, as exceeding the limits is a strong sign of a crafted message.

    Args:
        msg (email.message.Message): The parsed message, modified in place.
    """
    fields = 0
    size = 0
    unparsed = 0
    parts = collections.deque([msg])

    # Iterative breadth first walk (the message's own fields first), Message.walk() recurses and fails on deeply nested parts.
    while parts:
        part = parts.popleft()

        if part.is_multipart():
            parts.extend(typing.cast('list[email.message.Message]', part.get_payload()))

        # The one use of a private attribute of the stdlib: Message has no public interface to replace a value in place. Deleting and
        # adding the fields again would reorder them, and each deletion scans all fields, which is quadratic in their number.
        headers: list[tuple[str, str]] = part._headers  # type: ignore[attr-defined]  # noqa: SLF001
        always_parsed = set(eml_parser.constants.ALWAYS_PARSED_HEADERS)

        for i, (name, value) in enumerate(headers):
            fields += 1
            if len(value) <= eml_parser.constants.MAX_PARSED_HEADER_SIZE:
                size += len(value)

            lower_name = name.lower()
            if lower_name in always_parsed:
                always_parsed.discard(lower_name)
            elif fields > eml_parser.constants.MAX_PARSED_HEADER_FIELDS or size > eml_parser.constants.MAX_PARSED_HEADER_BYTES:
                headers[i] = (name, UnparsedHeaderValue(value))
                unparsed += 1

    if unparsed:
        description = (
            f'{fields} header fields with {size} bytes of values exceed the parsing limits of '
            f'{eml_parser.constants.MAX_PARSED_HEADER_FIELDS} fields and {eml_parser.constants.MAX_PARSED_HEADER_BYTES} bytes, '
            f'{unparsed} values are kept unparsed'
        )
        logger.warning('%s.', description)
        msg.defects.append(HeaderParsingLimitDefect(description))
