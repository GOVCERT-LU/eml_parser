"""The MIME structure of a message: finding its start, repairing and walking its parts, and reading the text parts."""

import binascii
import collections.abc
import email
import email.header
import email.message
import email.policy
import logging
import typing

import eml_parser.constants
import eml_parser.decode
import eml_parser.headers
import eml_parser.regexes

logger = logging.getLogger(__name__)

# The content transfer encodings `Message.get_payload(decode=True)` decodes, it returns the payload of others as it is.
_DECODED_TRANSFER_ENCODINGS = frozenset(('quoted-printable', 'base64', 'x-uuencode', 'uuencode', 'uue', 'x-uue'))


class BodyPart(typing.NamedTuple):
    """A text part of the e-mail, see `text_parts()`."""

    encoding: str  # content transfer encoding, lower-cased
    text: str  # the decoded text
    headers: collections.abc.Sequence[tuple[str, str | email.header.Header]]  # the header fields of the part
    boundary: str | None  # boundary of the enclosing multipart, if any


def find_header_start(data: bytes) -> int:
    """Find the first line which looks like a header field.

    Plain bytes operations are used on purpose: this is much faster than a regular expression on large inputs
    and every line is looked at only once.

    Args:
        data: Raw e-mail, possibly with garbage in front of the headers.

    Returns:
        Offset of the first line starting with a valid field name followed by a colon, or 0 if there is none.
    """
    pos = 0

    while (colon := data.find(b':', pos)) != -1:
        line_start = max(pos, data.rfind(b'\n', pos, colon) + 1)
        field_name = data[line_start:colon].rstrip(b' \t')

        if field_name and not field_name.translate(None, eml_parser.constants.FIELD_NAME_BYTES):
            return line_start

        line_end = data.find(b'\n', colon)

        if line_end == -1:
            break

        pos = line_end + 1

    return 0


def payload_text(part: email.message.Message) -> list[email.message.Message] | str:
    """Return the payload of a part like `part.get_payload()`, also if its declared charset fails.

    For 8-bit text the stdlib decodes the payload with the declared charset and falls back to ASCII only for unknown charset
    names; others raise, e.g. "idna" (which supports no error handler). These are decoded as ASCII as well, after the
    content transfer encoding (the stdlib offers the undecoded bytes only that way).

    Args:
        part (email.message.Message): The part.

    Returns:
        The list of sub-parts of a multipart part, otherwise the text.
    """
    try:
        return typing.cast('list[email.message.Message] | str', part.get_payload())
    except ValueError:
        logger.warning('Payload cannot be decoded with its charset "%s", decoding it as ASCII.', part.get_content_charset())

    return typing.cast('bytes', part.get_payload(decode=True)).decode('ascii', 'replace')


def _stored_payload(part: email.message.Message) -> str:
    """Return the payload of a part as the stdlib parser stores it: text with 8-bit bytes surrogate escaped.

    `get_payload()` decodes 8-bit bytes with the charset declared by the part. For a multipart part which the stdlib could not
    split, that is the wrong charset for all its sub-parts, and without one the bytes are lost. The bytes are taken as they are
    instead, which `get_payload(decode=True)` returns unless it decodes the content transfer encoding; then the decoded text is
    encoded as UTF-8.
    """
    if str(part.get('content-transfer-encoding', '')).lower() in _DECODED_TRANSFER_ENCODINGS:
        data = typing.cast('str', payload_text(part)).encode('utf-8', 'surrogateescape')
    else:
        data = typing.cast('bytes', part.get_payload(decode=True))

    return data.decode('ascii', 'surrogateescape')


def filename(part: email.message.Message) -> str:
    """Return the file name of a part, or an empty string if it has none or it cannot be decoded.

    The stdlib fails on some malformed parameters, e.g. with a ValueError on an RFC 2231 value with a NUL in its charset.
    """
    try:
        return part.get_filename('')
    except (binascii.Error, AssertionError, ValueError):
        logger.exception('Exception occurred while trying to parse the content-disposition header. Collected data will not be complete.')

    return ''


def iter_parts(msg: email.message.Message, recursion_limit: int) -> collections.abc.Iterator[tuple[email.message.Message, str | None]]:
    """Walk a message and all its MIME parts depth first, each part before its sub-parts.

    The walk is iterative, so the nesting depth is limited by *recursion_limit* only and not by the Python stack.

    Args:
        msg (email.message.Message): The message.
        recursion_limit: Maximum nesting depth of the parts.

    Yields:
        tuple: The part and the boundary of the multipart which encloses it (None for the message itself).

    Raises:
        RecursionError: If the parts are nested deeper than *recursion_limit*.
    """
    stack: list[tuple[email.message.Message, str | None, int]] = [(msg, None, 0)]

    while stack:
        part, boundary, depth = stack.pop()

        if depth > recursion_limit:
            logger.warning('multi-part nesting limit (%d) exceeded, aborting', recursion_limit)
            raise RecursionError('Recursion limit exceeded')

        yield part, boundary

        if not part.is_multipart():
            continue

        part_boundary = part.get_boundary(failobj=None)
        sub_parts = typing.cast('list[email.message.Message]', part.get_payload())

        # Pushed in reverse, so that the first sub-part is walked next.
        for sub_part in reversed(sub_parts):
            stack.append((sub_part, part_boundary, depth + 1))


def _guess_boundary(payload: str, declared: str | None) -> str | None:
    """Find the boundary of a multipart payload: the declared one if it occurs, else the first line which looks like a delimiter (`--something`)."""
    if declared and f'--{declared}' in payload:
        return declared

    for match in eml_parser.regexes.multipart_boundary_guess_regex.finditer(payload):
        if not match.group(1).endswith('--'):
            return match.group(1)

    return None


def _split_multipart(part: email.message.Message, payload: str, policy: email.policy.Policy) -> bool:
    """Split the payload of a multipart part which the stdlib left as one string, see `repair_multipart()`.

    Returns:
        bool: Whether the part was split. If not, it is turned into a text part.
    """
    boundary = _guess_boundary(payload, part.get_boundary(failobj=None))

    if boundary is None:
        part.replace_header('Content-Type', 'text/plain')
        return False

    try:
        repaired = email.message_from_string(f'Content-Type: multipart/mixed; boundary="{boundary}"\n\n{payload}', policy=policy).get_payload()
    except RecursionError:
        logger.warning('Multipart parts nested too deeply to repair, treating the part as text.')
        repaired = None

    if not isinstance(repaired, list):
        # The stdlib did not split it either, e.g. because it decodes an encoded word in the boundary. Retrying would never end.
        part.replace_header('Content-Type', 'text/plain')
        return False

    try:
        part.set_param('boundary', boundary)
    except ValueError:
        # The other parameters contain line breaks, which may not be stored again. set_param() removed the header already.
        logger.warning('Content-Type of a repaired multipart part contains line breaks, keeping only the boundary.')
        part['Content-Type'] = f'multipart/mixed; boundary="{boundary}"'

    part.set_payload(repaired)
    return True


def repair_multipart(msg: email.message.Message, policy: email.policy.Policy) -> None:
    """Split multipart parts which the stdlib parser could not split because their boundary is missing or wrong.

    The stdlib leaves the content of such a part as one opaque string, so the URLs, addresses and attachments in it would be invisible.
    This is what malware authors and broken mailers produce. If no boundary can be found at all, the part is treated as plain text instead
    of being ignored. The defects reported by the stdlib are kept. Parts created by the repair are checked as well.

    Args:
        msg (email.message.Message): The parsed message, modified in place.
        policy (email.policy.Policy): The policy the message was parsed with, used for the repaired parts.
    """
    parts = [msg]

    while parts:
        part = parts.pop()

        if part.is_multipart():
            parts.extend(typing.cast('list[email.message.Message]', part.get_payload()))
            continue

        if part.get_content_maintype() != 'multipart':
            continue

        if _split_multipart(part, _stored_payload(part), policy):
            parts.append(part)


def is_text_part(part: email.message.Message, filename_lower: str) -> bool:
    """Check whether a part is text which is to be scanned like the body.

    These are text parts (unless they are attachments) and attachments which carry links, i.e. scripts, shortcuts, web pages, SVG, ...
    Data attachments (XML, JSON, CSV, ...) are not scanned, and neither are attachments larger than `MAX_TEXT_ATTACHMENT_SIZE`.

    Args:
        part (email.message.Message): The part.
        filename_lower (str): The lower-cased file name of the part.

    Returns:
        bool: Whether the part is scanned as text.
    """
    is_attachment = part.get_content_disposition() == 'attachment'
    is_text = (
        (part.get_content_maintype() == 'text' and not is_attachment)
        or part.get_content_type() in eml_parser.constants.TEXT_ATTACHMENT_CONTENT_TYPES
        or filename_lower.endswith(eml_parser.constants.TEXT_ATTACHMENT_EXTENSIONS)
    )

    if is_text and is_attachment and len(payload_text(part)) > eml_parser.constants.MAX_TEXT_ATTACHMENT_SIZE:
        logger.warning('Text attachment "%s" is larger than %d bytes, it is not scanned.', filename_lower, eml_parser.constants.MAX_TEXT_ATTACHMENT_SIZE)
        return False

    return is_text


def text_parts(msg: email.message.Message, recursion_limit: int) -> list[BodyPart]:
    """Retrieve all text parts of an e-mail, i.e. the text parts and the attachments which are scanned as text (see `is_text_part()`).

    Args:
        msg (email.message.Message): The e-mail message.
        recursion_limit (int): Maximum nesting depth of the parts.

    Returns:
        list: The text parts, in the order of the message.

    Raises:
        RecursionError: If the parts are nested deeper than *recursion_limit*.
    """
    body_parts: list[BodyPart] = []

    for part, boundary in iter_parts(msg, recursion_limit):
        # Text document attachments (e.g. .htm/.html) belong to the body as well, so that they do not escape the URL scan.
        if part.is_multipart() or not is_text_part(part, filename(part).lower()):
            continue

        encoding = part.get('content-transfer-encoding', '').lower()
        text = eml_parser.decode.decode_body(typing.cast('bytes', part.get_payload(decode=True)), part.get_content_charset())
        body_parts.append(BodyPart(encoding, text, eml_parser.headers.header_items(part), boundary))

    return body_parts
