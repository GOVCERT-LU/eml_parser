"""The attachments of a message: which parts are attachments, their content, hashes, file type and anomalies."""

import base64
import collections.abc
import email.message
import email.policy
import hashlib
import logging
import pathlib
import typing

import eml_parser.anomalies
import eml_parser.decode
import eml_parser.headers
import eml_parser.mime

logger = logging.getLogger(__name__)

try:
    import magic
except ImportError:
    magic = None
else:
    if not hasattr(magic, 'open'):
        logger.warning(
            'The installed "magic" module does not provide the file-magic compatible API (magic.open), '
            'mime types will not be determined. Install file-magic or a python-magic version which provides it.'
        )

        magic = None

HASH_TYPES = ('md5', 'sha1', 'sha256', 'sha512')


def file_hashes(data: bytes) -> dict[str, str]:
    """Generate hashes of various types (``MD5``, ``SHA-1``, ``SHA-256``, ``SHA-512``) for the provided data.

    Args:
        data (bytes): The data to calculate the hashes on.

    Returns:
        dict: The hex encoded hash per hash type.
    """
    return {hash_type: hashlib.new(hash_type, data).hexdigest() for hash_type in HASH_TYPES}


def mime_type(data: bytes) -> tuple[str, str] | tuple[None, None]:
    """Get mime-type information based on the provided bytes object.

    Args:
        data: Binary data.

    Returns:
        tuple: Identified mime information and mime-type. If **magic** is not available, returns *None, None*.
            E.g. *"ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)", "application/x-sharedlib"*
    """
    if magic is None:
        return None, None

    detected = magic.detect_from_content(data)
    return detected.name, detected.mime_type


def embedded_message_bytes(part: email.message.Message) -> bytes:
    """Serialize the e-mail message attached in a *message/rfc822* part.

    For multipart parts without a boundary the stdlib generator invents a random one, which would give the attachment another hash on
    every run. They get a boundary derived from the content instead: the message is serialized with placeholders first, and the hash
    of that is part of the boundaries, so the content cannot contain them. The generator reads the boundary with the policy it
    writes with, which is compat32 if the default policy fails, so a part needs one if either policy finds none.

    Args:
        part (email.message.Message): The *message/rfc822* part, the boundaries of its parts are set.

    Returns:
        bytes: The attached message.
    """
    payload = typing.cast('list[email.message.Message]', part.get_payload())
    if len(payload) > 1:
        logger.warning('More than one payload for "message/rfc822" part detected. This is not supported, please report!')

    message = payload[0]
    unbounded = []

    for sub_part in message.walk():
        if sub_part.is_multipart() and sub_part.get_content_maintype() == 'multipart' and _lacks_boundary(sub_part):
            unbounded.append(sub_part)

    if not unbounded:
        return _serialize(message)

    for number, sub_part in enumerate(unbounded):
        sub_part.set_boundary(f'eml-parser-{number}')

    digest = hashlib.sha256(_serialize(message)).hexdigest()

    for number, sub_part in enumerate(unbounded):
        sub_part.set_boundary(f'eml-parser-{digest}-{number}')

    return _serialize(message)


def _lacks_boundary(part: email.message.Message) -> bool:
    """Whether a multipart part has no boundary, read with its own policy or with compat32, see `embedded_message_bytes()`."""
    if not part.get_boundary():
        return True

    with eml_parser.headers.using_policy(part, email.policy.compat32):
        return not part.get_boundary()


def _serialize(message: email.message.Message) -> bytes:
    """Serialize a message, with the lenient compat32 policy if the default policy fails on a header field.

    The text of the message is ASCII with 8-bit bytes surrogate escaped, as the parser stores it (repaired multipart parts are
    parsed from their bytes as well, see `mime.repair_multipart()`), which the bytes generator writes as it is.
    """
    try:
        return message.as_bytes(policy=email.policy.default.clone(max_line_length=0))
    except (AttributeError, IndexError, UnicodeEncodeError):
        # The stdlib header parsers fail while refolding some malformed header fields (AttributeError, IndexError), and so does
        # encoding a refolded value with an 8-bit byte as UTF-8 (UnicodeEncodeError). compat32 writes the fields as they are.
        logger.debug('The message in a "message/rfc822" part cannot be serialized with the default policy, using compat32.')

    return message.as_bytes(policy=email.policy.compat32.clone(max_line_length=0))


def attachment_parts(msg: email.message.Message, recursion_limit: int) -> collections.abc.Iterator[email.message.Message]:
    """Walk the parts of a message which are attachments.

    Any part which is not text is an attachment, and so is text with a disposition other than inline. An attached e-mail
    message (*message/rfc822*) is an attachment, and its parts are walked as well.

    Args:
        msg (email.message.Message): The message.
        recursion_limit (int): Maximum nesting depth of the parts.

    Yields:
        email.message.Message: The attachments, in the order of the message.

    Raises:
        RecursionError: If the parts are nested deeper than *recursion_limit*.
    """
    for part, _ in eml_parser.mime.iter_parts(msg, recursion_limit):
        # Without a Content-Type field, get_content_type() returns the default of the enclosing multipart.
        is_attached_message = 'content-type' in part and part.get_content_type() == 'message/rfc822'

        if part.is_multipart() and not is_attached_message:
            continue

        has_attachment_disposition = 'content-disposition' in part and part.get_content_disposition() != 'inline'

        if has_attachment_disposition or part.get_content_maintype() != 'text':
            yield part


def describe(part: email.message.Message, number: int, include_data: bool) -> tuple[dict[str, typing.Any], bytes]:
    """Build the entry of an attachment in the parse result: file name, size, hashes, file type, anomalies and header fields.

    Args:
        part (email.message.Message): The attachment, see `attachment_parts()`.
        number (int): The number of the attachment in the message, names attachments without a file name.
        include_data (bool): Include the content, base64 encoded.

    Returns:
        tuple: The entry and the content of the attachment.
    """
    if part.get_content_type() == 'message/rfc822':
        data = embedded_message_bytes(part)
    else:
        data = typing.cast('bytes', part.get_payload(decode=True))

    filename = eml_parser.mime.filename(part)
    filename = eml_parser.decode.decode_field(filename) if filename else f'part-{number:03d}'

    attachment: dict[str, typing.Any] = {'filename': filename, 'size': len(data)}

    # in case there is no extension pathlib.Path(filename).suffix returns an empty string
    if extension := pathlib.Path(filename).suffix:
        # strip leading dot and lower-case
        attachment['extension'] = extension[1:].lower()

    attachment['hash'] = file_hashes(data)

    full_mime_type, mime_type_short = mime_type(data)

    if anomalies := eml_parser.anomalies.find_filename_anomalies(filename, data, mime_type_short):
        attachment['anomaly'] = anomalies

    if full_mime_type is not None and mime_type_short is not None:
        attachment['mime_type'] = full_mime_type
        attachment['mime_type_short'] = mime_type_short
    elif magic is not None:
        logger.warning('Error determining attachment mime-type - "%s"', filename)

    if include_data:
        attachment['raw'] = base64.b64encode(data)

    content_headers: dict[str, list[str]] = {}
    for name, value in eml_parser.headers.header_items(part):
        content_headers.setdefault(name.lower(), []).append(str(value))
    attachment['content_header'] = content_headers

    return attachment, data
