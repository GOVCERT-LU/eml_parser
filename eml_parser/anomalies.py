"""Detection of tricks used to disguise the type of an attachment."""

import unicodedata

import eml_parser.constants

# Bidirectional control characters: the right-to-left override (U+202E) shows `invoice<U+202E>fdp.exe` as `invoiceexe.pdf`.
_BIDI_CONTROL = frozenset({'LRE', 'RLE', 'LRO', 'RLO', 'PDF', 'LRI', 'RLI', 'FSI', 'PDI'})

_PADDING = ' ' * 10


def is_executable_content(data: bytes, mime_type: str | None = None) -> bool:
    """Check whether the data is a Windows (PE) or Linux (ELF) executable, by its signature or by the detected mime type."""
    if mime_type in eml_parser.constants.EXECUTABLE_MIME_TYPES or data.startswith(b'\x7fELF'):
        return True

    if data.startswith(b'MZ') and len(data) >= 64:
        pe_offset = int.from_bytes(data[60:64], 'little')

        return data[pe_offset : pe_offset + 4] == b'PE\x00\x00'

    return False


def find_filename_anomalies(filename: str, data: bytes, mime_type: str | None = None) -> list[str]:
    """Look for tricks used to disguise the type of an attachment.

    The result is a list of the following codes:

    * *filename-bidi-control*: contains a bidirectional control character (see above).
    * *filename-control-chars*: contains other control or invisible formatting characters (NUL, zero width space, ...).
    * *filename-double-extension*: a document or picture extension followed by an executable one (`invoice.pdf.exe`).
    * *filename-trailing-dot-or-space*: ends with a dot or space, which Windows silently removes.
    * *filename-padding*: a run of 10 or more spaces, hiding the real extension from the display.
    * *extension-content-mismatch*: executable content (PE or ELF) under the name of a document or picture, or without an extension.

    Args:
        filename: The (decoded) name of the attachment.
        data: The content of the attachment.
        mime_type: The mime type of the content, if known.

    Returns:
        list: The codes, empty if nothing is suspicious.
    """
    anomalies: list[str] = []

    if any(unicodedata.bidirectional(char) in _BIDI_CONTROL for char in filename):
        anomalies.append('filename-bidi-control')
    elif any(unicodedata.category(char) in ('Cc', 'Cf') for char in filename):
        anomalies.append('filename-control-chars')

    extensions = [part.lower().strip() for part in filename.rstrip(' .').split('.')[1:]]

    if len(extensions) >= 2 and extensions[-1] in eml_parser.constants.EXECUTABLE_EXTENSIONS and extensions[-2] in eml_parser.constants.DECOY_EXTENSIONS:
        anomalies.append('filename-double-extension')

    if filename != filename.rstrip(' .'):
        anomalies.append('filename-trailing-dot-or-space')

    if _PADDING in filename:
        anomalies.append('filename-padding')

    harmless = {*eml_parser.constants.DECOY_EXTENSIONS, ''}
    if (extensions[-1] if extensions else '') in harmless and is_executable_content(data, mime_type):
        anomalies.append('extension-content-mismatch')

    return anomalies
