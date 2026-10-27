"""Tests for the attachment anomalies."""

import eml_parser.anomalies
import eml_parser.parser
import tests.table

RLO = chr(0x202E)  # right-to-left override
ZWSP = chr(0x200B)  # zero width space
PE = b'MZ' + b'\x00' * 58 + b'\x40\x00\x00\x00' + b'PE\x00\x00' + b'\x00' * 20


FIND_FILENAME_ANOMALIES_CASES = [
    ('report.pdf', b'%PDF-1.4', []),
    ('setup.exe', PE, []),
    ('invoice.pdf.exe', PE, ['filename-double-extension']),
    (f'invoice{RLO}fdp.exe', b'x', ['filename-bidi-control']),
    (f'invoice{ZWSP}.pdf', b'x', ['filename-control-chars']),
    ('invoice.pdf.', b'x', ['filename-trailing-dot-or-space']),
    (f'invoice.pdf{" " * 20}.exe', b'x', ['filename-double-extension', 'filename-padding']),
    ('invoice.pdf', PE, ['extension-content-mismatch']),
    ('invoice', b'\x7fELF\x02\x01', ['extension-content-mismatch']),
]


def test_find_filename_anomalies() -> None:
    """Each trick is detected, harmless files are not."""

    def check(filename: str, data: bytes, expected: list[str]) -> None:
        assert eml_parser.anomalies.find_filename_anomalies(filename, data) == expected

    tests.table.assert_all_cases(check, FIND_FILENAME_ANOMALIES_CASES)


def test_detected_mime_type_counts() -> None:
    """Executable content is also recognised by the detected mime type."""
    assert eml_parser.anomalies.find_filename_anomalies('a.jpg', b'x', 'application/x-dosexec') == ['extension-content-mismatch']


def test_reported_with_the_attachment() -> None:
    """The codes are part of the attachment, and absent for clean ones."""
    raw = (
        b'From: a@example.com\r\nContent-Type: multipart/mixed; boundary="b"\r\n\r\n--b\r\nContent-Type: application/octet-stream; name="a.pdf.exe"\r\n'
        b'Content-Disposition: attachment; filename="a.pdf.exe"\r\n\r\nxx\r\n--b\r\nContent-Type: text/x; name="ok.dat"\r\n'
        b'Content-Disposition: attachment; filename="ok.dat"\r\n\r\nyy\r\n--b--\r\n'
    )
    attachments = eml_parser.parser.EmlParser().decode_email_bytes(raw)['attachment']

    assert [a.get('anomaly') for a in attachments] == [['filename-double-extension'], None]
