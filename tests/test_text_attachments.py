"""Tests for text attachments."""

import pytest

import eml_parser.constants
import eml_parser.parser


def _mail(content_type: str, filename: str, disposition: str = 'attachment') -> bytes:
    return (
        b'From: a@example.com\r\nContent-Type: multipart/mixed; boundary="b"\r\n\r\n'
        b'--b\r\nContent-Type: text/plain\r\n\r\nhello\r\n'
        + f'--b\r\nContent-Type: {content_type}; name="{filename}"\r\nContent-Disposition: {disposition}; filename="{filename}"\r\n\r\n'.encode()
        + b'[InternetShortcut]\r\nURL=http://evil.example.com/dl\r\n--b--\r\n'
    )


def _parse(content_type: str, filename: str) -> dict:
    return eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(_mail(content_type, filename))


@pytest.mark.parametrize(
    ('content_type', 'filename'),
    [
        ('application/octet-stream', 'x.url'),
        ('application/octet-stream', 'run.PS1'),
        ('text/plain', 'note.txt'),
        ('image/svg+xml', 'logo'),
        ('application/javascript', 'x.dat'),
    ],
)
def test_attachment_is_scanned_and_kept(content_type: str, filename: str) -> None:
    """By extension or content type: the URL inside is found and the file stays in the attachment list."""
    parsed = _parse(content_type, filename)

    assert any('http://evil.example.com/dl' in body.get('uri', []) for body in parsed['body'])
    assert [a['filename'] for a in parsed['attachment']] == [filename]


@pytest.mark.parametrize(
    ('content_type', 'filename'),
    [
        ('application/octet-stream', 'x.bin'),
        ('application/xml', 'data.xml'),
        ('application/json', 'data.json'),
        ('text/csv', 'list.csv'),
        ('text/xml', 'schema.xsd'),
    ],
)
def test_binary_and_data_attachments_are_not_scanned(content_type: str, filename: str) -> None:
    """Binary files and data formats (XML, JSON, CSV) are only listed, their namespace and schema URLs are not indicators."""
    parsed = _parse(content_type, filename)

    assert not any(body.get('uri') for body in parsed['body'])
    assert [a['filename'] for a in parsed['attachment']] == [filename]


def test_large_attachment_is_not_scanned(monkeypatch: pytest.MonkeyPatch) -> None:
    """Above the limit the attachment is only listed."""
    monkeypatch.setattr(eml_parser.constants, 'MAX_TEXT_ATTACHMENT_SIZE', 10)
    parsed = _parse('text/plain', 'big.txt')

    assert not any(body.get('uri') for body in parsed['body'])
    assert [a['filename'] for a in parsed['attachment']] == ['big.txt']
