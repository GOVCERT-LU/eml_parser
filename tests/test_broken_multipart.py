"""Tests for multipart messages with a missing or wrong boundary."""

import eml_parser.parser

BODY = (
    b'--x1\r\nContent-Type: text/plain\r\n\r\nvisit http://evil.example.com/a\r\n'
    b'--x1\r\nContent-Type: application/octet-stream; name="a.bin"\r\nContent-Transfer-Encoding: base64\r\n\r\nSGVsbG8=\r\n--x1--\r\n'
)


def _parse(content_type: bytes, body: bytes = BODY) -> dict:
    return eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(b'From: a@example.com\r\nContent-Type: ' + content_type + b'\r\n\r\n' + body)


def test_missing_boundary() -> None:
    """Body and attachment are found, the defect is still reported."""
    parsed = _parse(b'multipart/mixed')

    assert parsed['body'][0]['uri'] == ['http://evil.example.com/a']
    assert len(parsed['attachment']) == 1
    assert 'NoBoundaryInMultipartDefect' in parsed['header']['defect']


def test_wrong_boundary() -> None:
    """A declared boundary which is not in the payload is replaced by the guessed one."""
    parsed = _parse(b'multipart/mixed; boundary="nope"')

    assert parsed['body'][0]['uri'] == ['http://evil.example.com/a']
    assert len(parsed['attachment']) == 1


def test_intact_message_is_untouched() -> None:
    """A correct boundary is kept and no defect is invented."""
    parsed = _parse(b'multipart/mixed; boundary="x1"')

    assert len(parsed['attachment']) == 1
    assert 'defect' not in parsed['header']


def test_without_any_delimiter_the_payload_is_scanned_as_text() -> None:
    """Nothing to split: the content is still searched for indicators."""
    parsed = _parse(b'multipart/mixed', b'visit http://evil.example.com/z\r\n')

    assert parsed['body'][0]['uri'] == ['http://evil.example.com/z']
    assert 'attachment' not in parsed


def test_nested_broken_multipart() -> None:
    """A broken part inside a repaired one is repaired too."""
    inner = b'--in\r\nContent-Type: text/plain\r\n\r\nnested http://nested.example.com/x\r\n--in--\r\n'
    parsed = _parse(b'multipart/mixed', b'--x1\r\nContent-Type: multipart/alternative\r\n\r\n' + inner + b'--x1--\r\n')

    assert parsed['body'][0]['uri'] == ['http://nested.example.com/x']
