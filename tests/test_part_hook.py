"""Tests for the part_hook callback."""

import hashlib

import pytest

import eml_parser.parser

# A multipart mail with three parts:
#   1. a text/plain body part
#   2. a text/html attachment (scanned as body AND as attachment)
#   3. a binary attachment
RAW_MAIL = (
    b'From: a@example.com\r\n'
    b'Subject: part hook\r\n'
    b'Content-Type: multipart/mixed; boundary="b"\r\n'
    b'\r\n'
    b'--b\r\n'
    b'Content-Type: text/plain; charset="utf-8"\r\n'
    b'\r\n'
    b'body line\r\n'
    b'--b\r\n'
    b'Content-Type: text/html; name="note.html"\r\n'
    b'Content-Disposition: attachment; filename="note.html"\r\n'
    b'\r\n'
    b'<html><body>note</body></html>\r\n'
    b'--b\r\n'
    b'Content-Type: application/octet-stream; name="bin.dat"\r\n'
    b'Content-Disposition: attachment; filename="bin.dat"\r\n'
    b'Content-Transfer-Encoding: base64\r\n'
    b'\r\n'
    b'AQID\r\n'
    b'--b--\r\n'
)


def test_hook_receives_every_part_with_hashed_bytes() -> None:
    """Each part is delivered once per representation, with data that matches its hash in the result."""
    calls: list[eml_parser.parser.PartData] = []
    result = eml_parser.parser.EmlParser(part_hook=calls.append).decode_email_bytes(RAW_MAIL)

    # The text/html attachment is scanned as body and as attachment, like in the result itself.
    assert [part.kind for part in calls] == ['body', 'body', 'attachment', 'attachment']

    for part in calls:
        assert part.sha256 == hashlib.sha256(part.data).hexdigest()

    bodies = {body['hash']: body for body in result['body']}
    attachments = {a['hash']['sha256']: a for a in result['attachment']}

    body_parts = [part for part in calls if part.kind == 'body']
    assert [part.data for part in body_parts] == [b'body line', b'<html><body>note</body></html>']
    assert all(part.sha256 in bodies for part in body_parts)
    assert all(part.filename is None for part in body_parts)
    assert body_parts[0].content_type == 'text/plain'
    assert body_parts[0].boundary == 'b'

    attachment_parts = [part for part in calls if part.kind == 'attachment']
    assert [part.filename for part in attachment_parts] == ['note.html', 'bin.dat']
    assert all(part.sha256 in attachments for part in attachment_parts)
    assert attachment_parts[1].data == b'\x01\x02\x03'
    assert attachment_parts[1].content_type == 'application/octet-stream'


def test_hook_fires_without_raw_body_in_the_result() -> None:
    """The point of the hook: the data is available to the scanner, but not in the returned structure."""
    calls: list[eml_parser.parser.PartData] = []
    result = eml_parser.parser.EmlParser(part_hook=calls.append).decode_email_bytes(RAW_MAIL)

    assert calls, 'the hook must fire even with include_raw_body and include_attachment_data left at False'
    assert all('content' not in body for body in result['body'])
    assert all('raw' not in attachment for attachment in result['attachment'])


def test_hook_not_set_parses_unchanged() -> None:
    """Without a hook the output is exactly the pre-existing one."""
    plain = eml_parser.parser.EmlParser().decode_email_bytes(RAW_MAIL)
    hooked = eml_parser.parser.EmlParser(part_hook=lambda part: None).decode_email_bytes(RAW_MAIL)
    assert plain == hooked


def test_hook_exception_propagates() -> None:
    """A failing scanner is not swallowed."""

    def failing(part: eml_parser.parser.PartData) -> None:
        raise RuntimeError('scan failed')

    with pytest.raises(RuntimeError, match='scan failed'):
        eml_parser.parser.EmlParser(part_hook=failing).decode_email_bytes(RAW_MAIL)


def test_hook_receives_attached_message_bytes() -> None:
    """A message/rfc822 attachment is delivered as attachment with the exact serialized bytes that were hashed.

    As an .eml file it is also scanned as text (like in the result itself), so the hook
    is called twice for it.
    """
    inner = b'From: in@example.com\r\nSubject: in\r\n\r\ninner body\r\n'
    raw = (
        b'From: a@example.com\r\n'
        b'Content-Type: multipart/mixed; boundary="b"\r\n'
        b'\r\n'
        b'--b\r\n'
        b'Content-Type: message/rfc822; name="inner.eml"\r\n'
        b'Content-Disposition: attachment; filename="inner.eml"\r\n'
        b'\r\n' + inner + b'--b--\r\n'
    )
    calls: list[eml_parser.parser.PartData] = []
    result = eml_parser.parser.EmlParser(part_hook=calls.append).decode_email_bytes(raw)

    attachments = [part for part in calls if part.kind == 'attachment']
    assert len(attachments) == 1
    attachment = attachments[0]
    assert attachment.filename == 'inner.eml'
    assert attachment.content_type == 'message/rfc822'
    assert result['attachment'][0]['hash']['sha256'] == attachment.sha256
