"""Tests for `eml_parser.attachments` and `eml_parser.anomalies`: attachment entries, names, hashes and anomalies."""

import binascii
import email
import email.message
import importlib
import pathlib
import sys
import types
import typing

import pytest

import eml_parser.anomalies
import eml_parser.attachments
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


def _unnamed_part(parent: email.message.EmailMessage, payload: bytes) -> None:
    parent.add_attachment(payload, maintype='application', subtype='octet-stream')


def _filenames(parsed: dict) -> list[str]:
    return [attachment['filename'] for attachment in parsed['attachment']]


def test_unnamed_attachments_get_unique_names() -> None:
    msg = email.message.EmailMessage()
    msg['From'] = 'a@example.com'
    msg.set_content('body')
    for payload in (b'first', b'second', b'third'):
        _unnamed_part(msg, payload)

    parsed = eml_parser.parser.EmlParser().decode_email_bytes(msg.as_bytes())

    assert _filenames(parsed) == ['part-000', 'part-001', 'part-002']


def test_unnamed_attachments_in_nested_multiparts_get_unique_names() -> None:
    part = b'Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\nQUJD\r\n'
    raw_email = (
        b'From: a@example.com\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="outer"\r\n\r\n'
        b'--outer\r\nContent-Type: text/plain\r\n\r\nbody\r\n'
        b'--outer\r\n' + part + b'--outer\r\nContent-Type: multipart/mixed; boundary="inner"\r\n\r\n'
        b'--inner\r\n' + part + b'--inner\r\n' + part + b'--inner--\r\n'
        b'--outer\r\n' + part + b'--outer--\r\n'
    )

    parsed = eml_parser.parser.EmlParser().decode_email_bytes(raw_email)
    names = _filenames(parsed)

    assert names == ['part-000', 'part-001', 'part-002', 'part-003']


def test_named_attachments_keep_their_name_and_consume_a_number() -> None:
    msg = email.message.EmailMessage()
    msg['From'] = 'a@example.com'
    msg.set_content('body')
    msg.add_attachment(b'one', maintype='application', subtype='octet-stream', filename='invoice.bin')
    _unnamed_part(msg, b'two')

    parsed = eml_parser.parser.EmlParser().decode_email_bytes(msg.as_bytes())

    assert _filenames(parsed) == ['invoice.bin', 'part-001']


def test_attached_message_which_cannot_be_serialised_does_not_raise() -> None:
    """A message/rfc822 part with text the generator cannot encode is still listed as attachment."""
    raw = b' \nContent-Type:multipart/\n--0t\nContent-Type:message/rfc822\n\xad'

    assert eml_parser.parser.EmlParser().decode_email_bytes(raw)['attachment']


def test_file_hashes() -> None:
    # Arrange
    data = (pathlib.Path(__file__).resolve().parent.parent / 'samples' / 'sample.eml').read_bytes()

    # Act
    hashes = eml_parser.attachments.file_hashes(data)

    # Assert
    assert hashes == {
        'md5': '2c5e3f62e6d2b1511a0f5e7476bca46a',
        'sha1': 'effbc0f4702f8d8d1d4911a6f0228013919c2cdc',
        'sha256': '99798841db2f773a11ead628526ab4d6226187e20ca715e3439bb7375806b275',
        'sha512': '3a3d78e6cb8a5e0740fbfdf36083d9da950a60843bb240990ab30fa4062e608a17770a582de3d13b5240727531cfb98a826fbcc6aadd371f541acabb7c9f98e7',
    }


def test_attached_message_with_a_multipart_without_boundary_has_a_stable_hash() -> None:
    # Arrange: the stdlib generator would invent a random boundary for the inner multipart on every serialization
    raw = (
        b'From: a@b.example\nContent-Type: multipart/mixed; boundary=X\n\n--X\nContent-Type: message/rfc822\n\n'
        b'From: c@d.example\nContent-Type: multipart/mixed; boundary=""\n\n--\nContent-Type: text/plain\n\ninner\n----\n--X--\n'
    )

    # Act
    first = eml_parser.parser.EmlParser().decode_email_bytes(raw)['attachment'][0]
    second = eml_parser.parser.EmlParser().decode_email_bytes(raw)['attachment'][0]

    # Assert
    assert first['hash'] == second['hash']


def test_boundaries_of_an_attached_message_are_derived_from_its_content() -> None:
    # Arrange
    raw = b'From: c@d.example\nContent-Type: multipart/mixed; boundary=""\n\n--\nContent-Type: text/plain\n\ninner\n----\n'
    part = email.message.Message()
    part['Content-Type'] = 'message/rfc822'
    part.set_payload([email.message_from_bytes(raw)])

    # Act
    data = eml_parser.attachments.embedded_message_bytes(part)

    # Assert
    boundary = typing.cast('list[email.message.Message]', part.get_payload())[0].get_boundary()
    assert boundary is not None
    assert boundary.startswith('eml-parser-')
    assert data.count(f'--{boundary}'.encode()) == 2


@pytest.fixture
def reload_attachments() -> typing.Iterator[None]:
    """Import `eml_parser.attachments` again after the test, with the real `magic` module."""
    yield
    importlib.reload(eml_parser.attachments)


@pytest.mark.usefixtures('reload_attachments')
def test_without_magic_no_mime_type_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange: magic not installed, and a magic module without the file-magic API (python-magic)
    monkeypatch.setitem(sys.modules, 'magic', None)
    importlib.reload(eml_parser.attachments)
    not_installed = eml_parser.attachments.mime_type(b'%PDF-1.4')
    monkeypatch.setitem(sys.modules, 'magic', types.ModuleType('magic'))

    # Act
    importlib.reload(eml_parser.attachments)
    other_api = eml_parser.attachments.mime_type(b'%PDF-1.4')

    # Assert
    assert not_installed == (None, None)
    assert other_api == (None, None)


def test_undetermined_mime_type_is_left_out(monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange
    monkeypatch.setattr(eml_parser.attachments, 'magic', types.SimpleNamespace())
    monkeypatch.setattr(eml_parser.attachments, 'mime_type', lambda data: (None, None))
    part = email.message.Message()
    part['Content-Type'] = 'application/pdf'
    part.set_payload('data')

    # Act
    attachment, _ = eml_parser.attachments.describe(part, 0, include_data=False)

    # Assert
    assert 'mime_type' not in attachment
    assert attachment['filename'] == 'part-000'


def test_only_the_first_of_several_attached_messages_is_serialized() -> None:
    # Arrange: the parser never creates such a part, but the stdlib allows it
    first = email.message_from_bytes(b'Subject: first\n\none')
    second = email.message_from_bytes(b'Subject: second\n\ntwo')
    part = email.message.Message()
    part['Content-Type'] = 'message/rfc822'
    part.set_payload([first, second])

    # Act
    data = eml_parser.attachments.embedded_message_bytes(part)

    # Assert
    assert data == first.as_bytes()


def test_invalid_attachment_data_drops_the_attachments(monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange: the stdlib raised these for invalid base64 or RFC 2231 data in older Python versions
    def describe(part: email.message.Message, number: int, include_data: bool) -> tuple[dict, bytes]:
        raise binascii.Error('forced for test')

    monkeypatch.setattr(eml_parser.attachments, 'describe', describe)
    raw = b'From: a@b.example\nContent-Type: multipart/mixed; boundary=X\n\n--X\nContent-Type: application/pdf\n\nAAAA\n--X--\n'

    # Act
    result = eml_parser.parser.EmlParser().decode_email_bytes(raw)

    # Assert
    assert 'attachment' not in result
