"""Tests for the header parsing limits (constants.MAX_PARSED_HEADER_FIELDS and MAX_PARSED_HEADER_BYTES).

Beyond the limits, header values are kept raw instead of being run through the structured header parsers: nothing is dropped,
the essential fields are parsed regardless, and the message reports a HeaderParsingLimitDefect.
"""

import email
import email.message

import pytest

import eml_parser.constants
import eml_parser.parser

ENCODED = '=?utf-8?q?h=C3=A9llo?='
HEAD = 'From: a@example.test\r\nTo: b@example.test\r\nSubject: s\r\nDate: Thu, 15 Oct 2026 12:00:00 +0000\r\n'


@pytest.fixture
def small_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(eml_parser.constants, 'MAX_PARSED_HEADER_FIELDS', 50)


def _parse(raw: str) -> dict:
    return eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(raw.encode())


def _limit_defects(data: dict) -> list[str]:
    return [d for d in data['header'].get('defect', []) if d.startswith('HeaderParsingLimitDefect')]


def test_message_within_limits_has_no_defect() -> None:
    data = _parse(HEAD + ''.join(f'X-E{i}: {ENCODED}\r\n' for i in range(100)) + '\r\nbody\r\n')

    assert not _limit_defects(data)
    assert all(data['header']['header'][f'x-e{i}'] == ['héllo'] for i in range(100))


@pytest.mark.usefixtures('small_limits')
def test_fields_beyond_the_limit_are_kept_unparsed() -> None:
    data = _parse(HEAD + ''.join(f'X-E{i}: {ENCODED}\r\n' for i in range(100)) + '\r\nbody\r\n')
    fields = data['header']['header']

    # every field is in the output: the ones within the limit decoded, the others as raw text
    assert [fields[f'x-e{i}'] for i in range(100)].count(['héllo']) == 50 - 4
    assert [fields[f'x-e{i}'] for i in range(100)].count([ENCODED]) == 100 - (50 - 4)
    assert len(_limit_defects(data)) == 1
    assert '104 header fields' in _limit_defects(data)[0]


@pytest.mark.usefixtures('small_limits')
def test_essential_fields_behind_junk_are_parsed() -> None:
    junk = ''.join(f'X-J{i}: junk\r\n' for i in range(100))
    raw = (
        f'{junk}From: "Sender" <sender@example.test>\r\nSubject: {ENCODED}\r\nDate: Thu, 15 Oct 2026 12:00:00 +0200\r\nContent-Type: text/plain\r\n\r\nbody\r\n'
    )
    data = _parse(raw)

    assert data['header']['from'] == 'sender@example.test'
    assert data['header']['subject'] == 'héllo'
    assert data['header']['date'].isoformat() == '2026-10-15T12:00:00+02:00'
    assert _limit_defects(data)


@pytest.mark.usefixtures('small_limits')
def test_only_the_first_occurrence_of_an_essential_field_is_exempt() -> None:
    raw = HEAD + ''.join(f'Subject: {ENCODED}\r\n' for i in range(100)) + '\r\nbody\r\n'
    data = _parse(raw)

    assert data['header']['subject'] == 's'
    assert ENCODED in data['header']['header']['subject']
    assert _limit_defects(data)


@pytest.mark.usefixtures('small_limits')
def test_fields_of_mime_parts_count_and_their_structure_survives() -> None:
    part_headers = ''.join(f'X-P{i}: {ENCODED}\r\n' for i in range(100))
    raw = (
        HEAD
        + 'Content-Type: multipart/mixed; boundary="b0"\r\n\r\n'
        + '--b0\r\nContent-Type: text/plain\r\n\r\ntext http://text.example.test/\r\n'
        + f'--b0\r\n{part_headers}Content-Type: application/octet-stream; name="f.bin"\r\nContent-Disposition: attachment; filename="f.bin"\r\n'
        + 'Content-Transfer-Encoding: base64\r\n\r\nAAECAw==\r\n--b0--\r\n'
    )
    data = eml_parser.parser.EmlParser(include_attachment_data=True).decode_email_bytes(raw.encode())

    assert _limit_defects(data)
    assert [a['filename'] for a in data['attachment']] == ['f.bin']
    assert data['attachment'][0]['raw'] == b'AAECAw=='


def test_byte_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(eml_parser.constants, 'MAX_PARSED_HEADER_BYTES', 1000)
    data = _parse(HEAD + ''.join(f'X-E{i}: {ENCODED} {"x" * 70}\r\n' for i in range(100)) + '\r\nbody\r\n')

    assert _limit_defects(data)
    assert data['header']['header']['x-e0'] == ['héllo ' + 'x' * 70]
    assert data['header']['header']['x-e99'] == [f'{ENCODED} {"x" * 70}']


def test_deeply_nested_parts_do_not_overflow_the_stack() -> None:
    """Message.walk() recurses once per nesting level, the limit walks the parts iteratively."""
    msg = email.message.Message()
    msg['Content-Type'] = 'text/plain'
    msg.set_payload('leaf')
    for _ in range(5000):
        parent = email.message.Message()
        parent['Content-Type'] = 'multipart/mixed'
        parent.set_payload([msg])
        msg = parent

    with pytest.raises(RecursionError):
        list(msg.walk())

    eml_parser.parser.EmlParser.limit_header_parsing(msg)
