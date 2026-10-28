"""Tests for `eml_parser.policy`: the header parsing policy, its cache and the header parsing limits."""

import datetime as dt
import email
import email.message
import email.policy
import logging
import time

import pytest

import eml_parser.decode
import eml_parser.parser
import eml_parser.policy
import eml_parser.regexes

MAIL = b"""From: Alice <alice@example.com>
To: Bob <bob@example.org>
Subject: Test
Date: Mon, 5 Oct 2026 09:12:44 +0200
Message-ID: <1@example.com>
Received: from mx.example.net (mx.example.net [192.0.2.1]) by mail.example.org; Mon, 5 Oct 2026 09:12:44 +0200

Body
"""


class TestHeaderCache:
    def test_repeated_header_access_hits_the_cache(self) -> None:
        eml_parser.policy.CustomPolicy._fetch_fixed_header.cache_clear()  # noqa: SLF001
        parser = eml_parser.parser.EmlParser()

        result = parser.decode_email_bytes(MAIL)

        info = eml_parser.policy.CustomPolicy._fetch_fixed_header.cache_info()  # noqa: SLF001
        assert info.hits > 0
        assert result['header']['from'] == 'alice@example.com'
        assert result['header']['header']['subject'] == ['Test']

    def test_policies_with_different_settings_do_not_share_results(self) -> None:
        value = '<[x]user@localhost>'
        relaxed = eml_parser.policy.CustomPolicy(eml_parser.regexes.email_no_force_tld_regex)
        strict = eml_parser.policy.CustomPolicy(eml_parser.regexes.email_force_tld_regex)

        assert relaxed.fetch_fixed_header('Message-ID', value) == '<user@localhost>'
        assert strict.fetch_fixed_header('Message-ID', value) == ''

    def test_warnings_are_logged_on_every_access(self, caplog: pytest.LogCaptureFixture) -> None:
        eml_parser.policy.CustomPolicy._fetch_fixed_header.cache_clear()  # noqa: SLF001
        caplog.set_level(logging.WARNING)
        parser = eml_parser.parser.EmlParser()
        mail = b'From: a@example.com\nMessage-ID: <[x]\n\nbody'

        parser.decode_email_bytes(mail)
        warning = 'Header field "message-id" is in an invalid format and cannot be fixed, it will be dropped.'
        count = caplog.text.count(warning)
        assert count > 0

        # The same value is already in the cache, so the second parse must still be warned about.
        parser.decode_email_bytes(mail)
        assert caplog.text.count(warning) == 2 * count


# The header parsing limits (constants.MAX_PARSED_HEADER_FIELDS and MAX_PARSED_HEADER_BYTES): beyond the limits, header values are kept
# raw instead of being run through the structured header parsers. Nothing is dropped, the essential fields are parsed regardless,
# and the message reports a HeaderParsingLimitDefect.
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

    eml_parser.policy.limit_header_parsing(msg)


def _parse_header(header: bytes) -> dict:
    return eml_parser.parser.EmlParser().decode_email_bytes(header + b'\r\nFrom: a@example.com\r\n\r\nbody')['header']


@pytest.mark.parametrize(
    'header',
    [
        b'Content-Type: text/plain; ' + b'a=b; ' * 30_000,
        b'To: ' + b'a@example.com, ' * 10_000,
        b'Subject: ' + b'word ' * 100_000,
    ],
    ids=['content-type', 'to', 'subject'],
)
def test_huge_header_is_cheap(header: bytes) -> None:
    """The stdlib parsers need seconds for such values, the cost must not grow with the square of the length."""
    start = time.monotonic()
    _parse_header(header)

    assert time.monotonic() - start < 3


def test_long_address_header_still_yields_the_addresses() -> None:
    """A long list of recipients is a real thing, its addresses are extracted from the unparsed value."""
    addresses = [f'user{i}@example.com' for i in range(2000)]

    header = _parse_header(b'To: ' + ', '.join(f'"User {i}" <{address}>' for i, address in enumerate(addresses)).encode())

    assert header['to'] == addresses


def test_huge_date_is_the_default_date() -> None:
    """A date can not be that long, it is invalid."""
    assert _parse_header(b'Date: ' + b'Mon ' * 20_000)['date'] == dt.datetime.fromisoformat(eml_parser.decode.default_date)


def test_date_the_stdlib_fails_on_is_the_default_date(monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange: older Python versions raise a TypeError for some dates
    original = email.policy.EmailPolicy.header_fetch_parse

    def header_fetch_parse(self: email.policy.EmailPolicy, name: str, value: str) -> str:
        if name.lower() == 'date':
            raise TypeError('forced for test')
        return original(self, name, value)

    monkeypatch.setattr(email.policy.EmailPolicy, 'header_fetch_parse', header_fetch_parse)
    policy = eml_parser.policy.CustomPolicy()

    # Act
    value = policy.header_fetch_parse('Date', 'Mon, 1 Jan 2024 10:00:00 +0000 (forced)')

    # Assert
    assert value == eml_parser.decode.default_date
