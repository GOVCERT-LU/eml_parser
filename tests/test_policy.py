"""Tests for `eml_parser.policy`: the header parsing policy, its cache and the header parsing limits."""

import datetime as dt
import email
import email.message
import email.policy
import logging
import time
import typing

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


def _count_stdlib_parses(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """Record every value the policy hands to the structured header parsers of the stdlib."""
    parses: list[tuple[str, str]] = []
    stdlib_parse = email.policy.EmailPolicy.header_fetch_parse

    def counting(self: email.policy.EmailPolicy, name: str, value: str) -> typing.Any:
        if isinstance(self, eml_parser.policy.CustomPolicy):
            parses.append((name, value))
        return stdlib_parse(self, name, value)

    monkeypatch.setattr(email.policy.EmailPolicy, 'header_fetch_parse', counting)
    return parses


def _parsed_header_cache() -> dict | None:
    return eml_parser.policy._PARSED_HEADERS.get()  # noqa: SLF001 - the cache has no public interface


class TestHeaderCache:
    def test_each_value_is_parsed_once_per_message(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # More distinct values than the process-wide cache of 1,024 values used up to v4.7.1, beyond which each field was parsed three times.
        received = ''.join(f'Received: from h{i}.example.net by mx.example.org; Mon, 5 Oct 2026 09:12:44 +0200\n' for i in range(2_000))
        parses = _count_stdlib_parses(monkeypatch)

        result = eml_parser.parser.EmlParser().decode_email_bytes(received.encode() + MAIL)

        assert len(result['header']['received']) == 2_001
        # No value is parsed twice; the count of distinct values is not asserted, it may differ across Python versions.
        assert len(parses) == len(set(parses))
        assert len({value for name, value in parses if name.lower() == 'received'}) == 2_001

    def test_nothing_is_kept_between_messages(self, monkeypatch: pytest.MonkeyPatch) -> None:
        parses = _count_stdlib_parses(monkeypatch)
        parser = eml_parser.parser.EmlParser()

        first = parser.decode_email_bytes(MAIL)
        once = len(parses)
        second = parser.decode_email_bytes(MAIL)

        assert once == len(set(parses))
        assert len(parses) == 2 * once
        assert first == second
        assert _parsed_header_cache() is None

    def test_cache_is_dropped_when_the_parse_fails(self) -> None:
        def failing_hook(part: eml_parser.parser.PartData) -> None:
            assert _parsed_header_cache()
            raise ValueError(f'hook failed on {len(part.data)} bytes')

        with pytest.raises(ValueError, match='hook failed'):
            eml_parser.parser.EmlParser(part_hook=failing_hook).decode_email_bytes(MAIL)

        assert _parsed_header_cache() is None

    def test_nested_parse_has_its_own_cache(self) -> None:
        inner_mail = MAIL.replace(b'Subject: Test', b'Subject: Inner')
        seen: dict[str, typing.Any] = {}

        def nested_hook(part: eml_parser.parser.PartData) -> None:
            outer = _parsed_header_cache()
            seen['outer_cached'] = bool(outer)
            seen['outer_keys'] = set(outer or {})
            seen['inner'] = eml_parser.parser.EmlParser().decode_email_bytes(inner_mail)
            seen['restored'] = _parsed_header_cache() is outer and set(outer or {}) == seen['outer_keys']

        result = eml_parser.parser.EmlParser(part_hook=nested_hook).decode_email_bytes(MAIL)

        assert result['header']['subject'] == 'Test'
        assert seen['inner']['header']['subject'] == 'Inner'
        assert seen['outer_cached']
        assert seen['restored']
        assert not any(value == 'Inner' for _, _, value in seen['outer_keys'])

    def test_policies_with_different_settings_do_not_share_results(self) -> None:
        value = '<[x]user@localhost>'
        relaxed = eml_parser.policy.CustomPolicy(eml_parser.regexes.email_no_force_tld_regex)
        strict = eml_parser.policy.CustomPolicy(eml_parser.regexes.email_force_tld_regex)

        for _ in range(2):  # outside a parse
            assert relaxed.fetch_fixed_header('Message-ID', value) == '<user@localhost>'
            assert strict.fetch_fixed_header('Message-ID', value) == ''

        with eml_parser.policy.parsed_header_cache():
            for _ in range(2):  # within one, the second time from the cache
                assert relaxed.fetch_fixed_header('Message-ID', value) == '<user@localhost>'
                assert strict.fetch_fixed_header('Message-ID', value) == ''

    def test_warnings_are_logged_on_every_access(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level(logging.WARNING)
        parser = eml_parser.parser.EmlParser()
        mail = b'From: a@example.com\nMessage-ID: <[x]\n\nbody'
        warning = 'Header field "message-id" is in an invalid format and cannot be fixed, it will be dropped.'

        with eml_parser.policy.parsed_header_cache():
            policy = eml_parser.policy.CustomPolicy()
            policy.fetch_fixed_header('Message-ID', '<[x]')
            policy.fetch_fixed_header('Message-ID', '<[x]')
        assert caplog.text.count(warning) == 2

        caplog.clear()
        parser.decode_email_bytes(mail)
        count = caplog.text.count(warning)
        assert count > 0

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


@pytest.mark.parametrize('value', ['"', '"John <a@b.example>', 'a@b.example x <c@d.example>', '<a@b.example> junk'])
def test_address_value_the_stdlib_parses_lossily_raises(value: str) -> None:
    """Such values raise an IndexError on every Python version, like older ones do for some of them, so the same workarounds apply."""
    with pytest.raises(IndexError):
        eml_parser.policy.CustomPolicy().header_fetch_parse('To', value)


@pytest.mark.parametrize('value', ['root', 'John <a@b.example>, c@d.example', 'team: a@b.example, c@d.example;', '"a b"@c.example'])
def test_address_value_with_harmless_defects_or_none_is_parsed(value: str) -> None:
    assert eml_parser.policy.CustomPolicy().header_fetch_parse('To', value) != ''


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
