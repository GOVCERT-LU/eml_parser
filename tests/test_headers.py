"""Tests for `eml_parser.headers`: header fields, addresses and authentication results, also of malformed messages."""

import email
import email.headerregistry
import email.message
import email.policy
import json
import os
import pathlib
import subprocess
import sys
import time
import typing

import pytest

import eml_parser.decode
import eml_parser.headers
import eml_parser.parser
import eml_parser.regexes
import tests.table


def test_authentication_results() -> None:
    """Methods are collected, properties like header.d= and comments are not mistaken for methods."""
    header = {
        'authentication-results': [
            'mx.example.com (dkim=fail inside (nested) comment); spf=pass smtp.mailfrom=a@example.com; dkim=fail header.d=example.com; dkim=pass header.d=other.example; dmarc=PASS; arc=none'
        ],
        'received-spf': ['Softfail (mx.example.com: domain of a@example.com does not designate 192.0.2.1 as permitted sender)'],
    }

    assert eml_parser.headers.authentication_results(header) == {
        'spf': ['pass', 'softfail'],
        'dkim': ['fail', 'pass'],
        'dmarc': ['pass'],
        'arc': ['none'],
    }


def test_reported_in_header() -> None:
    """The results are part of the header; the key is absent without such headers."""
    parser = eml_parser.parser.EmlParser()
    mail = b'Date: Mon, 1 Jan 2024 00:00:00 +0000\r\nFrom: a@example.com\r\n%s\r\n\r\nbody'
    failing = parser.decode_email_bytes(mail % b'Authentication-Results: mx.example.com; spf=fail; dkim=pass; dmarc=fail')['header']
    plain = parser.decode_email_bytes(mail % b'Subject: s')['header']

    assert failing['authentication'] == {'spf': ['fail'], 'dkim': ['pass'], 'dmarc': ['fail']}
    assert 'authentication' not in plain


def test_deeply_nested_comments_are_cheap() -> None:
    """Hundreds of thousands of nested parentheses must not cost one pass over the header per level."""
    header = {'authentication-results': ['(' * 300_000 + ')' * 300_000 + ' spf=pass']}

    start = time.monotonic()
    result = eml_parser.headers.authentication_results(header)

    assert result == {'spf': ['pass']}
    assert time.monotonic() - start < 2


RAW_EMAIL = (
    b'From: a@example.com\r\nTo: b@example.com\r\nSubject: hi\r\nX-First: 1\r\nX-Second: 2\r\n'
    b'X-Third: 3\r\nMessage-ID: <1@example.com>\r\nX-Fourth: 4\r\n\r\nbody'
)

SCRIPT = """
import json, sys
import eml_parser.parser
raw = sys.stdin.buffer.read()
print(json.dumps(list(eml_parser.parser.EmlParser().decode_email_bytes(raw)['header']['header'])))
"""


def test_header_order_follows_the_message() -> None:
    parsed = eml_parser.parser.EmlParser().decode_email_bytes(RAW_EMAIL)

    assert list(parsed['header']['header']) == ['from', 'to', 'subject', 'x-first', 'x-second', 'x-third', 'message-id', 'x-fourth']


def test_header_order_is_independent_of_hash_seed() -> None:
    results = set()

    for seed in ('0', '1', '2', '123', '4242'):
        env = {**os.environ, 'PYTHONHASHSEED': seed, 'PYTHONPATH': os.pathsep.join(sys.path)}
        out = subprocess.run([sys.executable, '-c', SCRIPT], input=RAW_EMAIL, capture_output=True, check=True, env=env)  # noqa: S603
        results.add(tuple(json.loads(out.stdout)))

    assert len(results) == 1


def test_header_names_differing_only_in_case_are_not_duplicated() -> None:
    raw_email = b'From: a@example.com\r\nX-Foo: one\r\nx-foo: two\r\n\r\nbody'

    parsed = eml_parser.parser.EmlParser().decode_email_bytes(raw_email)

    assert parsed['header']['header']['x-foo'] == ['one', 'two']


# Each line made the stdlib parsers raise: an IndexError in the address parser, an AttributeError or TypeError for 8-bit values.
MALFORMED_LINES = [
    b'Cc: "',
    b'Reply-To: "',
    b'To: x:"',
    b'Cc: :;]Test.=E9;=\xffbq;? q',
    b'To: \xff:?];=?',
    b'Sender: \xff:?];=?',
]

TOP_LEVEL = b'From: a@b.example\n%s\nSubject: s\n\nbody\n'
IN_ATTACHMENT = b"""From: a@b.example
Content-Type: multipart/mixed; boundary=X

--X
Content-Type: text/plain

body
--X
Content-Type: application/octet-stream
Content-Disposition: attachment; filename=a.bin
%s

AAAA
--X--
"""


def test_malformed_header_lines_are_collected() -> None:
    def check(line: bytes) -> None:
        name = line.partition(b':')[0].decode().lower()
        parser = eml_parser.parser.EmlParser()

        top_level = parser.decode_email_bytes(TOP_LEVEL % line)
        in_attachment = parser.decode_email_bytes(IN_ATTACHMENT % line)

        assert all(isinstance(value, str) for value in top_level['header']['header'][name])
        assert all(isinstance(value, str) for value in in_attachment['attachment'][0]['content_header'][name])
        eml_parser.decode.export_to_json(top_level)

    tests.table.assert_all_cases(check, MALFORMED_LINES)


def test_addresses_are_recovered_from_8bit_address_fields() -> None:
    # Arrange
    raw = b'From: x\xff:? <a@b.example>\nTo: y\xff:?;\xff <c@d.example>\nSubject: s\n\nbody\n'

    # Act
    header = eml_parser.parser.EmlParser().decode_email_bytes(raw)['header']

    # Assert
    assert header['from'] == 'a@b.example'
    assert header['to'] == ['c@d.example']


def test_header_items_falls_back_to_compat32() -> None:
    # Arrange
    msg = email.message_from_bytes(b'Cc: "\nSubject: s\n\nbody\n', policy=email.policy.default)

    # Act
    items = eml_parser.headers.header_items(msg)

    # Assert
    assert items == [('Cc', '"'), ('Subject', 's')]
    assert msg.policy is email.policy.default


def test_deeply_nested_address_groups_do_not_exhaust_the_stack() -> None:
    # Arrange: every colon opens a group, the stdlib address parser recurses once per group
    nested = b'a:' * 5000 + b'x@y.example'
    raw = b'From: ' + nested + b'\nTo: ' + nested + b'\n\nbody\n'

    # Act
    header = eml_parser.parser.EmlParser().decode_email_bytes(raw)['header']

    # Assert
    assert header['from'] == 'x@y.example'
    assert header['to'] == ['x@y.example']


def test_workaround_bug_27257_addresses_are_unique_and_ordered() -> None:
    msg = email.message_from_bytes(b'To: b@example.org, a@example.com, b@example.org\r\n\r\nbody')

    assert eml_parser.headers.regex_addresses(msg, 'to', eml_parser.regexes.email_no_force_tld_regex) == ['b@example.org', 'a@example.com']


@pytest.mark.parametrize('raw', [b'From:=??q?=0A\xcd', b' \nCc:=?\xd5?q?=0D'])
def test_malformed_encoded_address_headers_do_not_raise(raw: bytes) -> None:
    """Encoded words which decode to line breaks or to the wrong type must not make the parser fail."""
    assert eml_parser.parser.EmlParser().decode_email_bytes(raw)


SAMPLES = pathlib.Path(__file__).resolve().parent.parent / 'samples'


def _to_addresses(msg: email.message.Message) -> list[str]:
    return eml_parser.headers.addresses(msg, 'to', eml_parser.regexes.email_no_force_tld_regex, email_force_tld=False)


def test_addresses() -> None:
    # Arrange
    msg = email.message.EmailMessage()
    msg['To'] = (email.headerregistry.Address('Jané Doe', 'jane.doe', 'example.com'), email.headerregistry.Address('James Doe', 'james.doe', 'example.com'))

    # Act
    found = _to_addresses(msg)

    # Assert
    assert found == ['jane.doe@example.com', 'james.doe@example.com']


def test_addresses_of_a_value_the_stdlib_fails_on() -> None:
    # Arrange: an unquoted display name ending in a period raises in the stdlib address parser of some Python versions (bug 27257)
    msg = email.message_from_bytes((SAMPLES / 'sample_bug27257.eml').read_bytes(), policy=email.policy.default)

    # Act
    found = _to_addresses(msg)

    # Assert
    assert found == ['test@example.com']


def test_addresses_fall_back_to_regex_if_the_header_class_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange: some Python versions raise a ValueError in get_all() for the value, then the header class of the stdlib
    # (which fails on it as well) is tried on the compat32 values
    msg = email.message_from_bytes((SAMPLES / 'sample_bug27257.eml').read_bytes(), policy=email.policy.default)
    original_get_all = email.message.Message.get_all

    def get_all_raising_with_the_default_policy(self: email.message.Message, *args: typing.Any, **kwargs: typing.Any) -> typing.Any:
        if self.policy is email.policy.default:
            raise ValueError('forced for test')
        return original_get_all(self, *args, **kwargs)

    monkeypatch.setattr(email.message.Message, 'get_all', get_all_raising_with_the_default_policy)

    # Act
    found = _to_addresses(msg)

    # Assert
    assert found == ['test@example.com']


def test_using_policy_restores_the_policy_also_on_exception() -> None:
    # Arrange
    msg = email.message_from_bytes(b'Subject: x\n\nbody', policy=email.policy.default)

    # Act
    with eml_parser.headers.using_policy(msg, email.policy.compat32) as patched:
        policy_inside = patched.policy
    policy_after_exit = msg.policy

    with pytest.raises(ValueError, match='boom'), eml_parser.headers.using_policy(msg, email.policy.compat32):
        raise ValueError('boom')

    # Assert
    assert policy_inside is email.policy.compat32
    assert policy_after_exit is email.policy.default
    assert msg.policy is email.policy.default


def test_raw_items_are_not_parsed() -> None:
    # Arrange
    msg = email.message_from_bytes(b'Subject: =?utf-8?q?h=C3=A9llo?=\nTo: "a" <a@b.example>\n\nbody', policy=email.policy.default)

    # Act
    items = eml_parser.headers.raw_items(msg)

    # Assert
    assert items == [('Subject', '=?utf-8?q?h=C3=A9llo?='), ('To', '"a" <a@b.example>')]
    assert msg.policy is email.policy.default


def test_sender_which_the_address_parser_fails_on_is_replaced() -> None:
    # Arrange: an unterminated quote makes the stdlib address parser raise (bug 27257)
    raw = b'From: "\nTo: b@example.com\n\nbody'

    # Act
    header = eml_parser.parser.EmlParser().decode_email_bytes(raw)['header']

    # Assert
    assert 'from' not in header
    assert header['to'] == ['b@example.com']


def test_sender_falls_back_to_the_compat32_value(monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange: some Python versions raise a ValueError for malformed values, then the raw value is decoded
    msg = email.message_from_bytes(b'From: =?utf-8?q?J=C3=B6rg?= <joerg@example.com>\n\nbody', policy=email.policy.default)
    original_get = email.message.Message.get

    def get_raising_with_the_default_policy(self: email.message.Message, name: str, failobj: typing.Any = None) -> typing.Any:
        if self.policy is email.policy.default and name == 'from':
            raise ValueError('forced for test')
        return original_get(self, name, failobj)

    monkeypatch.setattr(email.message.Message, 'get', get_raising_with_the_default_policy)

    # Act
    sender = eml_parser.headers.sender(msg, eml_parser.regexes.email_no_force_tld_regex)

    # Assert
    assert sender == 'joerg@example.com'
