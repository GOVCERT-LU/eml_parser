"""Tests for the SPF / DKIM / DMARC results."""

import time

import eml_parser.parser


def test_parse_authentication_results() -> None:
    """Methods are collected, properties like header.d= and comments are not mistaken for methods."""
    header = {
        'authentication-results': [
            'mx.example.com (dkim=fail inside (nested) comment); spf=pass smtp.mailfrom=a@example.com; dkim=fail header.d=example.com; dkim=pass header.d=other.example; dmarc=PASS; arc=none'
        ],
        'received-spf': ['Softfail (mx.example.com: domain of a@example.com does not designate 192.0.2.1 as permitted sender)'],
    }

    assert eml_parser.parser.EmlParser.parse_authentication_results(header) == {
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
    result = eml_parser.parser.EmlParser.parse_authentication_results(header)

    assert result == {'spf': ['pass']}
    assert time.monotonic() - start < 2
