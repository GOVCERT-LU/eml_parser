import hashlib

import eml_parser.parser

RAW_EMAIL = b'From: a@example.com\r\nSubject: s\r\n\r\nvisit www.Evil.example.com/Path and http://other.example.org/x'


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def test_raw_mode_reports_uri_noscheme() -> None:
    body = eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(RAW_EMAIL)['body'][0]

    assert body['uri_noscheme'] == ['www.Evil.example.com/Path']
    assert body['uri'] == ['http://other.example.org/x']


def test_hashed_mode_reports_uri_noscheme_hash() -> None:
    body = eml_parser.parser.EmlParser().decode_email_bytes(RAW_EMAIL)['body'][0]

    assert body['uri_noscheme_hash'] == [_sha256('www.evil.example.com/path')]
    assert body['uri_hash'] == [_sha256('http://other.example.org/x')]
    assert 'uri_noscheme' not in body


def test_hashed_mode_without_noscheme_urls_has_no_key() -> None:
    body = eml_parser.parser.EmlParser().decode_email_bytes(b'From: a@example.com\r\n\r\nhttp://other.example.org/x')['body'][0]

    assert 'uri_noscheme_hash' not in body
