"""Tests for URLs in HTML attributes."""

import pytest

import eml_parser.decode
import eml_parser.parser


def _uris(html: str) -> list[str]:
    raw = f'From: a@example.com\r\nContent-Type: text/html\r\n\r\n{html}'.encode()

    body = eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(raw)['body'][0]

    return body.get('uri', []) + body.get('uri_noscheme', [])


@pytest.mark.parametrize(
    'html',
    [
        '<a href="http://evil.example.com/login">x</a>',
        '<form method=post action="http://evil.example.com/login">',
        '<button formaction="http://evil.example.com/login">',
        '<iframe width=1 src="http://evil.example.com/login"></iframe>',
        '<script src="http://evil.example.com/login"></script>',
        '<link rel=stylesheet href="http://evil.example.com/login">',
        '<object data="http://evil.example.com/login"></object>',
        '<body background="http://evil.example.com/login">',
        '<svg><use xlink:href="http://evil.example.com/login"/></svg>',
        '<meta http-equiv="refresh" content="0; url=http://evil.example.com/login">',
    ],
)
def test_url_in_attribute(html: str) -> None:
    """Each of these tags hides a URL which must be reported."""
    assert _uris(html) == ['http://evil.example.com/login']


@pytest.mark.parametrize(
    'value',
    [
        'http://evil.example.com/login',
        'ht&#9;tp://evil.example.com/login',
        'http:&#47;&#47;evil.example.com/login',
        'ht\ntp://evil.example.com/login',
        'http:\\\\evil.example.com\\login',
        'http://evil.example.com/log\tin',
    ],
)
def test_browser_style_normalisation(value: str) -> None:
    """Obfuscations which browsers undo before using the URL."""
    assert 'http://evil.example.com/login' in _uris(f'<a href="{value}">x</a>')


def test_normalize_attribute_url_keeps_backslashes_in_query() -> None:
    """Only the part before the query string is converted."""
    assert eml_parser.decode.normalize_attribute_url('http:\\\\h.example.com\\p?a=b\\c') == 'http://h.example.com/p?a=b\\c'


def test_protocol_relative_and_relative_references() -> None:
    """`//host/x` is a host, `images/logo.png` and `page.html` are not."""
    assert _uris('<a href="//evil.example.com/x">x</a><img src="images/logo.png"><a href="page.html">p</a><a href="/local/path">l</a>') == [
        '//evil.example.com/x'
    ]


def test_unrelated_attributes_are_ignored() -> None:
    """A plain data attribute is not a URL."""
    assert _uris('<div data-x="http-like">text</div>') == []
