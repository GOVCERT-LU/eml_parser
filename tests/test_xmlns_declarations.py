"""Tests for namespace declarations not being reported as indicators."""

import pytest

import eml_parser.parser


def _parse(html: str) -> dict:
    raw = f'From: a@example.com\r\nContent-Type: text/html\r\n\r\n{html}\r\n'.encode()
    return eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(raw)


@pytest.mark.parametrize(
    'declaration',
    [
        'xmlns="http://www.w3.org/TR/REC-html40"',
        'xmlns:v=\'urn:schemas-microsoft-com:vml\' xmlns:o="http://schemas.microsoft.com/office/2004/12/omml"',
        'XMLNS:w = "http://schemas.microsoft.com/office/word/2003/wordml"',
    ],
)
def test_namespace_declaration_is_not_an_indicator(declaration: str) -> None:
    result = _parse(f'<html {declaration}><body><a href="http://evil.example.com/x">go</a></body></html>')
    body = result['body'][0]

    assert body['domain'] == ['evil.example.com']
    assert body['uri'] == ['http://evil.example.com/x']


def test_raw_body_keeps_the_declaration() -> None:
    result = _parse('<html xmlns="http://www.w3.org/1999/xhtml">x</html>')

    assert 'xmlns="http://www.w3.org/1999/xhtml"' in result['body'][0]['content']


def test_link_in_other_attribute_is_kept() -> None:
    result = _parse('<a href="http://www.w3.org/evil">x</a> <a xmlns="a" href="http://www.example.org/">y</a>')

    assert set(result['body'][0]['domain']) == {'www.w3.org', 'www.example.org'}
