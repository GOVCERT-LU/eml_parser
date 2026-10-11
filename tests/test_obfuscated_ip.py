"""Tests for IPv4 addresses in obfuscated URL hosts."""

import pytest

import eml_parser.parser


@pytest.mark.parametrize(
    'host',
    ['3232235777', '0xC0A80101', '192.168.257', '0xC0.0xA8.1.1'],
)
def test_get_obfuscated_ip(host: str) -> None:
    """All notations resolve like in a browser."""
    assert eml_parser.parser.EmlParser().get_obfuscated_ip(host) == '192.168.1.1'


def test_octal_parts() -> None:
    """Parts with a leading zero are octal."""
    assert eml_parser.parser.EmlParser().get_obfuscated_ip('0300.0250.0.1') == '192.168.0.1'


@pytest.mark.parametrize('host', ['example.com', 'deface.cafe', '0x', '08', '1.2.3.4.5', '256.1.1.1', '12345678901'])
def test_get_obfuscated_ip_rejects(host: str) -> None:
    """Names and invalid numbers are not addresses."""
    assert eml_parser.parser.EmlParser().get_obfuscated_ip(host) is None


def test_body_extraction() -> None:
    """The URL is reported and its address is added to the observed IPs."""
    raw = b'From: a@example.com\r\n\r\nclick http://3232235777/login or http://0xC0A80102:8080/x now'
    body = eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(raw)['body'][0]

    assert body['uri'] == ['http://3232235777/login', 'http://0xC0A80102:8080/x']
    assert body['ip'] == ['192.168.1.1', '192.168.1.2']


def test_ip_force_routable_applies() -> None:
    """Private addresses are dropped when only routable ones are wanted."""
    assert eml_parser.parser.EmlParser(ip_force_routable=True).get_obfuscated_ip('3232235777') is None
    assert eml_parser.parser.EmlParser(ip_force_routable=True).get_obfuscated_ip('0x08080808') == '8.8.8.8'
