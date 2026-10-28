"""Tests for `eml_parser.hosts`: domains, IP addresses in any notation, host names like browsers resolve them and the IP whitelist."""

import ipaddress
import urllib.parse

import pytest

import eml_parser.constants
import eml_parser.hosts
import eml_parser.parser
import tests.table

HOSTS = eml_parser.hosts.HostValidator(domain_force_tld=False, ip_force_routable=False)
ROUTABLE_HOSTS = eml_parser.hosts.HostValidator(domain_force_tld=False, ip_force_routable=True)


def test_cache_is_used_and_per_instance() -> None:
    """Repeated hosts hit the cache and instances with different settings do not share verdicts."""
    loose = eml_parser.hosts.HostValidator(domain_force_tld=False, ip_force_routable=False)
    strict = eml_parser.hosts.HostValidator(domain_force_tld=True, ip_force_routable=False)

    assert loose.valid_domain_or_ip('host.invalidtld') == 'host.invalidtld'
    assert loose.valid_domain_or_ip('host.invalidtld') == 'host.invalidtld'
    assert loose._cached_valid_domain_or_ip.cache_info().hits == 1  # noqa: SLF001
    assert strict.valid_domain_or_ip('host.invalidtld') is None


OBFUSCATED_IP_CASES = ['3232235777', '0xC0A80101', '192.168.257', '0xC0.0xA8.1.1']


def test_obfuscated_ip() -> None:
    """All notations resolve like in a browser."""

    def check(host: str) -> None:
        assert HOSTS.obfuscated_ip(host) == '192.168.1.1'

    tests.table.assert_all_cases(check, OBFUSCATED_IP_CASES)


def test_octal_parts() -> None:
    """Parts with a leading zero are octal."""
    assert HOSTS.obfuscated_ip('0300.0250.0.1') == '192.168.0.1'


OBFUSCATED_IP_REJECTS_CASES = ['example.com', 'deface.cafe', '0x', '08', '1.2.3.4.5', '256.1.1.1', '12345678901']


def test_obfuscated_ip_rejects() -> None:
    """Names and invalid numbers are not addresses."""

    def check(host: str) -> None:
        assert HOSTS.obfuscated_ip(host) is None

    tests.table.assert_all_cases(check, OBFUSCATED_IP_REJECTS_CASES)


def test_obfuscated_ip_in_body() -> None:
    """The URL is reported and its address is added to the observed IPs."""
    raw = b'From: a@example.com\r\n\r\nclick http://3232235777/login or http://0xC0A80102:8080/x now'
    body = eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(raw)['body'][0]

    assert body['uri'] == ['http://3232235777/login', 'http://0xC0A80102:8080/x']
    assert body['ip'] == ['192.168.1.1', '192.168.1.2']


def test_ip_force_routable_applies() -> None:
    """Private addresses are dropped when only routable ones are wanted."""
    assert ROUTABLE_HOSTS.obfuscated_ip('3232235777') is None
    assert ROUTABLE_HOSTS.obfuscated_ip('0x08080808') == '8.8.8.8'


MESSAGE = b"""Received: from relay.example.net ([2001:db8:0:0::1]) by mx.example.com; Mon, 1 Jan 2024 10:00:00 +0000
Received: from other.example.net ([192.0.2.7]) by mx.example.com; Mon, 1 Jan 2024 09:00:00 +0000
From: a@example.org
To: b@example.com

Hosts ::ffff:192.0.2.1, 2001:DB8::1, 198.51.100.7 and fe80::1%eth0.
"""

NORMALIZED_IP_CASES = [
    ('192.0.2.1', ipaddress.ip_address('192.0.2.1')),
    ('::ffff:192.0.2.1', ipaddress.ip_address('192.0.2.1')),
    ('2001:DB8:0:0::1', ipaddress.ip_address('2001:db8::1')),
    ('[2001:db8::1]', ipaddress.ip_address('2001:db8::1')),
    ('fe80::1%eth0', ipaddress.ip_address('fe80::1')),
    ('mx.example.com', None),
    ('', None),
]


def test_normalized_ip() -> None:
    def check(text: str, expected: ipaddress.IPv4Address | ipaddress.IPv6Address | None) -> None:
        assert eml_parser.hosts.normalized_ip(text) == expected

    tests.table.assert_all_cases(check, NORMALIZED_IP_CASES)


def test_whitelisted_ips_match_in_any_notation() -> None:
    # Arrange
    parser = eml_parser.parser.EmlParser(include_raw_body=True, pconf={'whiteip': ['2001:DB8::1', '192.0.2.1', 'fe80::1']})

    # Act
    parsed = parser.decode_email_bytes(MESSAGE)

    # Assert
    assert parsed['header']['received_ip'] == ['192.0.2.7']
    assert parsed['body'][0]['ip'] == ['198.51.100.7']


def test_whitelisted_ips_given_as_in_the_text_still_match() -> None:
    # Arrange
    parser = eml_parser.parser.EmlParser(include_raw_body=True, pconf={'whiteip': ['192.0.2.7', '198.51.100.7']})

    # Act
    parsed = parser.decode_email_bytes(MESSAGE)

    # Assert
    assert parsed['header']['received_ip'] == ['2001:db8::1']
    assert '198.51.100.7' not in parsed['body'][0]['ip']


NUMERIC_TLD_IS_NOT_A_HOST_CASES = ['999.1.1.1', 'v1.20.30', '01.02.03.04']


def test_numeric_tld_is_not_a_host() -> None:
    """A numeric last label is not a top level domain."""

    def check(host: str) -> None:
        assert HOSTS.valid_domain_or_ip(host) is None

    tests.table.assert_all_cases(check, NUMERIC_TLD_IS_NOT_A_HOST_CASES)


def test_extension_which_is_a_tld_is_not_a_file_name(monkeypatch: pytest.MonkeyPatch) -> None:
    """An extension turns into a domain as soon as it is a TLD (here: zip), without touching the table."""
    monkeypatch.setattr(eml_parser.constants, 'FILE_EXTENSIONS', eml_parser.constants.FILE_EXTENSIONS | {'zip'})
    hosts = eml_parser.hosts.HostValidator(domain_force_tld=False, ip_force_routable=False)

    assert hosts.is_file_name('invoice.pdf')
    assert not hosts.is_file_name('evil.zip')


BROWSER_HOSTS = {
    'http://пример.example/login': 'xn--e1afmkfd.example',
    'http://ПРИМЕР.EXAMPLE/login': 'xn--e1afmkfd.example',
    'http://exаmple.com/login': 'xn--exmple-4nf.com',
    'http://exämple.de/': 'xn--exmple-cua.de',
    'http://exampleß.de/': 'xn--example-6va.de',
    'https://💌.example.com/': 'xn--rr8h.example.com',
    'http://ｅxample.com/': 'example.com',
    'http://exam\u200bple.com/x': 'example.com',
    'http://exam\u00adple.com/x': 'example.com',
    'http://exam\u2060ple.com/x': 'example.com',
    'http://example\u3002com/x': 'example.com',
    'http://example\uff0ecom/x': 'example.com',
    'http://example\uff61com/x': 'example.com',
    'http://ب\u200cا.example/': 'xn--mgbb899q.example',
    'http://%D0%BF%D1%80%D0%B8%D0%BC%D0%B5%D1%80.example/': 'xn--e1afmkfd.example',
    'http://ex%61mple.com/': 'example.com',
}


BROWSER_REJECTED_HOSTS = ['exam\u200cple.com', 'exam\u202eple.com', '\u0301a.com', 'a%2fb.com', 'exa mple.com']


def test_ascii_host_like_browsers() -> None:
    hosts = {url: eml_parser.hosts.ascii_host(urllib.parse.urlparse(url).hostname or '') for url in BROWSER_HOSTS}

    assert hosts == BROWSER_HOSTS


def test_ascii_host_rejected_like_browsers() -> None:
    assert {host: eml_parser.hosts.ascii_host(host) for host in BROWSER_REJECTED_HOSTS} == dict.fromkeys(BROWSER_REJECTED_HOSTS)


def body_domains(text: str, subtype: str) -> list[str] | None:
    """The domains reported for a message body."""
    raw = f'From: a@example.com\r\nContent-Type: text/{subtype}; charset=utf-8\r\n\r\n{text}\r\n'.encode()
    return eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(raw)['body'][0].get('domain')


def test_body_domain_of_url_is_browser_host() -> None:
    """The domain of a link, in text or in an attribute, is the host a browser contacts, never a fragment of it."""
    expected = {template.format(url): [host] for url, host in BROWSER_HOSTS.items() for template in ('{}', '<a href="{}">login</a>')}

    assert {text: body_domains(text, 'html') for text in expected} == expected


def test_body_no_domain_for_rejected_host() -> None:
    hosts = BROWSER_REJECTED_HOSTS[:3]

    assert {host: body_domains(f'http://{host}/login', 'plain') for host in hosts} == dict.fromkeys(hosts)


def test_body_reported_non_ascii_indicators() -> None:
    """The cases of the report: IDN and homograph links give the browser host, non-ASCII addresses give no fragment."""
    text = 'http://пример.example/login http://exаmple.com/login http://exam\u200bple.com/x user@exämple.de jörg@example.com'
    raw = f'From: a@b.com\n\n{text}\n'.encode()

    body = eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(raw)['body'][0]

    assert set(body['domain']) == {'xn--e1afmkfd.example', 'xn--exmple-4nf.com', 'example.com'}
    assert 'email' not in body


SHARE_HOST_CASES = [
    ('no share', None),
    (r'\\attacker.example.com\share', 'attacker.example.com'),
    (r'\\evil.example.net@SSL\DavWWWRoot\x', 'evil.example.net'),
    (r'\\3232235777\c$', '192.168.1.1'),
    (r'\\2001-db8--1.ipv6-literal.net\s', '2001:db8::1'),
    (r'\\fileserver\public', None),
    ('file://localhost/x', None),
]


def test_share_host() -> None:
    """The host is an indicator only if it is a domain or an address."""

    def check(share: str, expected: str | None) -> None:
        assert HOSTS.share_host(share) == expected

    tests.table.assert_all_cases(check, SHARE_HOST_CASES)


def test_ip_whitelist() -> None:
    # Arrange
    whitelist = eml_parser.hosts.IpWhitelist.from_entries(['2001:DB8::1', '192.0.2.1', 'mx.example.com'])

    # Act
    listed = [ip in whitelist for ip in ('2001:db8::1', '::ffff:192.0.2.1', '[192.0.2.1]', 'mx.example.com', '192.0.2.2')]

    # Assert
    assert listed == [True, True, True, True, False]
