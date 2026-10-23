"""Tests for false positive IP addresses and hosts."""

import pytest

import eml_parser.constants
import eml_parser.parser
import eml_parser.regexes


@pytest.mark.parametrize('text', ['1.2.3.4.5', 'v1.2.3.4', '1.2.3.45678', '1.2.3.4.nip.io', 'a1.2.3.4'])
def test_ipv4_inside_longer_tokens(text: str) -> None:
    """Parts of longer dotted tokens are not addresses."""
    assert eml_parser.regexes.ipv4_regex.findall(text) == []


@pytest.mark.parametrize('text', ['1.2.3.4', 'ip 1.2.3.4.', '(1.2.3.4)', 'ip=1.2.3.4,', '[1.2.3.4]'])
def test_ipv4_in_normal_context(text: str) -> None:
    """Addresses in sentences, brackets and key=value pairs are still found."""
    assert eml_parser.regexes.ipv4_regex.findall(text) == ['1.2.3.4']


@pytest.mark.parametrize('text', ['std::vector', '1:2:3:4:5:6:7:8:9', 'a.b::1'])
def test_ipv6_inside_longer_tokens(text: str) -> None:
    """C++ scopes and longer colon separated sequences are not addresses."""
    assert eml_parser.regexes.ipv6_regex.findall(text) == []


@pytest.mark.parametrize('text', ['at 2001:db8::1 now', '(::1)', 'IPv6:2001:db8::1'])
def test_ipv6_in_normal_context(text: str) -> None:
    """Real addresses, also in brackets and address literals."""
    assert len(eml_parser.regexes.ipv6_regex.findall(text)) == 1


@pytest.mark.parametrize('host', ['999.1.1.1', 'v1.20.30', '01.02.03.04'])
def test_numeric_tld_is_not_a_host(host: str) -> None:
    """A numeric last label is not a top level domain."""
    assert eml_parser.parser.EmlParser().get_valid_domain_or_ip(host) is None


def test_body_extraction() -> None:
    """File names, scope resolutions and "::" do not become indicators, real ones stay."""
    raw = b'From: a@example.com\r\n\r\nopen invoice.pdf and report.docx, call std::vector or Add::dead :: but visit evil.example.com and 2001:db8::1'
    body = eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(raw)['body'][0]

    assert body['domain'] == ['evil.example.com']
    assert body['ip'] == ['2001:db8::1']


def test_extension_which_is_a_tld_is_not_a_file_name(monkeypatch: pytest.MonkeyPatch) -> None:
    """An extension turns into a domain as soon as it is a TLD (here: zip), without touching the table."""
    monkeypatch.setattr(eml_parser.constants, 'FILE_EXTENSIONS', eml_parser.constants.FILE_EXTENSIONS | {'zip'})
    parser = eml_parser.parser.EmlParser()

    assert parser.is_file_name('invoice.pdf')
    assert not parser.is_file_name('evil.zip')


def test_file_name_in_url_path_is_not_a_domain() -> None:
    """The domains are also derived from the URLs found: a file name in the path is not one."""
    raw = b'From: a@example.com\r\n\r\nGet http://evil.example.com/dl/payload.docx now'
    body = eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(raw)['body'][0]

    assert body['domain'] == ['evil.example.com']


@pytest.mark.parametrize(
    ('text', 'expected'),
    [
        ('http://evil.example.com:8080/x', 'evil.example.com'),
        ('see www.a.example.com/x', 'www.a.example.com'),
        ('see http://a.b.example.com/', 'a.b.example.com'),
        ('see http://evil.example.com./x', 'evil.example.com'),
        ('Please visit evil.example.com.', 'evil.example.com'),
        ('visit evil.example.com, then', 'evil.example.com'),
        ('visit evil.example.com; then', 'evil.example.com'),
        ('visit evil.example.com! now', 'evil.example.com'),
        ('visit evil.example.com: now', 'evil.example.com'),
        ('visit "evil.example.com" now', 'evil.example.com'),
        ('visit [evil.example.com] now', 'evil.example.com'),
        ('visit *evil.example.com* now', 'evil.example.com'),
        ('visit “evil.example.com” now', 'evil.example.com'),
        ('visit «evil.example.com» now', 'evil.example.com'),
    ],
)
def test_domain_boundaries(text: str, expected: str) -> None:
    """Ports, one character labels, a trailing dot and common punctuation around a domain do not hide it."""
    assert eml_parser.regexes.dom_regex.findall(text) == [expected]


@pytest.mark.parametrize('text', ['e.g. this', 'i.e. that', 'at 10 a.m. and', 'U.S.A', 'src="other.example&#46;com"', 'a.b'])
def test_domain_boundaries_negative(text: str) -> None:
    """A one character last label is not a TLD and an HTML entity does not end a domain."""
    assert eml_parser.regexes.dom_regex.findall(text) == []


def test_domain_boundaries_in_body() -> None:
    """The domain of a URL with a port and a domain at the end of a sentence are reported."""
    raw = b'From: a@example.com\r\n\r\nLog in at http://login.example.com:8443/ or visit evil.example.net.'
    body = eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(raw)['body'][0]

    assert set(body['domain']) == {'login.example.com', 'evil.example.net'}
