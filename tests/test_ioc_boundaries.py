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
