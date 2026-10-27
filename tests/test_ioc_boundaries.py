"""Tests for false positive IP addresses and hosts."""

import typing
import urllib.parse

import pytest

import eml_parser.constants
import eml_parser.parser
import eml_parser.regexes
import tests.table

IPV4_INSIDE_LONGER_TOKENS_CASES = ['1.2.3.4.5', 'v1.2.3.4', '1.2.3.45678', '1.2.3.4.nip.io', 'a1.2.3.4']


def test_ipv4_inside_longer_tokens() -> None:
    """Parts of longer dotted tokens are not addresses."""

    def check(text: str) -> None:
        assert eml_parser.regexes.ipv4_regex.findall(text) == []

    tests.table.assert_all_cases(check, IPV4_INSIDE_LONGER_TOKENS_CASES)


IPV4_IN_NORMAL_CONTEXT_CASES = ['1.2.3.4', 'ip 1.2.3.4.', '(1.2.3.4)', 'ip=1.2.3.4,', '[1.2.3.4]']


def test_ipv4_in_normal_context() -> None:
    """Addresses in sentences, brackets and key=value pairs are still found."""

    def check(text: str) -> None:
        assert eml_parser.regexes.ipv4_regex.findall(text) == ['1.2.3.4']

    tests.table.assert_all_cases(check, IPV4_IN_NORMAL_CONTEXT_CASES)


IPV6_INSIDE_LONGER_TOKENS_CASES = ['std::vector', '1:2:3:4:5:6:7:8:9', 'a.b::1']


def test_ipv6_inside_longer_tokens() -> None:
    """C++ scopes and longer colon separated sequences are not addresses."""

    def check(text: str) -> None:
        assert eml_parser.regexes.ipv6_regex.findall(text) == []

    tests.table.assert_all_cases(check, IPV6_INSIDE_LONGER_TOKENS_CASES)


IPV6_IN_NORMAL_CONTEXT_CASES = ['at 2001:db8::1 now', '(::1)', 'IPv6:2001:db8::1']


def test_ipv6_in_normal_context() -> None:
    """Real addresses, also in brackets and address literals."""

    def check(text: str) -> None:
        assert len(eml_parser.regexes.ipv6_regex.findall(text)) == 1

    tests.table.assert_all_cases(check, IPV6_IN_NORMAL_CONTEXT_CASES)


NUMERIC_TLD_IS_NOT_A_HOST_CASES = ['999.1.1.1', 'v1.20.30', '01.02.03.04']


def test_numeric_tld_is_not_a_host() -> None:
    """A numeric last label is not a top level domain."""

    def check(host: str) -> None:
        assert eml_parser.parser.EmlParser().get_valid_domain_or_ip(host) is None

    tests.table.assert_all_cases(check, NUMERIC_TLD_IS_NOT_A_HOST_CASES)


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


DOMAIN_BOUNDARIES_CASES = [
    'http://evil.example.com:8080/x',
    'user:pw@evil.example.com:8080',
    'see http://evil.example.com./x',
    'Please visit evil.example.com.',
    'visit evil.example.com... now',
    'visit evil.example.com, then',
    'visit evil.example.com; then',
    'visit evil.example.com! now',
    'visit evil.example.com: now',
    'see evil.example.com?x',
    'x=evil.example.com&y',
    'visit "evil.example.com" now',
    'visit [evil.example.com] now',
    'visit {evil.example.com} now',
    'visit *evil.example.com* now',
    'visit `evil.example.com` now',
    'visit “evil.example.com” now',
    'visit «evil.example.com» now',
    'visit evil.example.com&nbsp;now',
    'visit evil.example.com&amp;x',
    '&lt;evil.example.com&gt;',
    '访问evil.example.com立即',
    'サーバーevil.example.comへ',
    'เข้าevil.example.comเลย',
    'evil.example.com에서 확인',
    'visit evil.example.com\u3002',
    'visit\u00a0evil.example.com\u3000now',
]


def test_domain_boundaries() -> None:
    """Ports, a trailing dot, punctuation, entities and text in scripts without word spacing around a domain do not hide it."""

    def check(text: str) -> None:
        assert eml_parser.regexes.dom_regex.findall(text) == ['evil.example.com']

    tests.table.assert_all_cases(check, DOMAIN_BOUNDARIES_CASES)


DOMAIN_WITH_ONE_CHARACTER_LABEL_CASES = ['www.a.example.com', 'a.b.example.com', 'x.co', 'x.xn--p1ai']


def test_domain_with_one_character_label() -> None:
    """Only the last label needs two characters, punycode included."""

    def check(text: str) -> None:
        assert eml_parser.regexes.dom_regex.findall(f'see {text}/x') == [text]

    tests.table.assert_all_cases(check, DOMAIN_WITH_ONE_CHARACTER_LABEL_CASES)


DOMAIN_BOUNDARIES_NEGATIVE_CASES = [
    'e.g. this',
    'i.e. that',
    'at 10 a.m. and',
    'U.S.A',
    'a.b',
    'see 192.168.189.66 now',
    'from [192.168.189.66] by',
    'release 2024.10.25',
    'font-size: 10.0pt;',
    'sendmail 8.9.1a',
    'foo_bar.example',
    'mail vince.j.kaminski@',
    'src="other.example&#46;com"',
    'src="other.example&#x2E;com"',
    'src="other&period;example.com"',
    'u=https%3A%2F%2Fevil.example.com%2F',
]


def test_domain_boundaries_negative() -> None:
    """Abbreviations, IP addresses, version numbers, sizes, local parts and tokens glued to an encoded dot or "%" are not domains."""

    def check(text: str) -> None:
        assert eml_parser.regexes.dom_regex.findall(text) == []

    tests.table.assert_all_cases(check, DOMAIN_BOUNDARIES_NEGATIVE_CASES)


def test_domain_boundaries_in_body() -> None:
    """The domain of a URL with a port, a domain ending a sentence and a domain followed by an entity are reported, IP addresses are not."""
    raw = b'From: a@example.com\r\nContent-Type: text/html\r\n\r\n<p>Log in at http://login.example.com:8443/ or visit evil.example.net.</p><p>[192.168.1.10] www.a.example.org&nbsp;now</p>'
    body = eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(raw)['body'][0]

    assert set(body['domain']) == {'login.example.com', 'evil.example.net', 'www.a.example.org'}


def test_domain_of_encoded_redirect_target() -> None:
    """The domain of a percent-encoded URL in the query of a redirector is reported."""
    raw = b'From: a@example.com\r\n\r\nhttps://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example.com%2Flogin&data=05'
    body = eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(raw)['body'][0]

    assert set(body['domain']) == {'eur01.safelinks.protection.outlook.com', 'evil.example.com'}


# Characters which continue a word: an ASCII token touching one is the fragment of a longer word (Cyrillic, Greek and Latin letters,
# full width letters, a combining mark, non-ASCII digits and format characters which browsers drop from host names).
WORD_CONTINUING_CHARACTERS = ['а', 'ε', 'ü', 'ß', 'ａ', '\u0301', '٣', '\u200b', '\u00ad', '\u2060', '\ufeff']
# Characters which end a token: white space, punctuation and scripts which do not put a space before or after an ASCII token.
TOKEN_ENDING_CHARACTERS = [' ', '\u00a0', '\u3000', '\u3002', '«', '访', 'ー', 'ภ', '에']
EMAIL_REGEXES = [eml_parser.regexes.email_no_force_tld_regex, eml_parser.regexes.email_force_tld_regex]


DOMAIN_FRAGMENT_TEMPLATES = ['{}evil.example.com', 'evil.example.com{}', 'evil{}example.com', 'evil.ex{}ample.com', 'evil.example.{}com']
EMAIL_FRAGMENT_TEMPLATES = [
    '{}john@example.com',
    'jo{}hn@example.com',
    'john.d{}e@example.com',
    'john@{}example.com',
    'john@ex{}ample.com',
    'john@example.com{}',
]


def test_domain_fragment_of_longer_word() -> None:
    """A domain glued to a word character is part of a longer (non-ASCII) word: no fragment like "mple.com" of "exаmple.com" is reported."""
    texts = [template.format(character) for template in DOMAIN_FRAGMENT_TEMPLATES for character in WORD_CONTINUING_CHARACTERS]

    assert {text: found for text in texts if (found := eml_parser.regexes.dom_regex.findall(f'visit {text} now'))} == {}


def test_domain_next_to_token_ending_character() -> None:
    """The counterpart of `test_domain_fragment_of_longer_word`: characters which end a token do not hide the domain."""
    texts = [f'{character}evil.example.com{character}' for character in TOKEN_ENDING_CHARACTERS]

    assert {text: found for text in texts if (found := eml_parser.regexes.dom_regex.findall(text)) != ['evil.example.com']} == {}


@pytest.mark.parametrize('pattern', EMAIL_REGEXES)
def test_email_fragment_of_longer_word(pattern: typing.Any) -> None:
    """An address containing or touching a word character is not cut into a fragment like "ller@example.com" or "user@b"."""
    texts = [template.format(character) for template in EMAIL_FRAGMENT_TEMPLATES for character in WORD_CONTINUING_CHARACTERS]

    assert {text: found for text in texts if (found := pattern.findall(f'mail {text} now'))} == {}


@pytest.mark.parametrize('pattern', EMAIL_REGEXES)
def test_email_next_to_token_ending_character(pattern: typing.Any) -> None:
    """The counterpart of `test_email_fragment_of_longer_word`."""
    texts = [f'{character}john.doe@example.com{character}' for character in TOKEN_ENDING_CHARACTERS]

    assert {text: found for text in texts if (found := pattern.findall(text)) != ['john.doe@example.com']} == {}


@pytest.mark.parametrize('pattern', EMAIL_REGEXES)
def test_email_local_part_is_not_cut(pattern: typing.Any) -> None:
    """A local part beyond the length limit yields no address made of its last characters."""
    assert pattern.findall(f'{"a" * 200}@example.com') == []
    assert pattern.findall(f'{"a" * 100}@example.com') == [f'{"a" * 100}@example.com']


# Expected hosts as resolved by the WHATWG URL parser of browsers (`new URL(url).hostname`, checked with Node.js 20). The parser must
# neither report a host a browser would not contact nor miss one it would.
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
# Hosts which browsers reject (misplaced joiner, bidi control, leading combining mark, forbidden code point).
BROWSER_REJECTED_HOSTS = ['exam\u200cple.com', 'exam\u202eple.com', '\u0301a.com', 'a%2fb.com', 'exa mple.com']


def test_ascii_host_like_browsers() -> None:
    hosts = {url: eml_parser.parser.EmlParser.get_ascii_host(urllib.parse.urlparse(url).hostname or '') for url in BROWSER_HOSTS}

    assert hosts == BROWSER_HOSTS


def test_ascii_host_rejected_like_browsers() -> None:
    assert {host: eml_parser.parser.EmlParser.get_ascii_host(host) for host in BROWSER_REJECTED_HOSTS} == dict.fromkeys(BROWSER_REJECTED_HOSTS)


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
