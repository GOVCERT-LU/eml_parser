"""Tests for `eml_parser.indicators`: URLs, remote file shares, e-mail addresses, domains and IP addresses found in text."""

import hashlib
import typing

import pytest

import eml_parser.decode
import eml_parser.hosts
import eml_parser.indicators
import eml_parser.parser
import eml_parser.regexes
import tests.table


def find_urls(text: str, **settings: bool) -> list[str]:
    """The URLs found in a text with the given settings of `EmlParser` (its defaults for the others)."""
    options = {'include_www': True, 'include_href': True, 'domain_force_tld': False, 'ip_force_routable': False} | settings
    hosts = eml_parser.hosts.HostValidator(domain_force_tld=options['domain_force_tld'], ip_force_routable=options['ip_force_routable'])
    finder = eml_parser.indicators.IndicatorFinder(hosts, eml_parser.regexes.email_no_force_tld_regex, options['include_www'], options['include_href'])
    return finder.find_urls(text)


def test_find_urls() -> None:
    test_urls = """Lorem ipsum dolor sit amet, consectetur adipiscing elit.
    Mauris consectetur mi tortor, http://www.example.com consectetur iaculis orci ultricies sit amet.
    Mauris "http://www.example.com/test1?bla" ornare lobortis ex nec dictum. Aliquam blandit arcu ac lorem iaculis aliquet.
    Praesent a tempus dui, eu feugiat diam. Interdum http://www.example.com/a/b/c/d/ et malesuada fames ac ante ipsum primis in faucibus.
    Suspendisse ac rutrum leo, non vehicula purus. Quisque quis sapien lorem. Nunc velit enim, <img src=image.example.com/test.jpg>
    placerat quis vestibulum at, https://www.example2.com condimentum non velit."""

    expected_result = ['http://www.example.com', 'http://www.example.com/test1?bla', 'http://www.example.com/a/b/c/d/', 'https://www.example2.com']

    assert find_urls(test_urls, include_href=False) == expected_result


def test_find_urls_in_href() -> None:
    test_urls = """<html><body>Lorem ipsum dolor sit amet, consectetur adipiscing elit.
    Mauris consectetur mi tortor, <a href="example.com">consectetur iaculis</a> orci ultricies sit amet.
    <center><img src="http://47fee4f03182a2437d6d-359a8ec3a1ca7be00e972dc7374155\r\n16.r50.cf3.example.com/img1.jpg" />Play a cool game!
    Mauris <a href="example.com/test1?bla"><img src=image.example.com/test.jpg></a> ex nec dictum. Aliquam blandit arcu ac lorem iaculis aliquet.
    Praesent a tempus dui, eu feugiat diam. Interdum <a href="example.com/a/b/c/d/">et malesuada</a> fames ac ante ipsum primis in faucibus.
    Suspendisse ac rutrum leo, non vehicula purus. Quisque <a href="http://www.example.com?t1=v1&amp;t2=v2">quis</a> sapien lorem. Nunc velit enim,
    placerat quis vestibulum at, <a href="example2.com">condimentum </a> non velit.</html></body>"""

    expected_result = [
        'http://www.example.com?t1=v1&t2=v2',
        'example.com',
        'http://47fee4f03182a2437d6d-359a8ec3a1ca7be00e972dc737415516.r50.cf3.example.com/img1.jpg',
        'example.com/test1?bla',
        'image.example.com/test.jpg',
        'example.com/a/b/c/d/',
        'example2.com',
    ]

    assert find_urls(test_urls, include_href=True) == expected_result


def test_find_urls_separated_by_commas() -> None:
    test_urls = """
    http://www.example.com?t1=v1&t2=v2,https://www.example.com, http://www1.example.com?t1=v1&t2=v2, https://www1.example.com,
    http://www2.example.com,https://www3.example.com
    """

    expected_result = [
        'http://www.example.com?t1=v1&t2=v2',
        'https://www.example.com',
        'http://www1.example.com?t1=v1&t2=v2',
        'https://www1.example.com',
        'http://www2.example.com',
        'https://www3.example.com',
    ]

    assert find_urls(test_urls, include_www=True) == expected_result


def test_find_urls_with_valid_tld() -> None:
    test_urls = """<html><body>Lorem ipsum dolor sit amet, consectetur adipiscing elit.
    Mauris consectetur mi tortor, <a href="example.com">consectetur iaculis</a> orci ultricies sit amet.
    Mauris <a href="example.com/test1?bla"><img src=image.example.jpg/test.jpg></a> ex nec dictum. Aliquam blandit arcu ac lorem iaculis aliquet.
    Praesent a tempus dui, eu feugiat diam. Interdum <a href="example.com/a/b/c/d/">et malesuada</a> fames ac ante ipsum primis in faucibus.
    Suspendisse ac rutrum leo, non vehicula purus. Quisque <a href="http://www.example.com?t1=v1&amp;t2=v2">quis</a> sapien lorem. Nunc velit enim,
    placerat quis vestibulum at, <a href="example2.com">condimentum </a> non velit.</html></body>
    """

    expected_result = ['http://www.example.com?t1=v1&t2=v2', 'example.com', 'example.com/test1?bla', 'example.com/a/b/c/d/', 'example2.com']

    assert find_urls(test_urls, include_href=True, domain_force_tld=True) == expected_result


def test_find_urls_without_catastrophic_backtracking() -> None:
    """Ensure url_regex_simple does not cause catastrophic backtracking (Issue 63), test with re instead of regex"""
    test_urls = """
    Lorem ipsum dolor sit amet, http://xxxxxxxxxx.example.com������������������������������������������������������������������������������������������������������������������������������������������������ consectetur adipiscing elit.
    """

    expected_result = [
        'http://xxxxxxxxxx.example.com������������������������������������������������������������������������������������������������������������������������������������������������'
    ]

    assert find_urls(test_urls, domain_force_tld=False) == expected_result


def test_find_urls_with_unicode() -> None:
    """Ensure url_regex includes Unicode in domains and paths"""
    test_urls = """
    Lorem ipsum dolor sit amet http://💌.example.คอม , http://💌.example.คอม/📮/📧/📬.png consectetur https://💩.la adipiscing elit.
    """

    expected_result = ['http://💌.example.คอม', 'http://💌.example.คอม/📮/📧/📬.png', 'https://💩.la']

    assert find_urls(test_urls, include_www=False, domain_force_tld=True) == expected_result


def test_find_urls_with_ipv6_host() -> None:
    """Ensure url_regex includes URLs with IPv6 hosts, including zone Indexes"""
    test_urls = """
    Lorem ipsum dolor sit amet http://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]
    http://[fe80::1ff:fe23:4567:890a%25eth0]/6️⃣ consectetur adipiscing elit.
    """

    expected_result = ['http://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]', 'http://[fe80::1ff:fe23:4567:890a%25eth0]/6️⃣']

    assert find_urls(test_urls, ip_force_routable=False) == expected_result


def test_find_urls_with_routable_ipv6_host() -> None:
    """Ensure url_regex can exclude private and other unallocated IPv6 hosts in URLs."""
    test_urls = """
    Curabitur vel neque lacinia, consequat erat id http://[2001:0db8:85a3:0000:0000:8a2e:0370:7334],
    venenatis sem. Etiam dignissim ullamcorper http://[2606:2800:220:1:248:1893:25c8:1946] risus non pulvinar.
    Etiam dui tortor http://[fe80::1ff:fe23:4567:890a%25eth0]/6️⃣, posuere et iaculis sed, accumsan a erat.
    """

    expected_result = ['http://[2606:2800:220:1:248:1893:25c8:1946]']

    assert find_urls(test_urls, ip_force_routable=True) == expected_result


def test_find_urls_starting_with_www() -> None:
    test_urls = """
    www91.example.com@www92.example.com  www93.example.com@example.com
    www94......example.com/path  not.www95.example.com:443/path
    www2.example.com:443/path 'www3.example.com/path' ‘www4.example.com#abc’  www5.example.com:443?def   \nwww6.example.com.../path
    www7.example.com/?# www8.example.com?/#  www9.example.com#?/  www10.example.com/?
    https://www01.example.com/path  https://www02.example.com..../path  https://www03.example.com/
    http://www04.example.com/?# http://www05.example.com?/#  http://www06.example.com#?/  http://www07.example.com/?
    """

    expected_result = [
        'www2.example.com:443/path',
        'www3.example.com/path',
        'www4.example.com#abc',
        'www5.example.com:443?def',
        'www6.example.com.../path',
        'www7.example.com/',
        'www8.example.com?/',
        'www9.example.com#?/',
        'www10.example.com/',
        'https://www01.example.com/path',
        'https://www02.example.com..../path',
        'https://www03.example.com/',
        'http://www04.example.com/',
        'http://www05.example.com?/',
        'http://www06.example.com#?/',
        'http://www07.example.com/',
    ]

    assert find_urls(test_urls, include_www=True) == expected_result


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


def test_body_extraction_skips_non_hosts() -> None:
    """File names, scope resolutions and "::" do not become indicators, real ones stay."""
    raw = b'From: a@example.com\r\n\r\nopen invoice.pdf and report.docx, call std::vector or Add::dead :: but visit evil.example.com and 2001:db8::1'
    body = eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(raw)['body'][0]

    assert body['domain'] == ['evil.example.com']
    assert body['ip'] == ['2001:db8::1']


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
# Hosts which browsers reject (misplaced joiner, bidi control, leading combining mark, forbidden code point).


def _uris(html: str) -> list[str]:
    raw = f'From: a@example.com\r\nContent-Type: text/html\r\n\r\n{html}'.encode()

    body = eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(raw)['body'][0]

    return body.get('uri', []) + body.get('uri_noscheme', [])


URL_IN_ATTRIBUTE_CASES = [
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
]


def test_url_in_attribute() -> None:
    """Each of these tags hides a URL which must be reported."""

    def check(html: str) -> None:
        assert _uris(html) == ['http://evil.example.com/login']

    tests.table.assert_all_cases(check, URL_IN_ATTRIBUTE_CASES)


BROWSER_STYLE_NORMALISATION_CASES = [
    'http://evil.example.com/login',
    'ht&#9;tp://evil.example.com/login',
    'http:&#47;&#47;evil.example.com/login',
    'ht\ntp://evil.example.com/login',
    'http:\\\\evil.example.com\\login',
    'http://evil.example.com/log\tin',
]


def test_browser_style_normalisation() -> None:
    """Obfuscations which browsers undo before using the URL."""

    def check(value: str) -> None:
        assert 'http://evil.example.com/login' in _uris(f'<a href="{value}">x</a>')

    tests.table.assert_all_cases(check, BROWSER_STYLE_NORMALISATION_CASES)


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


LOOP = eml_parser.indicators.sliding_windows


class TestSlidingWindow:
    """Slices must cover the body completely and never cut a token."""

    def test_short_and_empty_body(self) -> None:
        """A body which fits in one slice is returned unchanged."""
        assert list(LOOP('')) == ['']
        assert list(LOOP('abc')) == ['abc']

    def test_slices_cover_the_body(self) -> None:
        """No gaps, no overlaps."""
        body = ('x' * 495 + ' http://evil.example.com/abc ') * 30

        assert ''.join(LOOP(body)) == body

    def test_tokens_are_not_cut(self) -> None:
        """Every URL is complete in exactly one slice."""
        for offset in range(120):
            body = 'a' * offset + (' ' + 'b' * 380 + ' http://evil.example.com/path') * 4 + ' end'
            slices = list(LOOP(body))

            assert sum(s.count('http://evil.example.com/path') for s in slices) == 4

    def test_last_token_without_trailing_whitespace_is_not_cut(self) -> None:
        """A token which ends the body is complete even though no whitespace follows it."""
        body = 'a' * 480 + ' http://evil.example.com/last/token'

        assert list(LOOP(body)) == [body]

    def test_long_token_is_not_cut_with_default_distance(self) -> None:
        """A URL of several thousand characters crossing a slice border stays in one piece."""
        first_slice = 'a' * 480 + ' http://evil.example.com/' + 'p' * 5000
        body = first_slice + ' tail ' + 'b' * 2000

        assert next(iter(LOOP(body))) == first_slice

    def test_overlong_token_is_cut_but_not_lost(self) -> None:
        """Without whitespace the slices are cut hard, the content is kept."""
        body = 'y' * 2000

        assert ''.join(LOOP(body, 500, 100)) == body

    def test_url_at_slice_boundary_is_extracted(self) -> None:
        """End to end: a URL crossing the 500 character mark is reported completely."""
        body = 'a' * 470 + ' http://evil.example.com/a/long/path?x=1 tail'
        raw = f'From: a@example.com\r\n\r\n{body}'.encode()
        parsed = eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(raw)

        assert parsed['body'][0]['uri'] == ['http://evil.example.com/a/long/path?x=1']


REMOTE_SHARE_IS_FOUND_CASES = [
    (r'\\attacker.example.com\share\a.png', 'attacker.example.com'),
    (r'open "\\fileserver\public\doc.docx" now', 'fileserver'),
    (r'\\evil.example.net@SSL\DavWWWRoot\x.lnk', 'evil.example.net@SSL'),
    (r'\\evil.example.net@8080\x\y', 'evil.example.net@8080'),
    (r'\\?\UNC\srv.example.com\share\f', 'srv.example.com'),
    ('file://10.1.2.3/share/x.lnk', '10.1.2.3'),
    ('file:////evil.example.org/s/x', 'evil.example.org'),
    ('smb://203.0.113.9/c$', '203.0.113.9'),
]


def test_remote_share_is_found() -> None:
    """UNC paths (also the WebDAV forms) and file/smb URLs with a host."""

    def check(text: str, host: str) -> None:
        match = eml_parser.regexes.unc_regex.search(text)

        assert match is not None
        assert (match.group('unc_host') or match.group('url_host')) == host

    tests.table.assert_all_cases(check, REMOTE_SHARE_IS_FOUND_CASES)


LOCAL_AND_ESCAPED_PATHS_ARE_IGNORED_CASES = [
    r'C:\\Users\\Bob',
    r'"\\\\Users\\Bob"',
    r'regex \\d+\\w',
    r'path\\host\share',
    'file:///C:/x.txt',
    'file:/relative',
    r'\\host',
]


def test_local_and_escaped_paths_are_ignored() -> None:
    """Escaped text, drive paths, local file URLs and a bare host are not remote shares."""

    def check(text: str) -> None:
        assert eml_parser.regexes.unc_regex.search(text) is None

    tests.table.assert_all_cases(check, LOCAL_AND_ESCAPED_PATHS_ARE_IGNORED_CASES)


HTML = (
    '<img src="\\\\attacker.example.com\\share\\a.png"> see \\\\fileserver\\public\\doc.docx, \\\\203.0.113.9\\c$ and C:\\\\Users\\\\Bob '
    '<a href="file:////evil.example.org/s/x.lnk">x</a>'
)


def test_remote_shares_in_body() -> None:
    """The shares are reported and their hosts are added to the domains and IPs."""
    raw = f'From: a@example.com\r\nContent-Type: text/html\r\n\r\n{HTML}'.encode()
    body = eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(raw)['body'][0]

    assert body['unc'] == [
        '\\\\attacker.example.com\\share\\a.png',
        '\\\\fileserver\\public\\doc.docx',
        '\\\\203.0.113.9\\c$',
        'file:////evil.example.org/s/x.lnk',
    ]
    assert sorted(body['domain']) == ['attacker.example.com', 'evil.example.org']
    assert body['ip'] == ['203.0.113.9']


def test_hashed_mode() -> None:
    """Without raw body only hashes of the shares are reported."""
    raw = f'From: a@example.com\r\nContent-Type: text/html\r\n\r\n{HTML}'.encode()
    body = eml_parser.parser.EmlParser().decode_email_bytes(raw)['body'][0]

    assert 'unc' not in body
    assert body['unc_hash'][0] == hashlib.sha256(b'\\\\attacker.example.com\\share\\a.png').hexdigest()


# URL candidates which are dropped: the stdlib cannot parse them, they have no host, or nothing is left of them without the noise.
CLEAN_URL_REJECTED_CASES = ['http://[::1/x', 'http:///a.example/x', "http://'a.example.com"]


def test_clean_url_rejects_unparsable_urls_and_urls_without_host() -> None:
    hosts = eml_parser.hosts.HostValidator(domain_force_tld=False, ip_force_routable=False)
    finder = eml_parser.indicators.IndicatorFinder(hosts, eml_parser.regexes.email_no_force_tld_regex, include_www=True, include_href=True)

    def check(url: str) -> None:
        assert finder.clean_url(url) is None

    tests.table.assert_all_cases(check, CLEAN_URL_REJECTED_CASES)


def test_url_cut_inside_a_bracketed_host_does_not_raise() -> None:
    # Arrange: the noise after "a" is cut off the URL, which leaves the IPvFuture host unclosed, which the stdlib refuses to parse
    hosts = eml_parser.hosts.HostValidator(domain_force_tld=False, ip_force_routable=False)
    finder = eml_parser.indicators.IndicatorFinder(hosts, eml_parser.regexes.email_no_force_tld_regex, include_www=True, include_href=True)

    # Act
    found = finder.find('<a href="http://[v1.a,b.example.com]/">x</a>', eml_parser.hosts.IpWhitelist.from_entries(()))

    # Assert
    assert list(found.domain) == ['b.example.com']
