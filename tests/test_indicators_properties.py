"""Property-based tests (Hypothesis) for indicators written with character references in the body of an e-mail.

The messages are valid (RFC 5322 / 2045): built by the stdlib with the SMTP policy, with fixed header fields, a declared charset and
a transfer encoding the body allows. Only the text of a text/plain or text/html part varies: an indicator (URL, www link, e-mail
address, domain, IPv4 address) in surrounding text, some of its characters written as character references the way its reader still
sees the same character.

The expected result is never computed by the code under test: it is the result for the same message with the indicator written
as is, which must contain the generated indicator. Properties:

- HTML part, any reference a browser resolves: the same indicators as written as is.
- text/plain part, complete references (with ";"): the same indicators.
- text/plain part with a reference without ";" (shown as written by mail clients), and any part with a reference written twice
  (`&amp;#58;`, shown as `&#58;`): nothing which the reader does not see. Every reported value is one reported for the indicator
  written as is, or contains the reference as written.
- ordinary text (versions, prices, dates, file names...) written with references: the same as written as is.
- the transfer encoding (7bit, quoted-printable, base64) and a multipart/alternative do not change the result.
- URLs in href/src attribute values: the same as written as is.

Run with ``HYPOTHESIS_PROFILE=deep`` for many more examples, see `conftest.py`.
"""

import collections
import dataclasses
import email.message
import email.policy
import html.entities
import random
import re
import typing

import hypothesis
import hypothesis.strategies as st
import pytest

import eml_parser

KEYS = ('uri', 'uri_noscheme', 'domain', 'email', 'ip')
Found = dict[str, frozenset[str]]

pytestmark = pytest.mark.property

# --- indicators ------------------------------------------------------------------------------------------------------------------------

TLDS = ('com', 'net', 'org', 'lu', 'de', 'fr', 'eu', 'info', 'io', 'be')
LDH = 'abcdefghijklmnopqrstuvwxyz0123456789'
# letters of a few scripts which UTS #46 maps to themselves (lower case, no compatibility mapping)
IDN_LETTERS = 'äöüéèçñåøαβγδεζηθλμπστжзиклмнопрстуф'

# The strategies use st.text() over small alphabets rather than st.from_regex(): Hypothesis records every draw of an example, and the
# regex strategies draw much more, which made long runs slow and memory hungry.
ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'


def _framed(alphabet: str, inner: str, max_inner: int) -> st.SearchStrategy[str]:
    """One character of *alphabet*, or two of it around up to *max_inner* characters of *inner*."""
    edge = st.sampled_from(alphabet)
    return st.one_of(edge, st.builds(lambda a, b, c: a + b + c, edge, st.text(inner, max_size=max_inner), edge))


# a host label (RFC 1123), not reserved for IDNA (no "--" at positions 3-4, RFC 5891)
ascii_labels = _framed(LDH, LDH + '-', 12).filter(lambda label: label[2:4] != '--')


@st.composite
def idn_labels(draw: st.DrawFn) -> str:
    """A label with at least one non-ASCII letter."""
    letters = draw(st.lists(st.sampled_from(IDN_LETTERS + LDH), min_size=1, max_size=12))
    letters[draw(st.integers(0, len(letters) - 1))] = draw(st.sampled_from(IDN_LETTERS))
    return ''.join(letters)


@st.composite
def hosts(draw: st.DrawFn, idn: bool = False) -> str:
    labels = draw(st.lists(ascii_labels, min_size=1, max_size=3))
    if idn:
        labels[draw(st.integers(0, len(labels) - 1))] = draw(idn_labels())
    return '.'.join([*labels, draw(st.sampled_from(TLDS))])


words = st.text(ALNUM, min_size=1, max_size=8)
path_segments = _framed(ALNUM, ALNUM + '._~-', 8)


@st.composite
def url_tails(draw: st.DrawFn) -> str:
    """Path, query and fragment of a URL (RFC 3986), ending in a letter or digit, which ends a URL in text."""
    tail = ''.join('/' + segment for segment in draw(st.lists(path_segments, max_size=3)))
    if query := draw(st.lists(st.tuples(words, words), max_size=3)):
        tail += '/?' + '&'.join(f'{key}={value}' for key, value in query)
    if draw(st.booleans()):
        tail += '#' + draw(words)
    return tail


@dataclasses.dataclass(frozen=True)
class Indicator:
    text: str  # as written in the body
    key: str  # the result key it is reported under
    value: str  # as reported


@st.composite
def urls(draw: st.DrawFn, idn: bool = False) -> Indicator:
    host = draw(hosts(idn))
    port = f':{draw(st.integers(1, 65535))}' if draw(st.booleans()) else ''
    url = f'{draw(st.sampled_from(("http", "https", "ftp")))}://{host}{port}{draw(url_tails())}'
    return Indicator(url, 'uri', url)


@st.composite
def www_links(draw: st.DrawFn) -> Indicator:
    host = f'www.{draw(hosts())}'
    tail = draw(url_tails())
    # a www link without path is only reported as domain
    return Indicator(host + tail, 'uri_noscheme', host + tail) if tail else Indicator(host, 'domain', host)


@st.composite
def addresses(draw: st.DrawFn) -> Indicator:
    # a dot-atom local part (RFC 5322), without "&" which would start a reference
    atoms = draw(st.lists(st.text(ALNUM + "!#$%'*+/=?^_`{|}~-", min_size=1, max_size=10), min_size=1, max_size=3))
    local_part = '.'.join(atoms)
    # a local part which looks like a URL path with query (`a/b?c`) is read as URL, see `indicators._URL_IN_LOCAL_PART`
    hypothesis.assume(not re.search(r'://|\A//|/.*\?|\?.*=', local_part))
    address = local_part + '@' + draw(hosts())
    return Indicator(address, 'email', address.lower())  # addresses are reported in lower case


@st.composite
def domains(draw: st.DrawFn) -> Indicator:
    host = draw(hosts())
    return Indicator(host, 'domain', host)


@st.composite
def ipv4_addresses(draw: st.DrawFn) -> Indicator:
    address = draw(st.ip_addresses(v=4).filter(lambda ip: ip.is_global))
    return Indicator(str(address), 'ip', str(address))


indicators = st.one_of(urls(), urls(idn=True), www_links(), addresses(), domains(), ipv4_addresses())

# ordinary text with dots, colons and slashes which is no indicator
ordinary_text = st.one_of(
    st.from_regex(r'\Av?[0-9]{1,3}(?:\.[0-9]{1,3}){1,2}\Z'),  # versions
    st.from_regex(r'\A[$€][0-9]{1,4}\.[0-9]{2}\Z'),  # prices
    st.from_regex(r'\A[0-3][0-9]\.[01][0-9]\.20[0-9]{2}\Z'),  # dates
    st.from_regex(r'\A[0-2][0-9]:[0-5][0-9]\Z'),  # times
    st.from_regex(r'\A[a-z]{1,10}\.(?:pdf|docx|xlsx|png|jpg|txt)\Z'),  # file names
    st.sampled_from(('e.g.', 'i.e.', 'U.S.A.', 'a.m.', 'and/or', 'Q&A', 'AT&T')),
)

# --- character references ----------------------------------------------------------------------------------------------------------------

NAMED: dict[str, list[str]] = collections.defaultdict(list)
for _name, _value in html.entities.html5.items():
    if _name.endswith(';') and len(_value) == 1:
        NAMED[_value].append(_name)


@st.composite
def encoded(draw: st.DrawFn, text: str, *, without_semicolon: bool) -> str:
    """The text with at least one character written as a character reference which resolves to it.

    A numeric reference without ";" is only written where the next character cannot continue its number, which would change it.
    """
    chosen = draw(st.lists(st.booleans(), min_size=len(text), max_size=len(text)).filter(any))
    pieces: list[str] = []
    for index, (character, encode) in enumerate(zip(text, chosen, strict=True)):
        if not encode:
            pieces.append(character)
            continue
        # one draw per reference: its form, leading zeros, case of "x" and of the hex digits, and whether ";" is left out
        choice = draw(st.integers(0, 2**8 - 1))
        names = NAMED.get(character, [])
        if names and choice % 3 == 0:
            pieces.append('&' + names[(choice >> 2) % len(names)])
            continue
        zeros = '0' * ((choice >> 2) % 4)
        if choice % 3 == 1 or not names and choice % 2:
            reference, digits = f'&#{zeros}{ord(character)}', '0123456789'
        else:
            x, case = ('x', 'X')[(choice >> 4) & 1], ('x', 'X')[(choice >> 5) & 1]
            reference, digits = f'&#{x}{zeros}{ord(character):{case}}', '0123456789abcdefABCDEF'
        next_is_literal = index + 1 < len(text) and not chosen[index + 1]
        may_omit = without_semicolon and not (next_is_literal and text[index + 1] in digits)
        pieces.append(reference + ('' if may_omit and (choice >> 6) & 1 else ';'))
    return ''.join(pieces)


def escaped_once_more(text: str, amp: str) -> str:
    """The text with every "&" written as a reference, so the references of *text* are shown as written."""
    return text.replace('&', amp)


# --- messages ------------------------------------------------------------------------------------------------------------------------

FILLER_WORDS = ('please', 'verify', 'your', 'account', 'today', 'Dear', 'customer', 'invoice', 'x1', 'Q3', 'and', 'the')
SEPARATORS = ((' ', ' '), ('\n', '\n'), ('(', ')'), (' ', '. '), (' ', ', '))
HTML_SEPARATORS = (*SEPARATORS, ('<p>', '</p>'), ('<br>', '<br>'), ('<td>', '</td>'))


@st.composite
def fillers(draw: st.DrawFn) -> str:
    """Text without indicators in front of the indicator, up to about 1 000 characters, so the indicator also falls on a window boundary.

    Built from a fixed word list with two draws (length and seed): every draw is recorded by Hypothesis, one per word made long runs
    slow and memory hungry (about 200 KB per example).
    """
    count, seed = draw(st.integers(0, 150)), draw(st.integers(0, 2**16))
    rng = random.Random(seed)  # noqa: S311 - reproducible test data, not security related
    return ''.join(rng.choice(FILLER_WORDS) + ('\n' if i % 12 == 11 else ' ') for i in range(count))


@dataclasses.dataclass(frozen=True)
class Placement:
    filler: str
    before_html: tuple[str, str]
    before_plain: tuple[str, str]

    def body(self, token: str, subtype: str) -> str:
        if subtype == 'html':
            before, after = self.before_html
            return f'<html><body><p>{self.filler}{before}{token}{after}now</p></body></html>'
        before, after = self.before_plain
        return f'{self.filler}{before}{token}{after}now\n'


placements = st.builds(Placement, fillers(), st.sampled_from(HTML_SEPARATORS), st.sampled_from(SEPARATORS))
transfer_encodings = st.sampled_from(('7bit', 'quoted-printable', 'base64'))


def _allowed_encoding(text: str, cte: str) -> str:
    """7bit only for ASCII text with lines of at most 998 characters (RFC 5322), quoted-printable otherwise."""
    if cte == '7bit' and not (text.isascii() and all(len(line) <= 998 for line in text.splitlines())):
        return 'quoted-printable'
    return cte


def message(parts: typing.Sequence[tuple[str, str]], cte: str) -> bytes:
    """A valid message with the given (subtype, text) parts, one part or a multipart/alternative."""
    msg = email.message.EmailMessage(policy=email.policy.SMTP)
    msg['From'] = 'Sender <sender@sender.example.com>'
    msg['To'] = 'rcpt@rcpt.example.com'
    msg['Subject'] = 'Your account'
    msg['Date'] = 'Mon, 02 Nov 2026 10:00:00 +0000'
    msg['Message-ID'] = '<id-1@sender.example.com>'
    for index, (subtype, text) in enumerate(parts):
        charset = 'us-ascii' if text.isascii() else 'utf-8'
        add = msg.set_content if index == 0 else msg.add_alternative
        add(text, subtype=subtype, charset=charset, cte=_allowed_encoding(text, cte))
    return msg.as_bytes()


def found(raw: bytes) -> list[Found]:
    """The indicators of every body part."""
    parts = eml_parser.EmlParser(include_raw_body=True).decode_email_bytes(raw)['body']
    return [{key: frozenset(part.get(key, ())) for key in KEYS} for part in parts]


def found_in(subtype: str, body: str, cte: str = '7bit') -> Found:
    (part,) = found(message([(subtype, body)], cte))
    return part


_COMPLETE_REFERENCE = re.compile(r'&(?:#[0-9]+|#[xX][0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]*);')
_NUMERIC_REFERENCE_START = re.compile(r'&#([x]?)([0-9a-f]*)\Z')
_HEX_DIGITS = '0123456789abcdef'


def seen(body: str, subtype: str) -> str:
    """The text as its reader sees it, independent of the parser: HTML by the stdlib, plain text with only complete references resolved.

    Both resolve every reference once (a single pass), as browsers do.
    """
    if subtype == 'html':
        return html.unescape(body)
    return _COMPLETE_REFERENCE.sub(lambda match: html.unescape(match.group(0)), body)


def _starts_in_reference(text: str, start: int) -> bool:
    """Whether *start* is in the digits of a numeric reference shown as written in *text* (lower case), e.g. at "97" of `p&#97ypal.com`."""
    match = _NUMERIC_REFERENCE_START.search(text, 0, start)
    if match is None:
        return False
    x, digits = match.groups()
    following = text[start : start + 2]
    if x:
        return bool(digits) or following[:1] in _HEX_DIGITS
    if digits:
        return digits.isdigit()
    return following[:1].isdigit() or (following[:1] == 'x' and following[1:2] in _HEX_DIGITS)


def visible(value: str, text: str) -> bool:
    """Whether *value* is shown in *text* (the text as seen) as a whole token which does not start in a reference shown as written."""
    text, value = text.lower(), value.lower()  # domains and addresses are reported in lower case
    start = text.find(value)
    while start >= 0:
        end = start + len(value)
        if not text[start - 1 : start].isalnum() and not text[end : end + 1].isalnum() and not _starts_in_reference(text, start):
            return True
        start = text.find(value, start + 1)
    return False


def not_more_than(result: Found, expected: Found, text: str) -> dict[str, set[str]]:
    """The values which are not in *expected*, do not show a reference as written (with "&") and are not visible in *text* (as seen)."""
    return {key: extra for key in KEYS if (extra := {value for value in result[key] - expected[key] if '&' not in value and not visible(value, text)})}


# --- properties --------------------------------------------------------------------------------------------------------------------------


@st.composite
def cases(draw: st.DrawFn, *, without_semicolon: bool) -> tuple[Indicator, str, Placement, str]:
    indicator = draw(indicators)
    return indicator, draw(encoded(indicator.text, without_semicolon=without_semicolon)), draw(placements), draw(transfer_encodings)


def _expected(indicator: Indicator, placement: Placement, subtype: str) -> Found:
    expected = found_in(subtype, placement.body(indicator.text, subtype))
    assert indicator.value in expected[indicator.key], f'{indicator} written as is is not found: {expected}'
    return expected


@hypothesis.given(cases(without_semicolon=True))
def test_html_part_reports_what_the_reader_sees(case: tuple[Indicator, str, Placement, str]) -> None:
    """P1: in an HTML part every reference a browser resolves is resolved, with and without ";"."""
    indicator, token, placement, cte = case

    assert found_in('html', placement.body(token, 'html'), cte) == _expected(indicator, placement, 'html')


@hypothesis.given(cases(without_semicolon=False))
def test_plain_text_part_resolves_complete_references(case: tuple[Indicator, str, Placement, str]) -> None:
    """P2: in a text/plain part complete references (with ";") are resolved."""
    indicator, token, placement, cte = case

    assert found_in('plain', placement.body(token, 'plain'), cte) == _expected(indicator, placement, 'plain')


@hypothesis.given(cases(without_semicolon=True))
def test_plain_text_part_reports_nothing_unseen(case: tuple[Indicator, str, Placement, str]) -> None:
    """P3: a reference without ";" is shown as written in plain text; no value which its reader does not see is reported."""
    indicator, token, placement, cte = case
    hypothesis.assume('&' in token)

    body = placement.body(token, 'plain')

    assert not_more_than(found_in('plain', body, cte), _expected(indicator, placement, 'plain'), seen(body, 'plain')) == {}


@hypothesis.given(cases(without_semicolon=False), st.sampled_from(('&amp;', '&#38;', '&#x26;')), st.sampled_from(('html', 'plain')))
def test_references_are_resolved_once(case: tuple[Indicator, str, Placement, str], amp: str, subtype: str) -> None:
    """P4: a reference written as text (`&amp;#58;`) is shown as written: no value which only a second resolution gives."""
    indicator, token, placement, cte = case

    body = placement.body(escaped_once_more(token, amp), subtype)

    assert not_more_than(found_in(subtype, body, cte), _expected(indicator, placement, subtype), seen(body, subtype)) == {}


@hypothesis.given(
    ordinary_text.flatmap(lambda text: st.tuples(st.just(text), encoded(text, without_semicolon=True))), placements, st.sampled_from(('html', 'plain'))
)
def test_ordinary_text_with_references(texts: tuple[str, str], placement: Placement, subtype: str) -> None:
    """P5: ordinary text written with references gives what it gives written as is (in plain text: nothing more)."""
    text, token = texts
    body = placement.body(token, subtype)
    expected = found_in(subtype, placement.body(text, subtype))
    result = found_in(subtype, body)

    if subtype == 'html':
        assert result == expected
    else:
        assert not_more_than(result, expected, seen(body, subtype)) == {}


@hypothesis.given(cases(without_semicolon=True), st.sampled_from(('html', 'plain')))
def test_transfer_encoding_does_not_matter(case: tuple[Indicator, str, Placement, str], subtype: str) -> None:
    """P6: the same text in 7bit, quoted-printable or base64 gives the same indicators."""
    _, token, placement, _ = case
    body = placement.body(token, subtype)

    results = {cte: found_in(subtype, body, cte) for cte in ('7bit', 'quoted-printable', 'base64')}

    assert results['quoted-printable'] == results['base64'] == results['7bit']


@hypothesis.given(cases(without_semicolon=True))
def test_multipart_alternative_parts_are_read_by_their_type(case: tuple[Indicator, str, Placement, str]) -> None:
    """The text and the HTML part of a multipart/alternative give what they give alone."""
    _, token, placement, cte = case
    plain, html_body = placement.body(token, 'plain'), placement.body(token, 'html')

    assert found(message([('plain', plain), ('html', html_body)], cte)) == [found_in('plain', plain, cte), found_in('html', html_body, cte)]


ATTRIBUTES = ('<a href={value}>x</a>', '<img src={value}>', '<form action={value}></form>', '<a title="t" href={value}>x</a>')


@hypothesis.given(
    st.one_of(urls(), urls(idn=True)).flatmap(lambda url: st.tuples(st.just(url), encoded(url.text, without_semicolon=True))),
    st.sampled_from(ATTRIBUTES),
    st.sampled_from(('"{}"', "'{}'", '{}')),
    placements,
    transfer_encodings,
)
def test_url_in_attribute_value(urls_written: tuple[Indicator, str], tag: str, quotes: str, placement: Placement, cte: str) -> None:
    """URLs in href/src/action values, written with references (with and without ";"), are reported like written as is."""
    url, token = urls_written
    expected = found_in('html', placement.body(tag.format(value=quotes.format(url.text)), 'html'))
    assert url.value in expected['uri'], expected

    assert found_in('html', placement.body(tag.format(value=quotes.format(token)), 'html'), cte) == expected


@hypothesis.given(urls(), addresses(), st.sampled_from(('email', 'e', 'to', 'u')), placements, st.sampled_from(('html', 'plain')))
def test_address_in_url_query(url: Indicator, address: Indicator, key: str, placement: Placement, subtype: str) -> None:
    """An address in the query of a URL is reported as the address, not with the URL in front of it."""
    # "?", "=", "&", "/" and ":" in a query value are delimiters: an address with them is ambiguous there (`?email==@a.com`) and is
    # percent-encoded by senders
    hypothesis.assume(not any(char in address.text.partition('@')[0] for char in '?=&/:'))
    link = url.text.split('#')[0]
    link += ('&' if '?' in link else '/?') + f'{key}={address.text}'

    assert found_in(subtype, placement.body(link, subtype))['email'] == {address.value}


@st.composite
def login_urls(draw: st.DrawFn) -> tuple[str, str]:
    """A URL with a login part (`https://user:password@host/path`, RFC 3986 userinfo) and its host."""
    user, password, host = draw(words), draw(st.one_of(st.none(), words)), draw(hosts())
    login = user if password is None else f'{user}:{password}'
    return f'{draw(st.sampled_from(("http", "https", "ftp")))}://{login}@{host}{draw(url_tails()) or "/"}', host


@hypothesis.given(login_urls(), placements, st.sampled_from(('html', 'plain')))
def test_url_login_is_no_address(login_url: tuple[str, str], placement: Placement, subtype: str) -> None:
    """The login part of a URL (`https://user:password@host/`) is no address; the URL and its host are reported."""
    url, host = login_url

    result = found_in(subtype, placement.body(url, subtype))

    assert result['email'] == frozenset()
    assert url in result['uri']
    assert host in result['domain']
