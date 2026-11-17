"""Property-based tests (Hypothesis) for the header fields of an e-mail: addresses, subject, date, trace fields, authentication results
and attachment file names.

The fields are built from the grammar of the RFCs (RFC 5322 incl. its obsolete syntax, RFC 2047, RFC 2231, RFC 5321, RFC 8601), with
the hostile constructions a sender can put in them (addresses in display names and comments, fake results in comments). The messages
are otherwise valid; random bytes, NUL and bare CR/LF are not generated. The expected result is what was generated, never computed by
the code under test. Run with ``HYPOTHESIS_PROFILE=deep`` for many more examples, see `conftest.py`.
"""

import base64
import dataclasses
import datetime as dt
import quopri
import typing

import hypothesis
import hypothesis.strategies as st
import pytest

import eml_parser
import eml_parser.decode

pytestmark = pytest.mark.property

TLDS = ('com', 'net', 'org', 'lu', 'de', 'eu', 'info')
LDH = 'abcdefghijklmnopqrstuvwxyz0123456789'
ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
ATEXT = ALNUM + "!#$%&'*+-/=?^_`{|}~"
QUOTED_TEXT = ALNUM + ' .,:;@<>()[]\\"'  # specials and the characters escaped in a quoted string
BODY = 'Content-Type: text/plain; charset=us-ascii\r\n\r\nbody\r\n'

# --- building blocks -------------------------------------------------------------------------------------------------------------------

labels = st.one_of(
    st.sampled_from(LDH), st.builds(lambda a, b, c: a + b + c, st.sampled_from(LDH), st.text(LDH + '-', max_size=10), st.sampled_from(LDH))
).filter(lambda label: label[2:4] != '--')
hosts = st.builds(lambda parts, tld: '.'.join([*parts, tld]), st.lists(labels, min_size=1, max_size=3), st.sampled_from(TLDS))
local_parts = st.lists(st.text(ATEXT, min_size=1, max_size=8), min_size=1, max_size=3).map('.'.join)
addresses = st.builds(lambda local, host: f'{local}@{host}', local_parts, hosts)
words = st.text(ALNUM, min_size=1, max_size=8)
# text of a display name, a subject or a comment: printable, any script, no line breaks
texts = st.text(st.characters(codec='utf-8', categories=('L', 'M', 'N', 'P', 'S', 'Zs'), exclude_characters='\r\n\x85  '), max_size=24)


def encoded_word(text: str, charset: str, encoding: str) -> str:
    """An RFC 2047 encoded word for *text*."""
    data = text.encode(charset)
    if encoding == 'B':
        return f'=?{charset}?B?{base64.b64encode(data).decode()}?='
    quoted = quopri.encodestring(data, header=True).decode().replace('=\n', '')
    # in an encoded word "?", "=" and "_" are encoded, and so are the specials of a phrase (RFC 2047 5.(3))
    for char in '?"(),.:;<>@[\\]':  # quopri already encodes "_" (a space is written "_")
        quoted = quoted.replace(char, f'={ord(char):02X}')
    return f'=?{charset}?Q?{quoted}?='


@st.composite
def encoded_words(draw: st.DrawFn, text: str) -> str:
    charset = 'iso-8859-1' if all(ord(char) < 256 for char in text) and draw(st.booleans()) else 'utf-8'
    return encoded_word(text, charset, draw(st.sampled_from('BQ')))


def quoted_string(text: str) -> str:
    return '"' + text.replace('\\', '\\\\').replace('"', '\\"') + '"'


@st.composite
def comments(draw: st.DrawFn, inner: str | None = None) -> str:
    """A comment, possibly nested, with *inner* (or generated text) in it."""
    text = inner if inner is not None else draw(st.text(ALNUM + ' .,:;@<>"', max_size=16))
    text = text.replace('\\', '').replace('(', '').replace(')', '')
    return f'({text})' if draw(st.booleans()) else f'(x {text} (nested))'


def fold(value: str, positions: typing.Sequence[int]) -> str:
    """The value folded (CRLF before white space) at the white space after the given positions."""
    pieces = value.split(' ')
    out = pieces[0]
    for index, piece in enumerate(pieces[1:]):
        out += ('\r\n ' if index in positions else ' ') + piece
    return out


def message(fields: typing.Iterable[str], body: str = BODY) -> bytes:
    head = ''.join(f'{field}\r\n' for field in fields)
    return f'{head}MIME-Version: 1.0\r\n{body}'.encode()


def parse(raw: bytes) -> dict[str, typing.Any]:
    result = eml_parser.EmlParser(include_raw_body=True).decode_email_bytes(raw)
    eml_parser.decode.export_to_json(result)  # every result can be exported
    return result


# --- H1/H2: addresses --------------------------------------------------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Mailbox:
    text: str  # as written
    address: str  # as reported (lower case)


@st.composite
def mailboxes(draw: st.DrawFn) -> Mailbox:
    address = draw(addresses)
    form = draw(st.sampled_from(('bare', 'angle', 'atoms', 'quoted', 'encoded', 'comment', 'route')))
    if form == 'bare':
        text = address
    elif form == 'angle':
        text = f'<{address}>'
    elif form == 'atoms':
        text = ' '.join(draw(st.lists(words, min_size=1, max_size=3))) + f' <{address}>'
    elif form == 'quoted':
        text = f'{quoted_string(draw(st.text(QUOTED_TEXT, max_size=16)))} <{address}>'
    elif form == 'encoded':
        text = f'{draw(encoded_words(draw(texts)))} <{address}>'
    elif form == 'comment':
        text = f'{address} {draw(comments())}'
    else:  # obsolete route (RFC 5322 4.4)
        text = f'<@{draw(hosts)},@{draw(hosts)}:{address}>'
    return Mailbox(text, address.lower())


@st.composite
def address_lists(draw: st.DrawFn) -> tuple[str, list[str]]:
    """An address list (with a group in it, maybe) and the addresses in it."""
    boxes = draw(st.lists(mailboxes(), min_size=1, max_size=5))
    items = [box.text for box in boxes]
    if len(items) > 1 and draw(st.booleans()):
        start = draw(st.integers(0, len(items) - 1))
        end = draw(st.integers(start + 1, len(items)))
        items[start:end] = [f'{draw(words)}: {", ".join(items[start:end])};']
    value = ', '.join(items)
    return fold(value, draw(st.lists(st.integers(0, 20), max_size=3))), [box.address for box in boxes]  # duplicates are kept


BASE = ['From: sender@example.org', 'Subject: test', 'Date: Mon, 02 Nov 2026 10:00:00 +0000']


@hypothesis.given(st.sampled_from(('To', 'Cc', 'Delivered-To')), address_lists())
def test_address_lists(name: str, address_list: tuple[str, list[str]]) -> None:
    """H1: every address of an address list is reported, in order, whatever the display names, comments, groups and routes."""
    value, expected = address_list

    header = parse(message([*BASE, f'{name}: {value}']))['header']

    assert header[name.lower().replace('-', '_')] == expected


@hypothesis.given(mailboxes())
def test_sender(mailbox: Mailbox) -> None:
    """H1: the address of the From field is the sender."""
    assert parse(message([f'From: {mailbox.text}', 'Subject: test']))['header']['from'] == mailbox.address


@hypothesis.given(addresses, addresses, st.sampled_from(('quoted', 'encoded', 'comment', 'angle-in-name')))
def test_spoofed_display_name(real: str, spoofed: str, form: str) -> None:
    """H2: an address in the display name or a comment (`"ceo@bank.example" <evil@x.example>`) is never reported as the sender."""
    hypothesis.assume(real.lower() != spoofed.lower())
    name = {
        'quoted': quoted_string(spoofed),
        'encoded': encoded_word(f'{spoofed} <{spoofed}>', 'utf-8', 'B'),
        'comment': f'({spoofed})',
        'angle-in-name': quoted_string(f'{spoofed} <{spoofed}>'),
    }[form]

    header = parse(message([f'From: {name} <{real}>', f'To: {name} <{real}>', 'Subject: test']))['header']

    assert header['from'] == real.lower()
    assert header['to'] == [real.lower()]


# --- H3: subject -------------------------------------------------------------------------------------------------------------------------


@st.composite
def subjects(draw: st.DrawFn) -> tuple[str, str]:
    """A subject of plain words and encoded words, and its decoded text (white space between encoded words is dropped, RFC 2047 6.2)."""
    segments = draw(st.lists(st.one_of(st.tuples(st.just('plain'), words), st.tuples(st.just('encoded'), texts.filter(bool))), min_size=1, max_size=5))
    written = []
    decoded = ''
    previous = None
    for kind, text in segments:
        written.append(draw(encoded_words(text)) if kind == 'encoded' else text)
        separator = '' if previous is None or (previous == kind == 'encoded') else ' '
        decoded += separator + text
        previous = kind
    return fold(' '.join(written), draw(st.lists(st.integers(0, 6), max_size=2))), decoded


@hypothesis.given(subjects())
def test_subject(subject: tuple[str, str]) -> None:
    """H3: a subject with encoded words (B and Q, several charsets, folded) is decoded to its text."""
    value, expected = subject

    assert parse(message(['From: a@example.org', f'Subject: {value}']))['header']['subject'] == expected


@hypothesis.given(st.text(ALNUM + '=?_ ', max_size=40), st.sampled_from(('utf-8', 'x-unknown', 'iso-8859-1')))
def test_malformed_encoded_words(payload: str, charset: str) -> None:
    """H3: malformed encoded words (unknown charset, broken base64 or quoted-printable) do not fail the parse."""
    value = f'=?{charset}?B?{payload}?= =?{charset}?Q?{payload}?= tail'

    assert isinstance(parse(message(['From: a@example.org', f'Subject: {value}']))['header']['subject'], str)


# --- H4: date ----------------------------------------------------------------------------------------------------------------------------

ZONES = {'UT': 0, 'GMT': 0, 'EST': -300, 'EDT': -240, 'CST': -360, 'CDT': -300, 'MST': -420, 'MDT': -360, 'PST': -480, 'PDT': -420}


@st.composite
def dates(draw: st.DrawFn) -> tuple[str, dt.datetime]:
    """An RFC 5322 date (also with the obsolete two-digit year, named zones and comments) and the moment it stands for."""
    two_digit_year = draw(st.booleans())
    # naive bounds (st.datetimes() needs them naive), the zone is added below
    first, last = dt.datetime(2000 if two_digit_year else 1971, 1, 1), dt.datetime(2049 if two_digit_year else 2099, 12, 31)  # noqa: DTZ001
    naive = draw(st.datetimes(first, last))
    naive = naive.replace(microsecond=0)
    if draw(st.booleans()):
        zone_name = draw(st.sampled_from(sorted(ZONES)))
        offset, zone = ZONES[zone_name], zone_name
    else:
        offset = draw(st.integers(-14 * 4, 14 * 4)) * 15
        zone = f'{"+" if offset >= 0 else "-"}{abs(offset) // 60:02d}{abs(offset) % 60:02d}'
    moment = naive.replace(tzinfo=dt.timezone(dt.timedelta(minutes=offset)))
    year = f'{naive.year % 100:02d}' if two_digit_year else str(naive.year)
    day = naive.strftime('%a, ') if draw(st.booleans()) else ''
    value = f'{day}{naive.day} {naive.strftime("%b")} {year} {naive:%H:%M:%S} {zone}'
    if draw(st.booleans()):
        value += f' {draw(comments())}'
    return value, moment


@hypothesis.given(dates())
def test_date(date: tuple[str, dt.datetime]) -> None:
    """H4: a date in any RFC 5322 form gives the moment it stands for."""
    value, expected = date

    assert parse(message(['From: a@example.org', f'Date: {value}']))['header']['date'] == expected


@hypothesis.given(st.text(ALNUM + ' ,:+-()', max_size=40))
def test_malformed_date(value: str) -> None:
    """H4: an invalid date does not fail the parse and gives a datetime with a time zone."""
    date = parse(message(['From: a@example.org', f'Date: {value}']))['header']['date']

    assert isinstance(date, dt.datetime)
    assert date.tzinfo is not None


# --- H5: trace fields ---------------------------------------------------------------------------------------------------------------------

public_ips = st.ip_addresses(v=4).filter(lambda ip: ip.is_global).map(str)


@st.composite
def received_lines(draw: st.DrawFn) -> tuple[str, str, str, str, str]:
    """A Received field (RFC 5321 4.4) and its sending host, its IP address, the receiving host and the recipient."""
    sender, ip, receiver, recipient = draw(hosts), draw(public_ips), draw(hosts), draw(addresses)
    clauses = [f'from {sender} ({draw(st.sampled_from((sender, "unknown")))} [{ip}])', f'by {receiver}']
    if draw(st.booleans()):
        clauses.append(f'with {draw(st.sampled_from(("ESMTP", "ESMTPS", "SMTP", "LMTP")))}')
    if draw(st.booleans()):
        clauses.append(f'id {draw(words)}')
    clauses.append(f'for <{recipient}>')
    if draw(st.booleans()):
        clauses.insert(draw(st.integers(0, len(clauses))), draw(comments(f'from fake.{draw(hosts)} by relay')))
    value = ' '.join(clauses) + f'; {draw(dates())[0]}'
    return fold(value, draw(st.lists(st.integers(0, 12), max_size=3))), sender, ip, receiver, recipient.lower()


@hypothesis.given(st.lists(received_lines(), min_size=1, max_size=4))
def test_received(lines: list[tuple[str, str, str, str, str]]) -> None:
    """H5: the hosts, IP addresses and recipients of the trace fields are reported, and nothing which is not in them."""
    header = parse(message(['From: a@example.org', *(f'Received: {line[0]}' for line in lines)]))['header']
    flat = ' '.join(line[0] for line in lines).lower()

    for _, sender, ip, receiver, recipient in lines:
        assert {sender, receiver} <= set(header.get('received_domain', []))
        assert ip in header.get('received_ip', [])
        assert recipient in header.get('received_foremail', [])
    for key in ('received_domain', 'received_ip', 'received_email', 'received_foremail'):
        assert all(value in flat for value in header.get(key, [])), key


# --- H6: authentication results ----------------------------------------------------------------------------------------------------------

METHODS = ('spf', 'dkim', 'dmarc', 'arc', 'auth', 'iprev')
RESULTS = ('pass', 'fail', 'none', 'neutral', 'softfail', 'temperror', 'permerror', 'policy')


@hypothesis.given(st.lists(st.tuples(st.sampled_from(METHODS), st.sampled_from(RESULTS), st.booleans()), min_size=1, max_size=6), hosts)
def test_authentication_results(results: list[tuple[str, str, bool]], authserv: str) -> None:
    """H6: the results of an Authentication-Results field are reported per method; a result in a comment is not."""
    parts = []
    for method, result, commented in results:
        part = f'{method}={result} smtp.mailfrom={authserv}'
        if commented:
            part += ' (dkim=pass header.d=forged.example)'
        parts.append(part)
    field = f'Authentication-Results: {authserv}; ' + ';\r\n '.join(parts)
    expected: dict[str, list[str]] = {}
    for method, result, _ in results:
        expected.setdefault(method, []).append(result)

    assert parse(message(['From: a@example.org', field]))['header']['authentication'] == expected


# --- H7: attachment file names -----------------------------------------------------------------------------------------------------------

file_stems = st.text(st.characters(codec='utf-8', categories=('L', 'N'), exclude_characters='\x85'), min_size=1, max_size=20)


@st.composite
def file_names(draw: st.DrawFn) -> tuple[str, str]:
    """A Content-Disposition with a file name split by RFC 2231 (continuations, charset), and the file name."""
    name = draw(file_stems) + '.' + draw(st.sampled_from(('exe', 'pdf', 'docm', 'js', 'html', 'zip')))
    cuts = sorted(set(draw(st.lists(st.integers(1, max(1, len(name) - 1)), max_size=3))))
    pieces = [name[a:b] for a, b in zip([0, *cuts], [*cuts, len(name)], strict=True) if name[a:b]]
    if name.isascii() and draw(st.booleans()):
        params = [f'filename*{i}="{piece}"' for i, piece in enumerate(pieces)]
    else:
        params = [
            f'filename*{i}*={"utf-8" + chr(39) * 2 if i == 0 else ""}{"".join(f"%{byte:02X}" for byte in piece.encode())}' for i, piece in enumerate(pieces)
        ]
    return 'attachment;\r\n ' + ';\r\n '.join(params), name


@hypothesis.given(file_names())
def test_attachment_file_name(file_name: tuple[str, str]) -> None:
    """H7: a file name split by RFC 2231 is joined, so the extension of `in` + `voice.ex` + `e` is "exe"."""
    disposition, expected = file_name
    body = (
        'Content-Type: multipart/mixed; boundary="b"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n'
        f'--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: {disposition}\r\nContent-Transfer-Encoding: base64\r\n\r\n'
        'AAAA\r\n--b--\r\n'
    )

    (attachment,) = parse(message(['From: a@example.org'], body))['attachment']

    assert attachment['filename'] == expected
    assert attachment['extension'] == expected.rsplit('.', 1)[1]


# --- H8: whole header block --------------------------------------------------------------------------------------------------------------


@st.composite
def header_blocks(draw: st.DrawFn) -> list[tuple[str, str]]:
    """A header block of valid fields: duplicates, names in any case, UTF-8 values (RFC 6532), extension fields."""
    fields = [
        ('From', draw(mailboxes()).text),
        ('To', draw(address_lists())[0]),
        ('Cc', draw(address_lists())[0]),
        ('Subject', draw(subjects())[0]),
        ('Subject', draw(texts)),
        ('Date', draw(dates())[0]),
        ('Received', draw(received_lines())[0]),
        ('Message-ID', f'<{draw(words)}@{draw(hosts)}>'),
        ('Reply-To', draw(mailboxes()).text),
        (f'X-{draw(words)}', draw(texts)),
    ]
    chosen = draw(st.lists(st.sampled_from(fields), min_size=1, max_size=12))
    return [(draw(st.sampled_from((name, name.lower(), name.upper()))), value) for name, value in chosen]


def _structured(header: dict[str, typing.Any]) -> dict[str, typing.Any]:
    keys = ('from', 'to', 'cc', 'subject', 'date', 'received_domain', 'received_ip', 'received_foremail', 'authentication')
    return {key: header.get(key) for key in keys}


@hypothesis.given(header_blocks())
def test_header_block(fields: list[tuple[str, str]]) -> None:
    """H8: any block of valid fields is parsed and exported; its fields are kept, and unfolding the values does not change the result."""
    folded = parse(message(f'{name}: {value}' for name, value in fields))['header']
    unfolded = parse(message(f'{name}: {value.replace(chr(13) + chr(10) + " ", " ")}' for name, value in fields))['header']

    # fields with an empty value are left out (see `headers.fields()`)
    assert {name.lower() for name, value in fields if value.strip()} <= set(folded['header'])
    assert _structured(folded) == _structured(unfolded)
