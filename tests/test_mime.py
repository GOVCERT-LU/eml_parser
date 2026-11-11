"""Tests for `eml_parser.mime`: walking and repairing the MIME structure and the text parts."""

import datetime as dt
import email
import email.policy
from email.message import EmailMessage

import pytest

import eml_parser.mime
import eml_parser.parser
import tests.table

BODY = (
    b'--x1\r\nContent-Type: text/plain\r\n\r\nvisit http://evil.example.com/a\r\n'
    b'--x1\r\nContent-Type: application/octet-stream; name="a.bin"\r\nContent-Transfer-Encoding: base64\r\n\r\nSGVsbG8=\r\n--x1--\r\n'
)


def _parse(content_type: bytes, body: bytes = BODY) -> dict:
    return eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(b'From: a@example.com\r\nContent-Type: ' + content_type + b'\r\n\r\n' + body)


def test_missing_boundary() -> None:
    """Body and attachment are found, the defect is still reported."""
    parsed = _parse(b'multipart/mixed')

    assert parsed['body'][0]['uri'] == ['http://evil.example.com/a']
    assert len(parsed['attachment']) == 1
    assert 'NoBoundaryInMultipartDefect' in parsed['header']['defect']


def test_wrong_boundary() -> None:
    """A declared boundary which is not in the payload is replaced by the guessed one."""
    parsed = _parse(b'multipart/mixed; boundary="nope"')

    assert parsed['body'][0]['uri'] == ['http://evil.example.com/a']
    assert len(parsed['attachment']) == 1


def test_intact_message_is_untouched() -> None:
    """A correct boundary is kept and no defect is invented."""
    parsed = _parse(b'multipart/mixed; boundary="x1"')

    assert len(parsed['attachment']) == 1
    assert 'defect' not in parsed['header']


def test_without_any_delimiter_the_payload_is_scanned_as_text() -> None:
    """Nothing to split: the content is still searched for indicators."""
    parsed = _parse(b'multipart/mixed', b'visit http://evil.example.com/z\r\n')

    assert parsed['body'][0]['uri'] == ['http://evil.example.com/z']
    assert 'attachment' not in parsed


def test_nested_broken_multipart() -> None:
    """A broken part inside a repaired one is repaired too."""
    inner = b'--in\r\nContent-Type: text/plain\r\n\r\nnested http://nested.example.com/x\r\n--in--\r\n'
    parsed = _parse(b'multipart/mixed', b'--x1\r\nContent-Type: multipart/alternative\r\n\r\n' + inner + b'--x1--\r\n')

    assert parsed['body'][0]['uri'] == ['http://nested.example.com/x']


def test_boundary_which_the_stdlib_decodes_does_not_loop_forever() -> None:
    """A guessed boundary containing an encoded word is decoded by the stdlib and never matches; the part is then scanned as text."""
    raw = (
        b'From: a@b.com\r\nContent-Type: multipart/mixed; boundary="b"\r\n\r\n'
        b'--=?x?q?=ff?=b\r\nContent-Type: text/html\r\n\r\nhttp://evil.example.com/x\r\n--b--\r\n'
    )

    result = eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(raw)

    assert 'evil.example.com' in result['body'][0]['domain']


def test_deeply_nested_parts_do_not_raise() -> None:
    """Thousands of nested multiparts, each announcing the next one, exceed the recursion limit of the stdlib parser."""
    nested = b''.join(b'--b%d\r\nContent-Type: multipart/mixed; boundary="b%d"\r\n\r\n' % (i, i + 1) for i in range(5000))

    assert eml_parser.parser.EmlParser().decode_email_bytes(b'From: a@b.com\r\nContent-Type: multipart/mixed\r\n\r\n' + nested)


HEADER = b'From: a@b.example\nTo: c@d.example\nSubject: s\nMIME-Version: 1.0\n'
RFC822 = HEADER + b'Content-Type: message/rfc822\n\n'

# Each message made the parse raise, mostly from the stdlib: its parameter parser (IndexError), charsets without an error
# handler (UnicodeError), header fields it refuses to store or write again (ValueError, HeaderWriteError), its address
# parser while serializing an attached message (AttributeError) and its text generator re-encoding 8-bit text with an
# unknown, unsuitable or RFC 2231 charset (LookupError, TypeError, UnicodeEncodeError), and a NUL in an RFC 2231 charset (ValueError).
# UTF-7 decoded to lone surrogates, which cannot be hashed (UnicodeEncodeError).
MALFORMED_MESSAGES = [
    HEADER + b'Content-Type: text/plain; a*\n\nbody\n',
    HEADER + b'Content-Type: multipart/mixed; boundary=X\n\n--X\nContent-Type: application/pdf\nContent-Disposition: attachment; filename*\n\nAAAA\n--X--\n',
    HEADER + b'Content-Type: multipart/mixed; charset=idna\n\n--b1\nContent-Type: text/plain\n\nbody \xff\n--b1--\n',
    HEADER
    + b'Content-Type: multipart/mixed; boundary=X\n\n--X\nContent-Type: text/html; charset=idna\nContent-Disposition: attachment; filename=a.html\n\n\xff\n--X--\n',
    HEADER + b'Content-Type: multipart/mixed; x\x1dy=1\n\n--b1\nContent-Type: text/plain\n\nbody\n--b1--\n',
    RFC822 + b'Sender: \xff:?];=?\n',
    RFC822
    + b'Content-Type: multipart/digest; boundary='
    + b'x' * 80
    + b'\n--'
    + b'x' * 80
    + b'\nContent-Type: text/; charset="x-unknown"\nQ\xc7$B\x87\xf7\xff\n--'
    + b'x' * 80
    + b'\nContent-Type: multipart/digest; boundary==_P\n--=_P\n\xe1i\x04\n',
    RFC822
    + b"Content-Type: multipart/; boundary = \"b1\n--b1\nContent-Type: multipart/; boundary= \n--b2\n\xc3\xa4\n--b1\nContent-Type: application/pdf;charset*=utf-8''utf-16\n\xfe\n",
    RFC822 + b"Content-Type: multipart/encrypted; boundary = \"\n--other\nContent-Type: MESSAGE/RFC822;cha\x0cset*=utf-8''gb2312\n\xef\xbb\xbfBOM text",
    RFC822
    + b'Content-Type: multipart/mixed; boundary=" "\n-- \nContent-Type: multipart; charset="utf-16le"\n\xd0\x1a\n-- \nContent-Type: multipart/related; boundary=""\n--other\n\xff\xfe\x00h\x00i',
    HEADER
    + b"Content-Type: multipart/mixed; boundary=X\n\n--X\nContent-Type: application/pdf\nContent-Disposition: attachment; filename*=bogu\x00''%FF%FE\n\nAAAA\n--X--\n",
    HEADER + b'Content-Type: text/plain; charset=utf-7\n\na+2AA-b\n',
]


def test_malformed_mime_messages_are_parsed() -> None:
    def check(raw: bytes) -> None:
        parsed = eml_parser.parser.EmlParser(include_raw_body=True, include_attachment_data=True).decode_email_bytes(raw)

        assert parsed['header']['from'] == 'a@b.example'

    tests.table.assert_all_cases(check, MALFORMED_MESSAGES)


def mime_bomb_a(depth: int = 124) -> bytes:
    inner = b'From: a@a\r\nTo: b@b\r\nContent-Type: text/plain\r\n\r\n.\r\n'
    msg = inner
    for i in range(depth):
        b = f'B{i}'.encode()
        msg = (
            (b'Content-Type: multipart/mixed; boundary="' + b + b'"\r\n\r\n--' + b + b'\r\nContent-Type: message/rfc822\r\n\r\n')
            + msg
            + b'\r\n--'
            + b
            + b'--\r\n'
        )
    return msg


def mime_bomb_b(depth: int = 124) -> EmailMessage:
    msg = EmailMessage()
    msg.set_content('This is the core of the onion.')

    for i in range(depth):
        wrapper = EmailMessage()
        wrapper['Subject'] = f'Nesting Level {depth - i}'
        wrapper['From'] = 'sender@test.com'
        wrapper['To'] = 'receiver@test.com'
        # Add the previous message as a part of the new one
        wrapper.make_mixed()
        wrapper.attach(msg)
        msg = wrapper

    return msg


def mime_bomb_c(depth: int = 124) -> bytes:
    msg = b'From: leaf@test.com\r\nTo: root@test.com\r\nSubject: The Core\r\nContent-Type: text/plain\r\n\r\nThis is the innermost content.'

    for i in range(depth):
        boundary = f'boundary_{i}'.encode()

        headers = (
            b'From: level' + str(i).encode() + b'@test.com\r\n'
            b'To: recipient@test.com\r\n'
            b'Subject: Nesting Level ' + str(depth - i).encode() + b'\r\n'
            b'Date: ' + dt.datetime.now(tz=getattr(dt, 'UTC', dt.UTC)).strftime('%a, %d %b %Y %H:%M:%S +0000').encode() + b'\r\n'
            b'MIME-Version: 1.0\r\n'
            b'Content-Type: multipart/mixed; boundary="' + boundary + b'"\r\n\r\n'
        )

        # Construct the MIME structure
        # Note: --boundary is the start, --boundary-- is the end
        body = b'--' + boundary + b'\r\nContent-Type: message/rfc822\r\n\r\n' + msg + b'\r\n--' + boundary + b'--'

        msg = headers + body

    return msg


class TestMimeBomb:
    def test_mime_bomb_a(self) -> None:
        bomb = mime_bomb_a(depth=124)
        eml_parser.EmlParser.MULTIPART_RECURSION_LIMIT = 100
        ep = eml_parser.EmlParser()

        with pytest.raises(RecursionError):
            ep.decode_email_bytes(bomb)

    def test_mime_bomb_b(self) -> None:
        bomb = mime_bomb_b(depth=124)
        eml_parser.EmlParser.MULTIPART_RECURSION_LIMIT = 100
        ep = eml_parser.EmlParser()

        with pytest.raises(RecursionError):
            ep.decode_email_bytes(bomb.as_bytes())

    def test_mime_bomb_c(self) -> None:
        bomb = mime_bomb_c(depth=124)
        eml_parser.EmlParser.MULTIPART_RECURSION_LIMIT = 100
        ep = eml_parser.EmlParser()

        with pytest.raises(RecursionError):
            ep.decode_email_bytes(bomb)


def _mail(content_type: str, filename: str, disposition: str = 'attachment') -> bytes:
    return (
        b'From: a@example.com\r\nContent-Type: multipart/mixed; boundary="b"\r\n\r\n'
        b'--b\r\nContent-Type: text/plain\r\n\r\nhello\r\n'
        + f'--b\r\nContent-Type: {content_type}; name="{filename}"\r\nContent-Disposition: {disposition}; filename="{filename}"\r\n\r\n'.encode()
        + b'[InternetShortcut]\r\nURL=http://evil.example.com/dl\r\n--b--\r\n'
    )


def _parse_attachment(content_type: str, filename: str) -> dict:
    return eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(_mail(content_type, filename))


@pytest.mark.parametrize(
    ('content_type', 'filename'),
    [
        ('application/octet-stream', 'x.url'),
        ('application/octet-stream', 'run.PS1'),
        ('text/plain', 'note.txt'),
        ('image/svg+xml', 'logo'),
        ('application/javascript', 'x.dat'),
    ],
)
def test_attachment_is_scanned_and_kept(content_type: str, filename: str) -> None:
    """By extension or content type: the URL inside is found and the file stays in the attachment list."""
    parsed = _parse_attachment(content_type, filename)

    assert any('http://evil.example.com/dl' in body.get('uri', []) for body in parsed['body'])
    assert [a['filename'] for a in parsed['attachment']] == [filename]


@pytest.mark.parametrize(
    ('content_type', 'filename'),
    [
        ('application/octet-stream', 'x.bin'),
        ('application/xml', 'data.xml'),
        ('application/json', 'data.json'),
        ('text/csv', 'list.csv'),
        ('text/xml', 'schema.xsd'),
    ],
)
def test_binary_and_data_attachments_are_not_scanned(content_type: str, filename: str) -> None:
    """Binary files and data formats (XML, JSON, CSV) are only listed, their namespace and schema URLs are not indicators."""
    parsed = _parse_attachment(content_type, filename)

    assert not any(body.get('uri') for body in parsed['body'])
    assert [a['filename'] for a in parsed['attachment']] == [filename]


def test_large_attachment_is_not_scanned(monkeypatch: pytest.MonkeyPatch) -> None:
    """Above the limit the attachment is only listed."""
    monkeypatch.setattr(eml_parser.constants, 'MAX_TEXT_ATTACHMENT_SIZE', 10)
    parsed = _parse_attachment('text/plain', 'big.txt')

    assert not any(body.get('uri') for body in parsed['body'])
    assert [a['filename'] for a in parsed['attachment']] == ['big.txt']


NESTED_MESSAGE = b"""Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: text/plain

first
--outer
Content-Type: multipart/alternative; boundary="inner"

--inner
Content-Type: text/plain

second
--inner
Content-Type: text/html

<p>third</p>
--inner--
--outer
Content-Type: text/plain

fourth
--outer--
"""


def test_iter_parts_walks_depth_first_with_enclosing_boundary() -> None:
    # Arrange
    msg = email.message_from_bytes(NESTED_MESSAGE, policy=email.policy.default)

    # Act
    walked = [(part.get_content_type(), boundary) for part, boundary in eml_parser.mime.iter_parts(msg, recursion_limit=10)]

    # Assert
    assert walked == [
        ('multipart/mixed', None),
        ('text/plain', 'outer'),
        ('multipart/alternative', 'outer'),
        ('text/plain', 'inner'),
        ('text/html', 'inner'),
        ('text/plain', 'outer'),
    ]


def test_iter_parts_recursion_limit() -> None:
    # Arrange
    msg = email.message_from_bytes(NESTED_MESSAGE, policy=email.policy.default)

    # Act
    walked_within_limit = list(eml_parser.mime.iter_parts(msg, recursion_limit=2))

    # Assert
    assert len(walked_within_limit) == 6
    with pytest.raises(RecursionError):
        list(eml_parser.mime.iter_parts(msg, recursion_limit=1))


def test_text_parts_keep_their_enclosing_boundary() -> None:
    # Arrange
    parser = eml_parser.parser.EmlParser(include_raw_body=True)

    # Act
    bodies = parser.decode_email_bytes(NESTED_MESSAGE)['body']

    # Assert
    assert [(body['content'].strip(), body['boundary']) for body in bodies] == [
        ('first', 'outer'),
        ('second', 'inner'),
        ('<p>third</p>', 'inner'),
        ('fourth', 'outer'),
    ]


# The parts of a multipart, once with the declared boundary and once with a boundary which does not occur (repaired).
TWIN_PARTS = (
    b'--real\nContent-Type: text/plain; charset=iso-8859-1\nContent-Transfer-Encoding: 8bit\n\nGr\xfc\xdfe http://b\xfccher.example/\n'
    b'--real\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename="\xe2\x82\xacna\xc3\xafve.txt"\n\n\xff\xfe\x00\x01\n'
    b'--real--\n'
)


def _parse_twin(boundary: bytes) -> dict:
    message = b'From: a@b.example\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="' + boundary + b'"\n\n' + TWIN_PARTS
    return eml_parser.parser.EmlParser(include_raw_body=True, include_attachment_data=True).decode_email_bytes(message)


def test_repaired_multipart_is_parsed_like_a_well_formed_one() -> None:
    # Arrange: 8-bit text and file name, which the repair decoded with the (missing) charset of the multipart before
    well_formed = _parse_twin(b'real')

    # Act
    repaired = _parse_twin(b'missing')

    # Assert
    assert repaired['body'][0]['content'] == 'Grüße http://bücher.example/'
    assert repaired['body'] == well_formed['body']
    assert repaired['attachment'] == well_formed['attachment']


def test_find_header_start_without_header_line() -> None:
    # Arrange: the only colon is in a line which is no header field, without a line break after it
    data = b'no header field: here'

    # Act
    start = eml_parser.mime.find_header_start(data)

    # Assert
    assert start == 0


def test_declared_boundary_inside_a_line_does_not_split() -> None:
    # Arrange: the declared boundary occurs, but not as a delimiter line, and there is no other one
    raw = b'From: a@b.example\nContent-Type: multipart/mixed; boundary=X\n\nsee a--X and http://evil.example.com/\n'

    # Act
    body = eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(raw)['body']

    # Assert
    assert len(body) == 1
    assert body[0]['uri'] == ['http://evil.example.com/']


def test_repaired_multipart_with_an_encoded_transfer_encoding_is_split() -> None:
    # Arrange: the stdlib ignores the transfer encoding of a multipart, the delimiter lines are plain text
    raw = (
        b'From: a@b.example\nContent-Type: multipart/mixed; boundary=missing\nContent-Transfer-Encoding: quoted-printable\n\n'
        b'--real\nContent-Type: text/plain\n\nvisit http://evil.example.com/\n--real--\n'
    )

    # Act
    body = eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(raw)['body']

    # Assert
    assert [(part['content_type'], part['boundary']) for part in body] == [('text/plain', 'real')]
    assert body[0]['uri'] == ['http://evil.example.com/']
