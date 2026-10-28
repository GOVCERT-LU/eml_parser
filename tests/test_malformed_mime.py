import eml_parser.decode
import eml_parser.parser
import tests.table

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


def test_decode_body_replaces_lone_surrogates() -> None:
    # Arrange: UTF-7 encodes UTF-16 code units, "+2AA-" is the lone high surrogate U+D800
    data = b'a+2AA-b'

    # Act
    text = eml_parser.decode.decode_body(data, 'utf-7')

    # Assert
    assert text == 'a b'
