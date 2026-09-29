import datetime
from email.message import EmailMessage

import pytest

import eml_parser.parser


def mime_bomb_a(depth: int = 124):
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


def mime_bomb_b(depth: int = 124):
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


def mime_bomb_c(depth: int = 124):
    msg = b'From: leaf@test.com\r\nTo: root@test.com\r\nSubject: The Core\r\nContent-Type: text/plain\r\n\r\nThis is the innermost content.'

    for i in range(depth):
        boundary = f'boundary_{i}'.encode()

        headers = (
            b'From: level' + str(i).encode() + b'@test.com\r\n'
            b'To: recipient@test.com\r\n'
            b'Subject: Nesting Level ' + str(depth - i).encode() + b'\r\n'
            b'Date: ' + datetime.datetime.now(tz=getattr(datetime, 'UTC', datetime.UTC)).strftime('%a, %d %b %Y %H:%M:%S +0000').encode() + b'\r\n'
            b'MIME-Version: 1.0\r\n'
            b'Content-Type: multipart/mixed; boundary="' + boundary + b'"\r\n\r\n'
        )

        # Construct the MIME structure
        # Note: --boundary is the start, --boundary-- is the end
        body = b'--' + boundary + b'\r\nContent-Type: message/rfc822\r\n\r\n' + msg + b'\r\n--' + boundary + b'--'

        msg = headers + body

    return msg


class TestEMLParser:
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
