import email.message

import eml_parser.parser


def _unnamed_part(parent: email.message.EmailMessage, payload: bytes) -> None:
    parent.add_attachment(payload, maintype='application', subtype='octet-stream')


def _filenames(parsed: dict) -> list[str]:
    return [attachment['filename'] for attachment in parsed['attachment']]


def test_unnamed_attachments_get_unique_names() -> None:
    msg = email.message.EmailMessage()
    msg['From'] = 'a@example.com'
    msg.set_content('body')
    for payload in (b'first', b'second', b'third'):
        _unnamed_part(msg, payload)

    parsed = eml_parser.parser.EmlParser().decode_email_bytes(msg.as_bytes())

    assert _filenames(parsed) == ['part-000', 'part-001', 'part-002']


def test_unnamed_attachments_in_nested_multiparts_get_unique_names() -> None:
    part = b'Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\nQUJD\r\n'
    raw_email = (
        b'From: a@example.com\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="outer"\r\n\r\n'
        b'--outer\r\nContent-Type: text/plain\r\n\r\nbody\r\n'
        b'--outer\r\n' + part + b'--outer\r\nContent-Type: multipart/mixed; boundary="inner"\r\n\r\n'
        b'--inner\r\n' + part + b'--inner\r\n' + part + b'--inner--\r\n'
        b'--outer\r\n' + part + b'--outer--\r\n'
    )

    parsed = eml_parser.parser.EmlParser().decode_email_bytes(raw_email)
    names = _filenames(parsed)

    assert names == ['part-000', 'part-001', 'part-002', 'part-003']


def test_named_attachments_keep_their_name_and_consume_a_number() -> None:
    msg = email.message.EmailMessage()
    msg['From'] = 'a@example.com'
    msg.set_content('body')
    msg.add_attachment(b'one', maintype='application', subtype='octet-stream', filename='invoice.bin')
    _unnamed_part(msg, b'two')

    parsed = eml_parser.parser.EmlParser().decode_email_bytes(msg.as_bytes())

    assert _filenames(parsed) == ['invoice.bin', 'part-001']
