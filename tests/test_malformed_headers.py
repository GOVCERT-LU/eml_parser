import email
import email.policy

import eml_parser.decode
import eml_parser.parser
import tests.table

# Each line made the stdlib parsers raise: an IndexError in the address parser, an AttributeError or TypeError for 8-bit values.
MALFORMED_LINES = [
    b'Cc: "',
    b'Reply-To: "',
    b'To: x:"',
    b'Cc: :;]Test.=E9;=\xffbq;? q',
    b'To: \xff:?];=?',
    b'Sender: \xff:?];=?',
]

TOP_LEVEL = b'From: a@b.example\n%s\nSubject: s\n\nbody\n'
IN_ATTACHMENT = b"""From: a@b.example
Content-Type: multipart/mixed; boundary=X

--X
Content-Type: text/plain

body
--X
Content-Type: application/octet-stream
Content-Disposition: attachment; filename=a.bin
%s

AAAA
--X--
"""


def test_malformed_header_lines_are_collected() -> None:
    def check(line: bytes) -> None:
        name = line.partition(b':')[0].decode().lower()
        parser = eml_parser.parser.EmlParser()

        top_level = parser.decode_email_bytes(TOP_LEVEL % line)
        in_attachment = parser.decode_email_bytes(IN_ATTACHMENT % line)

        assert all(isinstance(value, str) for value in top_level['header']['header'][name])
        assert all(isinstance(value, str) for value in in_attachment['attachment'][0]['content_header'][name])
        eml_parser.decode.export_to_json(top_level)

    tests.table.assert_all_cases(check, MALFORMED_LINES)


def test_addresses_are_recovered_from_8bit_address_fields() -> None:
    # Arrange
    raw = b'From: x\xff:? <a@b.example>\nTo: y\xff:?;\xff <c@d.example>\nSubject: s\n\nbody\n'

    # Act
    header = eml_parser.parser.EmlParser().decode_email_bytes(raw)['header']

    # Assert
    assert header['from'] == 'a@b.example'
    assert header['to'] == ['c@d.example']


def test_header_items_falls_back_to_compat32() -> None:
    # Arrange
    msg = email.message_from_bytes(b'Cc: "\nSubject: s\n\nbody\n', policy=email.policy.default)

    # Act
    items = eml_parser.decode.header_items(msg)

    # Assert
    assert items == [('Cc', '"'), ('Subject', 's')]
    assert msg.policy is email.policy.default


def test_rfc2047_decode_keeps_undecodable_values() -> None:
    # Arrange: invalid base64 in the encoded word, the stdlib raises HeaderParseError
    value = '=?utf-8?B?==E9?='

    # Act
    decoded = eml_parser.decode.rfc2047_decode(value)

    # Assert
    assert decoded == value


def test_deeply_nested_address_groups_do_not_exhaust_the_stack() -> None:
    # Arrange: every colon opens a group, the stdlib address parser recurses once per group
    nested = b'a:' * 5000 + b'x@y.example'
    raw = b'From: ' + nested + b'\nTo: ' + nested + b'\n\nbody\n'

    # Act
    header = eml_parser.parser.EmlParser().decode_email_bytes(raw)['header']

    # Assert
    assert header['from'] == 'x@y.example'
    assert header['to'] == ['x@y.example']
