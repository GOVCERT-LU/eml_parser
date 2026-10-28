import json

import eml_parser.decode
import eml_parser.parser

MULTIPART_MESSAGE = b"""From: a@example.com
Content-Type: multipart/alternative; boundary="b1"

--b1
Content-Type: text/plain
Content-Transfer-Encoding: quoted-printable

Visit http://example.com/ caf=C3=A9
--b1
Content-Type: text/html

<p>html</p>
--b1--
"""


def test_raw_body_lists_the_text_parts() -> None:
    # Arrange
    parser = eml_parser.parser.EmlParser(include_raw_body=True)

    # Act
    parsed = parser.decode_email_bytes(MULTIPART_MESSAGE)
    exported = json.loads(eml_parser.decode.export_to_json(parsed))

    # Assert
    assert parsed['raw_body'] == [('quoted-printable', 'Visit http://example.com/ café'), ('', '<p>html</p>')]
    assert exported['raw_body'] == [['quoted-printable', 'Visit http://example.com/ café'], ['', '<p>html</p>']]


def test_raw_body_is_absent_by_default() -> None:
    # Arrange
    parser = eml_parser.parser.EmlParser()

    # Act
    parsed = parser.decode_email_bytes(MULTIPART_MESSAGE)

    # Assert
    assert 'raw_body' not in parsed
