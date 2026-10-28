import email
import email.message
import email.policy

import pytest

import eml_parser.decode
import eml_parser.parser

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
    walked = [(part.get_content_type(), boundary) for part, boundary in eml_parser.parser.iter_parts(msg, recursion_limit=10)]

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
    walked_within_limit = list(eml_parser.parser.iter_parts(msg, recursion_limit=2))

    # Assert
    assert len(walked_within_limit) == 6
    with pytest.raises(RecursionError):
        list(eml_parser.parser.iter_parts(msg, recursion_limit=1))


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


def test_compat32_policy_restores_policy_also_on_exception() -> None:
    # Arrange
    msg = email.message_from_bytes(b'Subject: x\n\nbody', policy=email.policy.default)

    # Act
    with eml_parser.decode.compat32_policy(msg) as patched:
        policy_inside = patched.policy
    policy_after_exit = msg.policy

    with pytest.raises(ValueError, match='boom'), eml_parser.decode.compat32_policy(msg):
        raise ValueError('boom')

    # Assert
    assert policy_inside is email.policy.compat32
    assert policy_after_exit is email.policy.default
    assert msg.policy is email.policy.default


def test_get_hash_rejects_unknown_type() -> None:
    with pytest.raises(ValueError, match='Invalid hash type'):
        eml_parser.parser.EmlParser.get_hash(b'x', 'sha3_256')
