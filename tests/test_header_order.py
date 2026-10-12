import json
import os
import subprocess
import sys

import eml_parser.parser

RAW_EMAIL = (
    b'From: a@example.com\r\nTo: b@example.com\r\nSubject: hi\r\nX-First: 1\r\nX-Second: 2\r\n'
    b'X-Third: 3\r\nMessage-ID: <1@example.com>\r\nX-Fourth: 4\r\n\r\nbody'
)

SCRIPT = """
import json, sys
import eml_parser.parser
raw = sys.stdin.buffer.read()
print(json.dumps(list(eml_parser.parser.EmlParser().decode_email_bytes(raw)['header']['header'])))
"""


def test_header_order_follows_the_message() -> None:
    parsed = eml_parser.parser.EmlParser().decode_email_bytes(RAW_EMAIL)

    assert list(parsed['header']['header']) == ['from', 'to', 'subject', 'x-first', 'x-second', 'x-third', 'message-id', 'x-fourth']


def test_header_order_is_independent_of_hash_seed() -> None:
    results = set()

    for seed in ('0', '1', '2', '123', '4242'):
        env = {**os.environ, 'PYTHONHASHSEED': seed, 'PYTHONPATH': os.pathsep.join(sys.path)}
        out = subprocess.run([sys.executable, '-c', SCRIPT], input=RAW_EMAIL, capture_output=True, check=True, env=env)  # noqa: S603
        results.add(tuple(json.loads(out.stdout)))

    assert len(results) == 1


def test_header_names_differing_only_in_case_are_not_duplicated() -> None:
    raw_email = b'From: a@example.com\r\nX-Foo: one\r\nx-foo: two\r\n\r\nbody'

    parsed = eml_parser.parser.EmlParser().decode_email_bytes(raw_email)

    assert parsed['header']['header']['x-foo'] == ['one', 'two']
