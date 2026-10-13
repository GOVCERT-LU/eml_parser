import json
import os
import subprocess
import sys

import eml_parser.decode
import eml_parser.parser

RAW_EMAIL = (
    b'From: a@example.com\r\nTo: b@example.com\r\nSubject: hi\r\n'
    b'Received: from mx3.example.net (mx3.example.net [203.0.113.3]) by mx2.example.org for <c@example.com>; Mon, 5 Oct 2026 09:12:44 +0200\r\n'
    b'Received: from mx1.example.com (mx1.example.com [198.51.100.1]) by mx3.example.net for <d@example.com>; Mon, 5 Oct 2026 09:11:44 +0200\r\n'
    b'Received: from mx0.example.org (mx0.example.org [192.0.2.7]) by mx1.example.com for <c@example.com>; Mon, 5 Oct 2026 09:10:44 +0200\r\n'
    b'\r\nbody'
)

SCRIPT = """
import json, sys
import eml_parser.parser
header = eml_parser.parser.EmlParser().decode_email_bytes(sys.stdin.buffer.read())['header']
print(json.dumps({key: header.get(key) for key in ('received_email', 'received_domain', 'received_ip', 'received_foremail')}))
"""


def test_received_lists_are_in_order_of_first_appearance() -> None:
    header = eml_parser.parser.EmlParser().decode_email_bytes(RAW_EMAIL)['header']

    assert header['received_ip'] == ['203.0.113.3', '198.51.100.1', '192.0.2.7']
    assert header['received_foremail'] == ['c@example.com', 'd@example.com']
    assert header['received_domain'][:2] == ['mx3.example.net', 'mx2.example.org']


def test_received_lists_are_independent_of_hash_seed() -> None:
    results = set()

    for seed in ('0', '1', '2', '123', '4242'):
        env = {**os.environ, 'PYTHONHASHSEED': seed, 'PYTHONPATH': os.pathsep.join(sys.path)}
        out = subprocess.run([sys.executable, '-c', SCRIPT], input=RAW_EMAIL, capture_output=True, check=True, env=env)  # noqa: S603
        results.add(json.dumps(json.loads(out.stdout)))

    assert len(results) == 1


def test_workaround_bug_27257_addresses_are_unique_and_ordered() -> None:
    msg = eml_parser.parser.email.message_from_bytes(b'To: b@example.org, a@example.com, b@example.org\r\n\r\nbody')

    assert eml_parser.decode.workaround_bug_27257(msg, 'to') == ['b@example.org', 'a@example.com']
