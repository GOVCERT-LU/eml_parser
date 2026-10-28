import ipaddress

import eml_parser.parser
import tests.table

MESSAGE = b"""Received: from relay.example.net ([2001:db8:0:0::1]) by mx.example.com; Mon, 1 Jan 2024 10:00:00 +0000
Received: from other.example.net ([192.0.2.7]) by mx.example.com; Mon, 1 Jan 2024 09:00:00 +0000
From: a@example.org
To: b@example.com

Hosts ::ffff:192.0.2.1, 2001:DB8::1, 198.51.100.7 and fe80::1%eth0.
"""

NORMALIZED_IP_CASES = [
    ('192.0.2.1', ipaddress.ip_address('192.0.2.1')),
    ('::ffff:192.0.2.1', ipaddress.ip_address('192.0.2.1')),
    ('2001:DB8:0:0::1', ipaddress.ip_address('2001:db8::1')),
    ('[2001:db8::1]', ipaddress.ip_address('2001:db8::1')),
    ('fe80::1%eth0', ipaddress.ip_address('fe80::1')),
    ('mx.example.com', None),
    ('', None),
]


def test_normalized_ip() -> None:
    def check(text: str, expected: ipaddress.IPv4Address | ipaddress.IPv6Address | None) -> None:
        assert eml_parser.parser._normalized_ip(text) == expected  # noqa: SLF001

    tests.table.assert_all_cases(check, NORMALIZED_IP_CASES)


def test_whitelisted_ips_match_in_any_notation() -> None:
    # Arrange
    parser = eml_parser.parser.EmlParser(include_raw_body=True, pconf={'whiteip': ['2001:DB8::1', '192.0.2.1', 'fe80::1']})

    # Act
    parsed = parser.decode_email_bytes(MESSAGE)

    # Assert
    assert parsed['header']['received_ip'] == ['192.0.2.7']
    assert parsed['body'][0]['ip'] == ['198.51.100.7']


def test_whitelisted_ips_given_as_in_the_text_still_match() -> None:
    # Arrange
    parser = eml_parser.parser.EmlParser(include_raw_body=True, pconf={'whiteip': ['192.0.2.7', '198.51.100.7']})

    # Act
    parsed = parser.decode_email_bytes(MESSAGE)

    # Assert
    assert parsed['header']['received_ip'] == ['2001:db8::1']
    assert '198.51.100.7' not in parsed['body'][0]['ip']
