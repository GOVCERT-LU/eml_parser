import eml_parser.parser
import tests.table

MESSAGE = b"""Received: from relay.example.net (envelope-from <sender@example.net>) by mx.example.com for <john@example.com>; Mon, 1 Jan 2024 10:00:00 +0000
Received: from host (helo user@nodomain) by mx.example.com; Mon, 1 Jan 2024 09:00:00 +0000
From: a@example.org
To: john@example.com

body
"""

RECEIVED_EMAIL_CASES = [
    (False, ['sender@example.net', 'user@nodomain']),
    (True, ['sender@example.net']),
]


def test_received_email_reports_addresses() -> None:
    def check(force_tld: bool, expected: list[str]) -> None:
        # Arrange
        parser = eml_parser.parser.EmlParser(email_force_tld=force_tld, domain_force_tld=force_tld)

        # Act
        header = parser.decode_email_bytes(MESSAGE)['header']

        # Assert: addresses, not their domains, and the recipient of the "for" part is not repeated
        assert header['received_email'] == expected

    tests.table.assert_all_cases(check, RECEIVED_EMAIL_CASES)
