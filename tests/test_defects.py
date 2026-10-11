"""Tests for the reporting of message defects."""

import eml_parser.parser


class TestDefects:
    """Defects must be reported by name."""

    def test_defect_names(self) -> None:
        """A multipart without boundary reports the defect classes, not empty strings."""
        raw = b'From: a@example.com\r\nContent-Type: multipart/mixed\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nhello\r\n--x--\r\n'
        parsed = eml_parser.parser.EmlParser().decode_email_bytes(raw)

        assert parsed['header']['defect'] == ['NoBoundaryInMultipartDefect', 'MultipartInvariantViolationDefect']

    def test_clean_message_has_no_defect_key(self) -> None:
        """No defects, no key."""
        assert 'defect' not in eml_parser.parser.EmlParser().decode_email_bytes(b'From: a@example.com\r\n\r\nhello\r\n')['header']
