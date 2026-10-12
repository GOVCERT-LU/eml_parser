"""Tests for the decoding of text bodies."""

import pytest

import eml_parser.decode
import eml_parser.parser


class TestDecodeBody:
    """Undecodable bytes must never join the neighbouring tokens."""

    def test_declared_charset(self) -> None:
        """Valid data is decoded with the declared charset."""
        assert eml_parser.decode.decode_body('grüße'.encode('latin-1'), 'iso-8859-1') == 'grüße'

    @pytest.mark.parametrize('charset', ['foo-bar', 'utf\x008', None])
    def test_missing_or_unknown_charset(self, charset: str | None) -> None:
        """No exception and nothing lost."""
        assert eml_parser.decode.decode_body(b'visit http://evil.example.com/', charset) == 'visit http://evil.example.com/'

    def test_undecodable_byte_is_not_dropped_or_kept(self) -> None:
        """An invalid byte must neither turn good<byte>.evil.com into good.evil.com nor stay in the text as U+FFFD."""
        result = eml_parser.decode.decode_body(b'http://good\xff.evil.com/x', 'utf-8')

        assert 'good.evil.com' not in result
        assert '\ufffd' not in result
        assert 'evil.com/x' in result

    def test_end_to_end(self) -> None:
        """The invalid byte does not create a different host and does not end up in an indicator."""
        raw = (
            b'From: a@example.com\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n'
            b'visit http://good\xff.evil.com/x and http://fine.example.org/a now'
        )
        parsed = eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(raw)
        uris = parsed['body'][0].get('uri', [])

        assert 'http://good.evil.com/x' not in uris
        assert 'http://fine.example.org/a' in uris
        assert not any('\ufffd' in uri for uri in uris)


class TestWrongDeclaredCharset:
    """The declared charset is often wrong."""

    TEXT = 'Привет, это тестовое сообщение для проверки кодировки. Посетите сайт'

    def test_wrong_charset_is_corrected(self) -> None:
        """Cyrillic text declared as us-ascii is detected."""
        assert eml_parser.decode.decode_body(self.TEXT.encode('cp1251'), 'us-ascii') == self.TEXT

    def test_valid_declaration_is_not_second_guessed(self) -> None:
        """No detection if nothing was lost."""
        assert eml_parser.decode.decode_body('grüße'.encode('latin-1'), 'iso-8859-1') == 'grüße'

    def test_huge_body_skips_detection(self) -> None:
        """Bodies above the size limit keep the declared charset (the lost bytes are replaced with spaces)."""
        data = b'\xff' * (eml_parser.decode.MAX_CHARSET_DETECTION_SIZE + 1)

        assert set(eml_parser.decode.decode_body(data, 'utf-8')) == {' '}
