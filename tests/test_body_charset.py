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

    def test_undecodable_byte_is_a_separator(self) -> None:
        """An invalid byte must neither turn good<byte>.evil.com into good.evil.com nor stay in the text."""
        result = eml_parser.decode.decode_body(b'http://good\xff.evil.com/x', 'utf-8')

        assert result == 'http://good .evil.com/x'

    def test_end_to_end(self) -> None:
        """Undecodable bytes next to indicators (e.g. Windows-1252 quotes in a message declared as UTF-8) do not end up in them."""
        raw = (
            b'From: a@example.com\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n'
            b'visit http://good\xff.evil.com/x or \x93http://evil.example.org/a\x94 now'
        )
        parsed = eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(raw)

        assert 'http://good.evil.com/x' not in parsed['body'][0]['uri']
        assert 'http://evil.example.org/a' in parsed['body'][0]['uri']
        assert not any('\ufffd' in uri for uri in parsed['body'][0]['uri'])
