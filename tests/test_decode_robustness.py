import types

import pytest

import eml_parser.decode


class TestDecodeString:
    @staticmethod
    def _disable_detection(monkeypatch: pytest.MonkeyPatch) -> None:
        """Make charset_normalizer find no encoding at all, as it does for e.g. random binary data."""
        monkeypatch.setattr(
            eml_parser.decode.charset_normalizer,
            'from_bytes',
            lambda _data: types.SimpleNamespace(best=lambda: None),
        )

    def test_undetectable_bytes_never_become_the_string_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._disable_detection(monkeypatch)

        result = eml_parser.decode.decode_string(b'visit http://evil.example.com/ now')

        assert result == 'visit http://evil.example.com/ now'

    def test_undetectable_bytes_fall_back_to_utf8(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._disable_detection(monkeypatch)

        assert eml_parser.decode.decode_string('café evil.example.com'.encode()) == 'café evil.example.com'

    def test_undetectable_invalid_utf8_keeps_ascii_iocs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._disable_detection(monkeypatch)

        result = eml_parser.decode.decode_string(b'visit http://evil.example.com/\xff\xfe now')

        assert 'http://evil.example.com/' in result
        assert result != 'None'

    def test_failing_encoding_hint_falls_back(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._disable_detection(monkeypatch)

        assert eml_parser.decode.decode_string(b'caf\xc3\xa9', 'ascii') == 'café'
        assert eml_parser.decode.decode_string(b'abc', 'no-such-charset') == 'abc'

    def test_real_detection_on_binary_blob_returns_text(self) -> None:
        result = eml_parser.decode.decode_string(bytes(range(256)) * 2)

        assert isinstance(result, str)
        assert result != 'None'
        assert result != ''

    def test_plain_and_empty_input(self) -> None:
        assert eml_parser.decode.decode_string(b'') == ''
        assert eml_parser.decode.decode_string(b'plain ascii') == 'plain ascii'
