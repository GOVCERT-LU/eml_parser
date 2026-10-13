import base64
import datetime as dt
import email.message
import json
import types

import pytest

import eml_parser.decode
import eml_parser.parser


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


class TestExportToJson:
    def test_bytes_values_are_exported_as_text(self) -> None:
        exported = eml_parser.decode.export_to_json({'raw': base64.b64encode(b'payload')})

        assert json.loads(exported) == {'raw': 'cGF5bG9hZA=='}

    def test_non_base64_bytes_are_rejected(self) -> None:
        with pytest.raises(UnicodeDecodeError):
            eml_parser.decode.export_to_json({'raw': b'\xff\xfeabc'})

    def test_attachment_data_survives_the_export(self) -> None:
        message = email.message.EmailMessage()
        message['From'] = 'a@example.com'
        message['To'] = 'b@example.com'
        message.set_content('body')
        message.add_attachment(b'\x00\x01binary', maintype='application', subtype='octet-stream', filename='blob.bin')

        parsed = eml_parser.parser.EmlParser(include_attachment_data=True).decode_email_bytes(message.as_bytes())
        exported = json.loads(eml_parser.decode.export_to_json(parsed))

        assert base64.b64decode(exported['attachment'][0]['raw']) == b'\x00\x01binary'

    def test_datetime_is_still_exported_as_utc(self) -> None:
        moment = dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone(dt.timedelta(hours=2)))

        assert json.loads(eml_parser.decode.export_to_json({'date': moment})) == {'date': '2026-01-02T01:04:05+00:00'}

    def test_unsupported_types_still_raise(self) -> None:
        with pytest.raises(TypeError):
            eml_parser.decode.export_to_json({'value': object()})


class TestJsonSerialExtremeDates:
    @pytest.mark.parametrize(
        ('moment', 'expected'),
        [
            (dt.datetime(9999, 12, 31, 23, 59, 59, tzinfo=dt.timezone(dt.timedelta(hours=-5))), '9999-12-31T23:59:59-05:00'),
            (dt.datetime(1, 1, 1, 0, 0, 0, tzinfo=dt.timezone(dt.timedelta(hours=5))), '0001-01-01T00:00:00+05:00'),
        ],
    )
    def test_dates_which_cannot_be_converted_to_utc_keep_their_offset(self, moment: dt.datetime, expected: str) -> None:
        assert eml_parser.decode.json_serial(moment) == expected

    def test_naive_datetime_is_unchanged(self) -> None:
        assert eml_parser.decode.json_serial(dt.datetime.fromisoformat('2026-01-02T03:04:05')) == '2026-01-02T03:04:05'

    def test_hostile_date_header_can_be_exported(self) -> None:
        raw_email = b'From: a@example.com\r\nDate: Fri, 31 Dec 9999 23:59:59 -0500\r\n\r\nbody'

        parsed = eml_parser.parser.EmlParser().decode_email_bytes(raw_email)
        exported = json.loads(eml_parser.decode.export_to_json(parsed))

        assert exported['header']['date'].startswith('9999-12-31T23:59:59')


class TestRfc2047Decode:
    def test_unknown_charset_does_not_raise(self) -> None:
        assert eml_parser.decode.rfc2047_decode('=?foo-bar?q?hello_world?=') == 'hello world'

    def test_unknown_charset_in_mixed_value(self) -> None:
        assert eml_parser.decode.rfc2047_decode('Re: =?foo-bar?b?aGVsbG8=?= there') == 'Re: hello there'

    def test_known_charset_is_still_decoded(self) -> None:
        assert eml_parser.decode.rfc2047_decode('=?utf-8?q?caf=C3=A9?=') == 'café'

    def test_invalid_bytes_in_known_charset_are_replaced(self) -> None:
        assert eml_parser.decode.rfc2047_decode('=?utf-8?q?a=FFb?=') == 'a�b'

    def test_plain_ascii_and_empty(self) -> None:
        assert eml_parser.decode.rfc2047_decode('plain') == 'plain'
        assert eml_parser.decode.rfc2047_decode('') == ''


@pytest.mark.parametrize('raw', [b'From:=??q?=0A\xcd', b' \nCc:=?\xd5?q?=0D'])
def test_malformed_encoded_address_headers_do_not_raise(raw: bytes) -> None:
    """Encoded words which decode to line breaks or to the wrong type must not make the parser fail."""
    assert eml_parser.parser.EmlParser().decode_email_bytes(raw)


def test_attached_message_which_cannot_be_serialised_does_not_raise() -> None:
    """A message/rfc822 part with text the generator cannot encode is still listed as attachment."""
    raw = b' \nContent-Type:multipart/\n--0t\nContent-Type:message/rfc822\n\xad'

    assert eml_parser.parser.EmlParser().decode_email_bytes(raw)['attachment']
