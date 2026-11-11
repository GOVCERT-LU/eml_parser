"""Tests for `eml_parser.decode`: header and body text, dates and the JSON export."""

import base64
import datetime as dt
import email
import email.errors
import email.header
import email.message
import json
import pathlib
import types
import typing

import dateutil.parser
import pytest

import eml_parser.decode
import eml_parser.parser
import tests.table

my_execution_dir = pathlib.Path(__file__).resolve().parent
parent_dir = my_execution_dir.parent
samples_dir = parent_dir / 'samples'


class TestDecode:
    def test_decode_field(self) -> None:
        test_subjects = {
            'Die Bezahlung mit Ihrer Kreditkarte wurde erfolgreich durchgeführt.': '=?utf-8?B?RGllIEJlemFobHVuZyBtaXQgSWhyZXIgS3JlZGl0a2FydGUgd3VyZGUgZXJmb2xncmVpY2ggZHVyY2hnZWbDvGhydC4=?=',
            'Abmahnung Ihrer offenen Rechnung über 236,00 Euro': '=?utf-8?q?Abmahnung Ihrer offenen Rechnung =C3=BCber 236,00 Euro?=',
            'Account Analysis (Notice)': '=?utf-8?B?QWNjb3VudCBBbmFseXNpcyAoTm90aWNlKQ==?=',
            'Account Review Department (Notice)': '=?utf-8?B?QWNjb3VudCBSZXZpZXcgRGVwYXJ0bWVudCAoTm90aWNlKQ==?=',
            'John Doe Abmahnung Ihrer nicht beglichenen Rechnung über 818,00 Euro': '=?utf-8?q?John Doe Abmahnung Ihrer nicht beglichenen Rechnung =C3=BCber 818,00 Euro?=',
            '"Jane Doé" <jane.doe@example.com>': '"=?utf-8?q?Jane Do=C3=A9?=" <jane.doe@example.com>',
            '"Jane Doe" <jane.doe@example.com>': '"=?utf-8?Q?Jane_Doe?=" <jane.doe@example.com>',
            '"Geschäftsstelle www.example.com" <test@example.com>': '"=?utf-8?q?Gesch=C3=A4ftsstelle www.example.com?=" <test@example.com>',
            'ÑÓÇáÉ ÊÌÑíÈíÉ': '=?Windows-1252?B?0dPH4ckgyszR7cjtyQ==?=',
            'attachment; filename="Document N°': '=?utf-8?q?attachment=3B_filename=3D=22Document_N=C2=B0?=',
            'Sécuriser vos achats sur Internet': '=?utf-8?q?S=C3=A9curiser_vos_achats_sur_Internet?=',
            '[Spam]': '=?utf-8?Q?=5BSpam=5D?=',
            'Léa Lala-Lulu <lealalalulu@example.com>': '=?iso-8859-1?Q?L=E9a_Lala-Lulu?= <lealalalulu@example.com>',
            """[Spam][SPAM]\r
 Cliente Example Bank""": '=?utf-8?Q?=5BSpam=5D?= =?utf-8?Q?=5BSPAM=5D=0D=0A=20Cliente=20Example=20Bank?=',
        }

        for clear, encoded in test_subjects.items():
            assert eml_parser.decode.decode_field(encoded) == clear

    def test_rfc2047_decode(self) -> None:
        """Regression test: rfc2047_decode must not crash on values which
        contain no RFC2047 encoded-word at all. In that case
        email.header.decode_header() returns plain str fragments instead of
        bytes, which used to trigger an AttributeError.
        """
        assert eml_parser.decode.rfc2047_decode('') == ''
        assert eml_parser.decode.rfc2047_decode('plain ascii subject no encoding') == 'plain ascii subject no encoding'
        assert eml_parser.decode.rfc2047_decode('=?utf-8?B?SGVsbG8=?= plain') == 'Hello plain'

    def test_robust_string2date(self) -> None:
        """Test the converter function, it should never return the default date
        on the provided input
        """
        default_date = '1970-01-01T00:00:00+0000'
        default_date_date = dateutil.parser.parse(default_date)
        test_input = [
            'Mon, 12 Jun 2017 22:25:19 +0200',
            'Mon, 12 Jun 2017 20:24:43 +0000 (UTC)',
            'Mon, 12 Jun 2017 16:24:21 -0400',
            '12 Jun 2017 22:01:19.5933',
        ]

        for test in test_input:
            assert eml_parser.decode.robust_string2date(test) != default_date_date

    def test_noparenthesis(self) -> None:
        test_input = {
            ' test ': ' test ',
            '(test)': '',
            '((test))': '',
            '(((test) (bla)))': '',
            '(test) foo': ' foo',
            'asd (foo (test)(() foo': 'asd (foo ( foo',
            'foo (test) )()foo)': 'foo  )foo)',
            '(asd)(((((': '(((((',
            '))))(asd)': '))))',
        }

        for test, expected_result in test_input.items():
            assert eml_parser.decode.noparenthesis(test) == expected_result

    def test_noparenthesis_replacement(self) -> None:
        assert eml_parser.decode.noparenthesis('pass(a(b))dkim=fail (c)', ' ') == 'pass dkim=fail  '
        assert eml_parser.decode.noparenthesis('a(b', ' ') == 'a(b'


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


MISSING_DATE_PARTS_NEVER_COME_FROM_THE_CURRENT_CLOCK_CASES = [
    ('March 2024', '2024-03-01T00:00:00+00:00'),
    ('Tue, 5 Mar', '1970-03-05T00:00:00+00:00'),
    ('12:30', '1970-01-01T12:30:00+00:00'),
    ('5 Mar 2024', '2024-03-05T00:00:00+00:00'),
    ('2024-03-05', '2024-03-05T00:00:00+00:00'),
    ('Mon, 1 Jan 2024 00:00:00 +0000', '2024-01-01T00:00:00+00:00'),
    ('Mon, 1 Jan 2024 10:00:00 +0200', '2024-01-01T10:00:00+02:00'),
]


def test_missing_date_parts_never_come_from_the_current_clock() -> None:
    def check(line: str, expected: str) -> None:
        assert eml_parser.decode.robust_string2date(line).isoformat() == expected

    tests.table.assert_all_cases(check, MISSING_DATE_PARTS_NEVER_COME_FROM_THE_CURRENT_CLOCK_CASES)


UNPARSABLE_DATES_STILL_RETURN_THE_DEFAULT_CASES = ['', 'not a date', 'Fri, 31 Feb 2024 10:00:00 +0000', '0000-00-00', 'garbage 99']


def test_unparsable_dates_still_return_the_default() -> None:
    def check(line: str) -> None:
        assert eml_parser.decode.robust_string2date(line).isoformat() == eml_parser.decode.default_date

    tests.table.assert_all_cases(check, UNPARSABLE_DATES_STILL_RETURN_THE_DEFAULT_CASES)


def test_absurd_number_is_an_invalid_date() -> None:
    """dateutil raises decimal.InvalidOperation for huge numbers of minutes or seconds."""
    assert eml_parser.decode.robust_string2date('99999999999999999999999999999m') == dt.datetime.fromisoformat(eml_parser.decode.default_date)


OFFSET_OF_DATEUTIL_DATES_IS_KEPT_CASES = [
    # Fractional seconds are not understood by the email module, dateutil parses these and returns an offset without a name.
    ('Mon, 5 Oct 2026 09:12:44.123 +0200', '2026-10-05T09:12:44.123000+02:00'),
    ('Mon, 5 Oct 2026 09:12:44.123 -0500', '2026-10-05T09:12:44.123000-05:00'),
    ('Mon, 5 Oct 2026 09:12:44.123 +0000', '2026-10-05T09:12:44.123000+00:00'),
    ('Fri, 29 Jan 2021 07:24:22.501 +0530', '2021-01-29T07:24:22.501000+05:30'),
]


def test_offset_of_dateutil_dates_is_kept() -> None:
    def check(line: str, expected: str) -> None:
        assert eml_parser.decode.robust_string2date(line).isoformat() == expected

    tests.table.assert_all_cases(check, OFFSET_OF_DATEUTIL_DATES_IS_KEPT_CASES)


def test_date_without_offset_is_utc() -> None:
    assert eml_parser.decode.robust_string2date('Mon, 5 Oct 2026 09:12:44.123').utcoffset() == dt.timedelta(0)


def test_rfc2047_decode_keeps_undecodable_values() -> None:
    # Arrange: invalid base64 in the encoded word, the stdlib raises HeaderParseError
    value = '=?utf-8?B?==E9?='

    # Act
    decoded = eml_parser.decode.rfc2047_decode(value)

    # Assert
    assert decoded == value


def test_decode_body_replaces_lone_surrogates() -> None:
    # Arrange: UTF-7 encodes UTF-16 code units, "+2AA-" is the lone high surrogate U+D800
    data = b'a+2AA-b'

    # Act
    text = eml_parser.decode.decode_body(data, 'utf-7')

    # Assert
    assert text == 'a b'


def test_decode_field_keeps_undecodable_values() -> None:
    # Arrange: invalid base64 in the encoded word
    value = '=?utf-8?B?==E9?='

    # Act
    decoded = eml_parser.decode.decode_field(value)

    # Assert
    assert decoded == value


# Values for which decode.decode_header() must give the result of email.header.decode_header(), the exception included.
DECODE_HEADER_CASES = [
    '',
    'plain text',
    '=?utf-8?q?caf=C3=A9?=',
    '  =?utf-8?q?a?= =?utf-8?q?b?=  and =?iso-8859-1?b?6Q==?= text',  # white space between encoded words is dropped
    '=?utf-8?q?a?==?utf-8?q?b?=',
    '=?utf-8?q?a?= =?utf-8?q?_?= =?utf-8?q?b?=',  # an encoded word of white space between two others is dropped as well
    '=??q?empty charset?= =??b?YQ==?=',
    '=?UTF-8?Q?upper?= =?utf-8?B?SGVsbG8?=',  # missing base64 padding
    '=?utf-8?B?==E9?=',  # invalid base64: HeaderParseError
    'first line =?utf-8?q?a?=\r\n second =?utf-8?q?b?=\n\tthird',
    '=?ab\ncd?q?x?=',  # an encoded word in the value, but not in its lines
    '=?a?q?x =?a?q?y ?= ??= =?a?x?z?=',  # unclosed words and a wrong encoding
    'a?b?=?b?=?=?b?=?x?=',
    '=?utf-8?q?a??=b?=',
]


def test_decode_header_like_the_stdlib() -> None:
    def outcome(call: typing.Callable[[], object]) -> object:
        try:
            return call()
        except email.errors.HeaderParseError as error:
            return f'HeaderParseError: {error}'

    def check(value: str) -> None:
        assert outcome(lambda: eml_parser.decode.decode_header(value)) == outcome(lambda: email.header.decode_header(value))

    tests.table.assert_all_cases(check, DECODE_HEADER_CASES)


def test_decode_header_of_a_header_object() -> None:
    # Arrange: compat32 returns values with 8-bit bytes as Header objects
    value = email.header.Header(b'caf\xc3\xa9'.decode('ascii', 'surrogateescape'), 'unknown-8bit')

    # Act
    fragments = eml_parser.decode.decode_header(value)

    # Assert
    assert fragments == email.header.decode_header(value)
