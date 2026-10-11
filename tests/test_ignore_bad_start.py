import pathlib

import pytest

import eml_parser.parser

samples_dir = pathlib.Path(__file__).resolve().parent.parent / 'samples'

MESSAGE_BODY = 'body http://evil.example.com/x\n'


def build_message(prefix: bytes, line_ending: bytes) -> bytes:
    lines = [b'From: a@b.com', b'Subject: hi', b'', MESSAGE_BODY.encode().rstrip(b'\n')]
    return prefix + line_ending.join(lines) + line_ending


class TestIgnoreBadStart:
    @pytest.mark.parametrize('line_ending', [b'\n', b'\r\n'])
    @pytest.mark.parametrize(
        'prefix', [b'garbage line\nmore garbage\n', b'+OK message follows\r\n', b'\r\n\r\n', b'   leading whitespace line\n', b'Dear Bob, note: see below\n']
    )
    def test_leading_garbage_is_skipped_and_structure_is_kept(self, prefix: bytes, line_ending: bytes) -> None:
        parser = eml_parser.EmlParser(ignore_bad_start=True, include_raw_body=True)

        result = parser.decode_email_bytes(build_message(prefix, line_ending))

        assert result['header']['subject'] == 'hi'
        assert result['header']['from'] == 'a@b.com'
        assert result['header']['header']['subject'] == ['hi']
        assert result['body'][0]['content'].strip() == MESSAGE_BODY.strip()
        assert result['body'][0]['uri'] == ['http://evil.example.com/x']

    def test_garbage_prefix_does_not_change_the_body_hash(self) -> None:
        parser = eml_parser.EmlParser(ignore_bad_start=True)

        clean = parser.decode_email_bytes(build_message(b'', b'\n'))
        dirty = parser.decode_email_bytes(build_message(b'garbage line\n', b'\n'))

        assert dirty['body'][0]['hash'] == clean['body'][0]['hash']

    def test_per_call_argument_enables_skipping(self) -> None:
        parser = eml_parser.EmlParser()

        result = parser.decode_email_bytes(build_message(b'garbage line\n', b'\n'), ignore_bad_start=True)

        assert result['header']['subject'] == 'hi'

    def test_valid_message_is_unchanged(self) -> None:
        raw_email = (samples_dir / 'sample.eml').read_bytes()

        with_flag = eml_parser.EmlParser(ignore_bad_start=True).decode_email_bytes(raw_email)
        without_flag = eml_parser.EmlParser().decode_email_bytes(raw_email)

        assert with_flag == without_flag

    def test_input_without_any_header_like_line_is_passed_through(self) -> None:
        parser = eml_parser.EmlParser(ignore_bad_start=True, include_raw_body=True)

        result = parser.decode_email_bytes(b'just some text\nwithout any header\n')

        assert result['header']['subject'] == ''
