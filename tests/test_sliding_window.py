"""Tests for the slicing of large bodies."""

import eml_parser.parser

LOOP = eml_parser.parser.EmlParser.string_sliding_window_loop


class TestSlidingWindow:
    """Slices must cover the body completely and never cut a token."""

    def test_short_and_empty_body(self) -> None:
        """A body which fits in one slice is returned unchanged."""
        assert list(LOOP('')) == ['']
        assert list(LOOP('abc')) == ['abc']

    def test_slices_cover_the_body(self) -> None:
        """No gaps, no overlaps."""
        body = ('x' * 495 + ' http://evil.example.com/abc ') * 30

        assert ''.join(LOOP(body)) == body

    def test_tokens_are_not_cut(self) -> None:
        """Every URL is complete in exactly one slice."""
        for offset in range(120):
            body = 'a' * offset + (' ' + 'b' * 380 + ' http://evil.example.com/path') * 4 + ' end'
            slices = list(LOOP(body))

            assert sum(s.count('http://evil.example.com/path') for s in slices) == 4

    def test_last_token_without_trailing_whitespace_is_not_cut(self) -> None:
        """A token which ends the body is complete even though no whitespace follows it."""
        body = 'a' * 480 + ' http://evil.example.com/last/token'

        assert list(LOOP(body)) == [body]

    def test_long_token_is_not_cut_with_default_distance(self) -> None:
        """A URL of several thousand characters crossing a slice border stays in one piece."""
        first_slice = 'a' * 480 + ' http://evil.example.com/' + 'p' * 5000
        body = first_slice + ' tail ' + 'b' * 2000

        assert next(iter(LOOP(body))) == first_slice

    def test_overlong_token_is_cut_but_not_lost(self) -> None:
        """Without whitespace the slices are cut hard, the content is kept."""
        body = 'y' * 2000

        assert ''.join(LOOP(body, 500, 100)) == body

    def test_url_at_slice_boundary_is_extracted(self) -> None:
        """End to end: a URL crossing the 500 character mark is reported completely."""
        body = 'a' * 470 + ' http://evil.example.com/a/long/path?x=1 tail'
        raw = f'From: a@example.com\r\n\r\n{body}'.encode()
        parsed = eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(raw)

        assert parsed['body'][0]['uri'] == ['http://evil.example.com/a/long/path?x=1']
