"""Tests for headers which are too long for the stdlib header parsers."""

import datetime
import time

import pytest

import eml_parser.decode
import eml_parser.parser


def _parse(header: bytes) -> dict:
    return eml_parser.parser.EmlParser().decode_email_bytes(header + b'\r\nFrom: a@example.com\r\n\r\nbody')['header']


@pytest.mark.parametrize(
    'header',
    [
        b'Content-Type: text/plain; ' + b'a=b; ' * 30_000,
        b'To: ' + b'a@example.com, ' * 10_000,
        b'Subject: ' + b'word ' * 100_000,
    ],
    ids=['content-type', 'to', 'subject'],
)
def test_huge_header_is_cheap(header: bytes) -> None:
    """The stdlib parsers need seconds for such values, the cost must not grow with the square of the length."""
    start = time.monotonic()
    _parse(header)

    assert time.monotonic() - start < 3


def test_long_address_header_still_yields_the_addresses() -> None:
    """A long list of recipients is a real thing, its addresses are extracted from the unparsed value."""
    addresses = [f'user{i}@example.com' for i in range(2000)]

    header = _parse(b'To: ' + ', '.join(f'"User {i}" <{address}>' for i, address in enumerate(addresses)).encode())

    assert header['to'] == addresses


def test_huge_date_is_the_default_date() -> None:
    """A date can not be that long, it is invalid."""
    assert _parse(b'Date: ' + b'Mon ' * 20_000)['date'] == datetime.datetime.fromisoformat(eml_parser.decode.default_date)
