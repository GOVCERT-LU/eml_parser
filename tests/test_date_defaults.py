import datetime

import pytest

import eml_parser.decode


@pytest.mark.parametrize(
    ('line', 'expected'),
    [
        ('March 2024', '2024-03-01T00:00:00+00:00'),
        ('Tue, 5 Mar', '1970-03-05T00:00:00+00:00'),
        ('12:30', '1970-01-01T12:30:00+00:00'),
        ('5 Mar 2024', '2024-03-05T00:00:00+00:00'),
        ('2024-03-05', '2024-03-05T00:00:00+00:00'),
        ('Mon, 1 Jan 2024 00:00:00 +0000', '2024-01-01T00:00:00+00:00'),
        ('Mon, 1 Jan 2024 10:00:00 +0200', '2024-01-01T10:00:00+02:00'),
    ],
)
def test_missing_date_parts_never_come_from_the_current_clock(line: str, expected: str) -> None:
    assert eml_parser.decode.robust_string2date(line).isoformat() == expected


@pytest.mark.parametrize('line', ['', 'not a date', 'Fri, 31 Feb 2024 10:00:00 +0000', '0000-00-00', 'garbage 99'])
def test_unparsable_dates_still_return_the_default(line: str) -> None:
    assert eml_parser.decode.robust_string2date(line).isoformat() == eml_parser.decode.default_date


def test_absurd_number_is_an_invalid_date() -> None:
    """dateutil raises decimal.InvalidOperation for huge numbers of minutes or seconds."""
    assert eml_parser.decode.robust_string2date('99999999999999999999999999999m') == datetime.datetime.fromisoformat(eml_parser.decode.default_date)
