import datetime as dt

import eml_parser.decode
import tests.table

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
