import datetime as dt

import eml_parser.decode
import tests.table

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
