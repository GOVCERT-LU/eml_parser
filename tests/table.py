"""Run a table of cases in one test and report every failing case at once."""

import collections.abc
import inspect
import typing


def assert_all_cases(check: collections.abc.Callable[..., None], cases: collections.abc.Sequence[typing.Any]) -> None:
    """Call `check` for every case and fail once, listing each failing case with its assertion message.

    Args:
        check: The assertions for one case. A case of several values (a tuple, like for `pytest.mark.parametrize`) is passed as positional arguments.
        cases: The cases.
    """
    unpack = len(inspect.signature(check).parameters) > 1
    failures = {}
    for case in cases:
        try:
            if unpack:
                check(*case)
            else:
                check(case)
        except AssertionError as error:
            failures[repr(case)] = str(error)

    assert failures == {}, f'{len(failures)} of {len(cases)} cases fail'
