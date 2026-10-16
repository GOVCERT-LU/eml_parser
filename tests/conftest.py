"""Shared pytest configuration.

Tests marked ``@pytest.mark.slow`` (e.g. the scaling tests in ``test_performance_scaling.py``) are skipped unless pytest
is started with ``--run-slow``, so the regular CI job (``pytest -v tests``) is not slowed down by them::

    pytest --run-slow tests                                     # everything, including slow tests
    pytest --run-slow -m slow tests                             # only the slow tests
    pytest --run-slow tests/test_performance_scaling.py -v      # only the performance scaling tests
"""

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption('--run-slow', action='store_true', default=False, help='also run tests marked as slow (e.g. performance scaling tests)')


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line('markers', 'slow: long-running test, skipped unless pytest is run with --run-slow')


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption('--run-slow'):
        return

    skip_slow = pytest.mark.skip(reason='slow test, run with --run-slow to enable')
    for item in items:
        if 'slow' in item.keywords:
            item.add_marker(skip_slow)
