"""Shared pytest configuration.

Tests marked ``@pytest.mark.slow`` (e.g. the scaling tests in ``test_performance_scaling.py``) are skipped unless pytest
is started with ``--run-slow``, so the regular CI job (``pytest -v tests``) is not slowed down by them::

    pytest --run-slow tests                                     # everything, including slow tests
    pytest --run-slow -m slow tests                             # only the slow tests
    pytest --run-slow tests/test_performance_scaling.py -v      # only the performance scaling tests

The property-based tests (Hypothesis, ``@pytest.mark.property``, ``test_*_properties.py``) are skipped unless pytest is started with
``--run-property``; CI runs them in a step of their own. The Hypothesis profile is ``ci`` (fixed seed, 100 examples per test, so CI is
reproducible), ``slow`` together with ``--run-slow`` (1 000 examples), or the one named by ``HYPOTHESIS_PROFILE``, e.g. ``deep``
(random seeds, 5 000 examples per test, a few minutes)::

    pytest --run-property -m property tests                                     # only the property-based tests, as CI
    pytest --run-slow --run-property tests                                      # everything, property-based tests with 1 000 examples
    HYPOTHESIS_PROFILE=deep pytest --run-property tests/test_indicators_properties.py
"""

import os
import typing

import hypothesis
import pytest

import eml_parser.attachments

_HYPOTHESIS_SETTINGS: dict[str, typing.Any] = {'deadline': None, 'print_blob': True, 'suppress_health_check': [hypothesis.HealthCheck.too_slow]}
hypothesis.settings.register_profile('ci', max_examples=100, derandomize=True, database=None, **_HYPOTHESIS_SETTINGS)
hypothesis.settings.register_profile('slow', max_examples=1_000, derandomize=True, database=None, **_HYPOTHESIS_SETTINGS)
hypothesis.settings.register_profile('deep', max_examples=5_000, **_HYPOTHESIS_SETTINGS)


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption('--run-slow', action='store_true', default=False, help='also run tests marked as slow (e.g. performance scaling tests)')
    parser.addoption('--run-property', action='store_true', default=False, help='also run the property-based tests (Hypothesis)')


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line('markers', 'slow: long-running test, skipped unless pytest is run with --run-slow')
    config.addinivalue_line('markers', 'property: property-based test (Hypothesis), skipped unless pytest is run with --run-property')
    hypothesis.settings.load_profile(os.environ.get('HYPOTHESIS_PROFILE', 'slow' if config.getoption('--run-slow') else 'ci'))


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    skips = {
        marker: pytest.mark.skip(reason=f'{marker} test, run with {option} to enable')
        for marker, option in (('slow', '--run-slow'), ('property', '--run-property'))
        if not config.getoption(option)
    }
    for item in items:
        for marker, skip in skips.items():
            if marker in item.keywords:
                item.add_marker(skip)


def pytest_unconfigure() -> None:
    """Close the detector which file-magic caches for the main thread in `magic.threadlocal`.

    It is closed in `__del__`, which at interpreter shutdown runs after the globals of the module are cleared and then fails with
    "Exception ignored in: MagicDetect.__del__ ... TypeError: 'NoneType' object is not callable".
    """
    cache = getattr(eml_parser.attachments.magic, 'threadlocal', None)
    if cache is not None and hasattr(cache, 'magic_instance'):
        del cache.magic_instance
