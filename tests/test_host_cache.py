"""Tests for the host validation cache."""

import eml_parser.parser


def test_cache_is_used_and_per_instance() -> None:
    """Repeated hosts hit the cache and instances with different settings do not share verdicts."""
    loose = eml_parser.parser.EmlParser()
    strict = eml_parser.parser.EmlParser(domain_force_tld=True)

    assert loose.get_valid_domain_or_ip('host.invalidtld') == 'host.invalidtld'
    assert loose.get_valid_domain_or_ip('host.invalidtld') == 'host.invalidtld'
    assert loose._cached_valid_domain_or_ip.cache_info().hits == 1  # noqa: SLF001
    assert strict.get_valid_domain_or_ip('host.invalidtld') is None
