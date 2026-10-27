import logging
import time

import pytest

import eml_parser.parser
import eml_parser.regexes
import tests.table

MAIL = b"""From: Alice <alice@example.com>
To: Bob <bob@example.org>
Subject: Test
Date: Mon, 5 Oct 2026 09:12:44 +0200
Message-ID: <1@example.com>
Received: from mx.example.net (mx.example.net [192.0.2.1]) by mail.example.org; Mon, 5 Oct 2026 09:12:44 +0200

Body
"""


class TestHeaderCache:
    def test_repeated_header_access_hits_the_cache(self) -> None:
        eml_parser.parser.CustomPolicy._fetch_fixed_header.cache_clear()  # noqa: SLF001
        parser = eml_parser.parser.EmlParser()

        result = parser.decode_email_bytes(MAIL)

        info = eml_parser.parser.CustomPolicy._fetch_fixed_header.cache_info()  # noqa: SLF001
        assert info.hits > 0
        assert result['header']['from'] == 'alice@example.com'
        assert result['header']['header']['subject'] == ['Test']

    def test_policies_with_different_settings_do_not_share_results(self) -> None:
        value = '<[x]user@localhost>'
        relaxed = eml_parser.parser.CustomPolicy(eml_parser.regexes.email_no_force_tld_regex)
        strict = eml_parser.parser.CustomPolicy(eml_parser.regexes.email_force_tld_regex)

        assert relaxed.fetch_fixed_header('Message-ID', value) == '<user@localhost>'
        assert strict.fetch_fixed_header('Message-ID', value) == ''

    def test_warnings_are_logged_on_every_access(self, caplog: pytest.LogCaptureFixture) -> None:
        eml_parser.parser.CustomPolicy._fetch_fixed_header.cache_clear()  # noqa: SLF001
        caplog.set_level(logging.WARNING)
        parser = eml_parser.parser.EmlParser()
        mail = b'From: a@example.com\nMessage-ID: <[x]\n\nbody'

        parser.decode_email_bytes(mail)
        warning = 'Header field "message-id" is in an invalid format and cannot be fixed, it will be dropped.'
        count = caplog.text.count(warning)
        assert count > 0

        # The same value is already in the cache, so the second parse must still be warned about.
        parser.decode_email_bytes(mail)
        assert caplog.text.count(warning) == 2 * count


class TestIpv6Prefilter:
    SAME_RESULT_AS_THE_PATTERN_CASES = [
        'plain text without any colon',
        'time 09:12:44 and 10:11:12:13',
        'std::vector and Add::dead',
        'from [IPv6:2001:db8::1] by mx.example.org',
        'full 2001:db8:0:0:0:0:0:1 form',
        'mapped 2001:db8:0:0:0:0:192.0.2.1 form',
        '::1 and ::',
        '1:2:3:4:5:6:7:8:9',
    ]

    def test_same_result_as_the_pattern(self) -> None:
        def check(text: str) -> None:
            assert eml_parser.regexes.findall_ipv6(text) == eml_parser.regexes.ipv6_regex.findall(text)

        tests.table.assert_all_cases(check, self.SAME_RESULT_AS_THE_PATTERN_CASES)

    def test_finds_addresses(self) -> None:
        assert eml_parser.regexes.findall_ipv6('from [IPv6:2001:db8::1] by mx') == ['2001:db8::1']


class TestRfc2047Regex:
    ENCODED_WORDS_CASES = ['=?utf-8?B?SGVsbG8=?=', '=?iso-8859-1?q?caf=E9?=', 'prefix =?UTF-8?Q?x?= suffix']

    def test_encoded_words(self) -> None:
        def check(value: str) -> None:
            assert eml_parser.regexes.email_regex_rfc2047.search(value)

        tests.table.assert_all_cases(check, self.ENCODED_WORDS_CASES)

    NO_ENCODED_WORDS_CASES = ['plain', '=?utf-8?x?abc?=', '=?utf-8?|?abc?=', '=?utf-8?B?', 'a ?= b']

    def test_no_encoded_words(self) -> None:
        def check(value: str) -> None:
            assert eml_parser.regexes.email_regex_rfc2047.search(value) is None

        tests.table.assert_all_cases(check, self.NO_ENCODED_WORDS_CASES)

    def test_linear_on_hostile_input(self) -> None:
        start = time.perf_counter()
        eml_parser.regexes.email_regex_rfc2047.search('=?' * 100_000)
        assert time.perf_counter() - start < 1
