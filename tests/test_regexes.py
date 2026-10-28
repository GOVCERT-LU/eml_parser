"""Tests for `eml_parser.regexes`."""

import pathlib
import time

import eml_parser.regexes
import tests.table

my_execution_dir = pathlib.Path(__file__).resolve().parent
parent_dir = my_execution_dir.parent
samples_dir = pathlib.Path(parent_dir, 'samples')


class TestRegularExpressions:
    def test_url_regex_simple(self) -> None:
        """Ensure eml_parser.regexes.url_regex_simple matches URL samples"""
        with pathlib.Path(samples_dir, 'regexes_url_samples.txt').open('r', encoding='utf8') as fhdl:
            url_text_list = fhdl.read().splitlines()

        url_match_list = []
        for line in url_text_list:
            match = eml_parser.regexes.url_regex_simple.search(line)
            if match:
                url_match_list.append(match.group())

        with pathlib.Path(samples_dir, 'regexes_url_matches.txt').open('r', encoding='utf8') as fhdl:
            url_check_list = [li for li in fhdl.read().splitlines() if len(li) > 3 and not li.startswith('#')]

        url_diff = set(url_match_list) ^ set(url_check_list)

        assert url_diff == set()

    def test_url_regex_www(self) -> None:
        """Ensure eml_parser.regexes.url_regex_www matches URL samples"""
        with pathlib.Path(samples_dir, 'regexes_url_samples.txt').open('r', encoding='utf8') as fhdl:
            url_text_list = fhdl.read().splitlines()

        url_match_list = []
        for line in url_text_list:
            if eml_parser.regexes.url_regex_www.search(line):
                url_match_list.append(line)

        with pathlib.Path(samples_dir, 'regexes_url_matches.txt').open('r', encoding='utf8') as fhdl:
            url_check_list = [li for li in fhdl.read().splitlines() if len(li) > 3 and not li.startswith('#')]

        url_diff = set(url_match_list) ^ set(url_check_list)

        assert url_diff == set()

    def test_dom_regex(self) -> None:
        """Ensure eml_parser.regexes.dom_regex matches domain samples"""

        test_doms = """www1.example.com www2.example.com"""

        expected_result = ['www1.example.com', 'www2.example.com']

        assert expected_result == eml_parser.regexes.dom_regex.findall(test_doms)

    def test_email_regex_comma_separator(self) -> None:
        """Regression test: an unescaped hyphen in the character class used to
        form an accidental ASCII range ('+' to '/'), which included ',' and
        caused two comma-separated addresses to be matched as a single,
        invalid address.
        """
        assert eml_parser.regexes.email_regex.findall('contact me at a,b@example.com please') == ['b@example.com']

    def test_email_regex_valid_local_part_chars(self) -> None:
        """Ensure characters legitimately allowed in the local-part (hyphen,
        plus, slash) are still matched after fixing the character class.
        """
        assert eml_parser.regexes.email_regex.findall('john-doe@example.com') == ['john-doe@example.com']
        assert eml_parser.regexes.email_regex.findall('user+tag@example.com') == ['user+tag@example.com']
        assert eml_parser.regexes.email_regex.findall('a/b@example.com') == ['a/b@example.com']


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


# Attribute URLs which are no URL of an HTML tag attribute.
FINDALL_HREF_SKIPPED_CASES = [
    'href="http://a.example/"',  # no tag
    '<a> href="http://a.example/"',  # after the end of the tag
    '<1 href="http://a.example/"',  # no tag name
    '<ahref="http://a.example/"',  # no white space after the tag name
    '<p href="http://a.example/"',  # an attribute the tag does not have
]


def test_findall_href_skips_attributes_outside_of_tags() -> None:
    def check(body: str) -> None:
        assert eml_parser.regexes.findall_href(body) == []

    tests.table.assert_all_cases(check, FINDALL_HREF_SKIPPED_CASES)
