# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
from __future__ import annotations

import pathlib
from eml_parser.regexes import *

my_execution_dir = pathlib.Path(__file__).resolve().parent
parent_dir = my_execution_dir.parent
samples_dir = pathlib.Path(parent_dir, 'samples')


class TestRegularExpressions:
    def test_url_regex_simple(self):
        with pathlib.Path(samples_dir, 'regexes_url_samples.txt').open('r', encoding='utf8') as fhdl:
            url_text_list = fhdl.read().splitlines()

        url_match_list = []
        for line in url_text_list:
            match = url_regex_simple.search(line)
            if match:
                url_match_list.append(match.group())

        with pathlib.Path(samples_dir, 'regexes_url_matches.txt').open('r', encoding='utf8') as fhdl:
            url_check_list = [li for li in fhdl.read().splitlines() if len(li) > 3 and not li.startswith('#')]

        url_diff = set(url_match_list) ^ set(url_check_list)

        assert url_diff == set()
