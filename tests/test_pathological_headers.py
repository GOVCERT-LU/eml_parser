import time

import pytest

import eml_parser.parser


class TestPathologicalHeaders:
    @pytest.mark.parametrize('header,count', [('cc', 500), ('From', 500), ('resent-sender', 500), ('Sender', 500)])
    def test_many_open_parentheses(self, header: str, count: int) -> None:
        parens = b'(' * count
        sample = header.encode() + b': ' + parens + b', c@c' + b', Foo Bar <d@d> ' + parens
        ep = eml_parser.EmlParser()
        data = ep.decode_email_bytes(sample)
        header_name = header.lower()
        assert data['header']['header'][header_name] == ['c@c, d@d']
        if header_name in ('to', 'cc'):
            assert data['header'][header_name] == ['c@c', 'd@d']

    def test_many_parentheses_in_received_header(self) -> None:
        count = 50000
        start = time.monotonic()
        open_parens = b'(' * count
        closed_parens = b')' * count
        sample = b'Received: from ' + open_parens + b', a.a, ' + closed_parens
        eml_parser.EmlParser.MULTIPART_RECURSION_LIMIT = 100
        ep = eml_parser.EmlParser()
        ep.decode_email_bytes(sample)
        elapsed = time.monotonic() - start
        assert elapsed < 0.5

    def test_many_local_part_characters_in_received_header(self) -> None:
        count = 100000
        start = time.monotonic()
        sample = b'Received: from ' + b'a' * count + b', a.a, '
        ep = eml_parser.EmlParser()
        ep.decode_email_bytes(sample)
        elapsed = time.monotonic() - start
        assert elapsed < 1
