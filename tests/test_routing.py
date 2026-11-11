"""Tests for `eml_parser.routing` and the received fields of the result."""

import datetime as dt
import json
import os
import pathlib
import subprocess
import sys
import time

import pytest

import eml_parser.parser
import eml_parser.regexes
import eml_parser.routing
import tests.table

my_execution_dir = pathlib.Path(__file__).resolve().parent
parent_dir = my_execution_dir.parent
samples_dir = parent_dir / 'samples'


class TestRouting:
    def test_cleanline(self) -> None:
        test_input = {
            '   ;': '',
            '  test  ': 'test',
            ';  test;  ': 'test',
        }

        for test, expected_result in test_input.items():
            assert eml_parser.routing.cleanline(test) == expected_result

    def test_give_dom_ip(self) -> None:
        test_input = {
            ' 192.168.1.1 abc bla bla www.example.com sdsf ::1 test ': ['192.168.1.1', '::1', 'www.example.com'],
        }

        for test, expected_result in test_input.items():
            assert sorted(eml_parser.routing.get_domain_ip(test)) == sorted(expected_result)

    def test_parserouting(self) -> None:
        test_input = {
            'test1': (
                """Received: from mta1.example.com (mta1.example.com [192.168.1.100]) (using TLSv1 with cipher ADH-AES256-SHA (256/256 bits)) (No client certificate requested) by mta.example2.com (Postfix) with ESMTPS id 6388F684168 for <info@example.com>; Fri, 26 Apr 2013 13:15:55 +0200 (CEST)""",
                {
                    'by': ['mta.example2.com'],
                    'for': ['info@example.com'],
                    'from': ['mta1.example.com', '192.168.1.100'],
                    'src': 'Received: from mta1.example.com (mta1.example.com [192.168.1.100]) (using TLSv1 with cipher ADH-AES256-SHA (256/256 bits)) (No client certificate requested) by mta.example2.com (Postfix) with ESMTPS id 6388F684168 for <info@example.com>; Fri, 26 Apr 2013 13:15:55 +0200 (CEST)',
                    'with': 'esmtps id 6388f684168',
                    'date': dt.datetime(2013, 4, 26, 13, 15, 55, tzinfo=dt.timezone(dt.timedelta(0, 7200))),
                },
            ),
            'test2': (
                # Tests a received entry which has *from* as part of a field.
                """Received: by f321.i.example.com with local (envelope-from <b8u3hkqlkj@example.com>) id 1khYpb-0001XE-KE for someone@here-from-there.com; Tue, 24 Nov 2020 16:58:07 +0300""",
                {
                    'by': ['f321.i.example.com'],
                    'for': ['someone@here-from-there.com'],
                    'src': 'Received: by f321.i.example.com with local (envelope-from <b8u3hkqlkj@example.com>) id 1khYpb-0001XE-KE for someone@here-from-there.com; Tue, 24 Nov 2020 16:58:07 +0300',
                    'with': 'local (envelope-from <b8u3hkqlkj@example.com>) id 1khypb-0001xe-ke',
                    'date': dt.datetime(2020, 11, 24, 16, 58, 7, tzinfo=dt.timezone(dt.timedelta(seconds=10800))),
                },
            ),
            'test3': (
                # C.f. github issue #54; unsupported line; point of this test is to make sure we properly catch related exceptions
                r"""Received: from)by ismtpd0112p1sjc2.abc.net (SG) with ESMTP id\n B4glDdmiQcqJYrMuLIqjUQfor <p-j.a@sdf.com>; Fri, 29 Jan 2021\n 07:24:22.501 +0000 (UTC)""",
                {
                    'src': r'Received: from)by ismtpd0112p1sjc2.abc.net (SG) with ESMTP id\n B4glDdmiQcqJYrMuLIqjUQfor <p-j.a@sdf.com>; Fri, 29 Jan 2021\n 07:24:22.501 +0000 (UTC)',
                    'by': ['ismtpd0112p1sjc2.abc.net'],
                    'with': r'esmtp id\n b4glddmiqcqjyrmuliqjuqfor <p-j.a@sdf.com>',
                },
            ),
        }

        for _test_number, test in test_input.items():
            test_output = eml_parser.routing.parserouting(test[0])

            # get all keys from the test case
            supported_keys = list(test[1])

            for sk in supported_keys:
                # make sure key is also in output
                assert sk in test_output

                if isinstance(test[1][sk], list):
                    # check if lengths match
                    assert len(test_output[sk]) == len(test[1][sk])

                    # check content
                    for e in test[1][sk]:
                        assert e in test_output[sk]

                else:
                    assert test_output[sk] == test[1][sk]

            # make sure all keys from generated output are also in the test case
            for k in test_output:
                assert k in test[1]


TAIL = '; Mon, 5 Oct 2026 09:12:44 +0200'


def parse(line: str) -> dict:
    return eml_parser.routing.parserouting(line)


SECTIONS_CASES = [
    # a host name ending in a keyword must not start a section
    ('from toby (toby.example.com [192.0.2.1]) by mx.example.org with ESMTP' + TAIL, ['toby.example.com', '192.0.2.1'], ['mx.example.org']),
    ('from before.example.org (x [192.0.2.7]) by mx.example.org' + TAIL, ['before.example.org', '192.0.2.7'], ['mx.example.org']),
    ('from ruby.example.org ([192.0.2.8]) by nearby.example.org with ESMTP' + TAIL, ['ruby.example.org', '192.0.2.8'], ['nearby.example.org']),
    # keywords in comments are not keywords
    ('from a.example.com (a.example.com [192.0.2.1]) (using TLS by default) by b.example.com' + TAIL, ['a.example.com', '192.0.2.1'], ['b.example.com']),
    ('from a.example.com ([192.0.2.1]) by b.example.com (Postfix, from userid 1000) with ESMTP' + TAIL, ['a.example.com', '192.0.2.1'], ['b.example.com']),
    # an unbalanced opening parenthesis does not swallow the rest
    ('from a.example.com (a.example.com [192.0.2.1] by b.example.com with ESMTP' + TAIL, ['a.example.com', '192.0.2.1'], ['b.example.com']),
    # upper case
    ('FROM A.EXAMPLE.COM (A.EXAMPLE.COM [192.0.2.1]) BY B.EXAMPLE.COM WITH ESMTP' + TAIL, ['a.example.com', '192.0.2.1'], ['b.example.com']),
]


def test_sections() -> None:
    def check(line: str, expected_from: list[str], expected_by: list[str]) -> None:
        result = parse(line)

        assert result['from'] == expected_from
        assert result['by'] == expected_by

    tests.table.assert_all_cases(check, SECTIONS_CASES)


def test_hosts_are_in_order_of_appearance() -> None:
    result = parse('from mail.example.com (mail.example.com [192.0.2.1] [2001:db8::1]) by mx.example.org' + TAIL)

    assert result['from'] == ['mail.example.com', '192.0.2.1', '2001:db8::1']


BY_CONTAINS_ONLY_RELAYS_CASES = [
    # version numbers are no host names
    ('from a.example.com by mx.example.org (Exim 4.96) id 1' + TAIL, ['mx.example.org']),
    ('from a.example.com by mx.example.org (8.12.2/8.12.2/20020902/$Revision: 1.30 $) with SMTP' + TAIL, ['mx.example.org']),
    # the domain of an address in angle brackets is no relay
    ('from a.example.com by mx.example.org (envelope-from <s@sender.example>) id 1' + TAIL, ['mx.example.org']),
    ('from a.example.com by mx.example.org with SMTP id <B001@msg.example>' + TAIL, ['mx.example.org']),
]


def test_by_contains_only_relays() -> None:
    def check(line: str, expected_by: list[str]) -> None:
        assert parse(line)['by'] == expected_by

    tests.table.assert_all_cases(check, BY_CONTAINS_ONLY_RELAYS_CASES)


def test_ident_host_of_sendmail_is_kept() -> None:
    result = parse('from client (user@c-24-98-25-152.atl.example.com [24.98.25.152]) by mx.example.org with SMTP' + TAIL)

    assert result['from'] == ['c-24-98-25-152.atl.example.com', '24.98.25.152']


def test_empty_sections_are_omitted() -> None:
    result = parse('from by mx.example.org with ;')

    assert 'from' not in result
    assert result['by'] == ['mx.example.org']
    assert 'with' not in result


def test_repeated_keyword_belongs_to_the_previous_section() -> None:
    result = parse('from a.example.com by b.example.com for <x@example.com> from c.example.com' + TAIL)

    assert result['for'] == ['x@example.com']
    assert result['from'] == ['a.example.com', 'c.example.com']


def test_for_addresses_are_in_order_of_appearance() -> None:
    result = parse('from a.example.com by b.example.com for <z@example.com> <a@example.com>' + TAIL)

    assert result['for'] == ['z@example.com', 'a@example.com']


DATE_CASES = [
    ('from a.example.com by b.example.com' + TAIL + ' (CEST)', '2026-10-05T09:12:44+02:00'),
    ('from a.example.com by b.example.com; Mon, 5 Oct 2026 09:12:44.123 -0500', '2026-10-05T09:12:44.123000-05:00'),
    ('from a.example.com by b.example.com; 5 Oct 2026 07:12:44 -0000', '2026-10-05T07:12:44+00:00'),
]


def test_date() -> None:
    def check(line: str, expected: str) -> None:
        assert parse(line)['date'].isoformat() == expected

    tests.table.assert_all_cases(check, DATE_CASES)


NO_DATE_IS_INVENTED_CASES = ['from a.example.com by b.example.com', 'from a.example.com by b.example.com; not a date', 'from a.example.com by b.example.com;']


def test_no_date_is_invented() -> None:
    def check(line: str) -> None:
        assert 'date' not in parse(line)

    tests.table.assert_all_cases(check, NO_DATE_IS_INVENTED_CASES)


def test_merged_and_unparsable_lines() -> None:
    assert parse('from a.example.com by b.example.com ; mon, 5 oct 2026 09:12:44 +0200 received: from c.example.com by d.example.com')['warning'] == [
        'Merged Received headers'
    ]
    assert parse('(qmail 12345 invoked by uid 0); 22 Aug 2002 08:28:38 -0000')['warning'] == ['Nothing Parsable']


@pytest.mark.parametrize('filler', [';', '(', ')', ' ', '(x) ', 'by ', 'a.'])
def test_parsing_time_is_linear(filler: str) -> None:
    """Runs of semicolons and spaces took seconds (quadratic) in the old implementation, the others are included for completeness."""
    result = parse('from a.example.com ' + filler * 50_000 + 'x by b.example.com' + TAIL)

    assert result['by'] == ['b.example.com'] or 'by' not in result


CLEANLINE_UNICODE_WHITESPACE_CASES = [('', ''), ('  ; x ;  ', 'x'), ('; ; x　;', 'x'), ('x', 'x')]


def test_cleanline_unicode_whitespace() -> None:
    def check(text: str, expected: str) -> None:
        assert eml_parser.routing.cleanline(text) == expected

    tests.table.assert_all_cases(check, CLEANLINE_UNICODE_WHITESPACE_CASES)


BY_IN_REAL_WORLD_FORMATS_CASES = [
    # a comment directly behind the host name
    (
        'from a.example.com by notes.example.com(Lotus SMTP MTA v4.6.5 (863.2 5-20-1999)) id 86256895.00832fb3 ; Wed, 1 Mar 2000 17:52:54 -0600',
        ['notes.example.com'],
    ),
    # a host in brackets
    (
        'from elpmime02.example.com ([192.0.2.90]) by [mail.example.com] (GroupWise SMTP/MIME daemon 4.1 v3) ; Mon, 19 Jun 2000 17:21:00 -0700',
        ['mail.example.com'],
    ),
    # ids and versions are no hosts: mailer message ids and versions
    (
        'from a.example.com by imo-m10.mx.example.net (mail_out_v31_r1.9.) id 2.73.172b0394 (2519) for <ken@example.com>; Tue, 4 Dec 2001 13:02:04 -0500',
        ['imo-m10.mx.example.net'],
    ),
    ('from a.example.com by mx.example.com (v82.22) with ESMTP id MAILINYE410-1115115900; Thu, 15 Nov 2001 11:59:00 -0500', ['mx.example.com']),
    (
        'from a.example.com by mx.example.com (8.10.1/8.10.1/external_corp-1.08) with ESMTP id g0mgoa021678; Tue, 22 Jan 2002 10:24:10 -0600',
        ['mx.example.com'],
    ),
]


def test_by_in_real_world_formats() -> None:
    def check(line: str, expected_by: list[str]) -> None:
        assert parse(line)['by'] == expected_by

    tests.table.assert_all_cases(check, BY_IN_REAL_WORLD_FORMATS_CASES)


def test_line_in_brackets() -> None:
    result = parse(
        '[from pobox3.example.org (pobox3.example.org [192.0.2.242]) by motgate4.example.org (motgate4 2.1) with ESMTP id haa08361; Tue, 13 Nov 2001 07:51:10 -0700 (MST)]'
    )

    assert result['from'] == ['pobox3.example.org', '192.0.2.242']
    assert result['by'] == ['motgate4.example.org']


GARBAGE_IS_NOT_A_DATE_CASES = [
    '; tue, 15 aug 2000 gmt',  # no time
    '; wed, 21 feb 2001 19:29: 59 -0500',  # blank in the time
    '; tue, 15 aug 2000 08:57:09 -04= 00',  # left over of a quoted-printable line break, dateutil would ignore it and return a wrong zone
    '; of, 15 ssa 2000 09:40:38 -0600',
]


def test_garbage_is_not_a_date() -> None:
    def check(tail: str) -> None:
        assert 'date' not in parse('from a.example.com by b.example.com' + tail)

    tests.table.assert_all_cases(check, GARBAGE_IS_NOT_A_DATE_CASES)


GET_DOMAIN_IP_HOST_NAMES_CASES = [
    ('mail10.m.example.net', ['mail10.m.example.net']),  # single character labels
    ('mail_gw1.example.com', ['mail_gw1.example.com']),  # underscore, used by Exchange and Lotus servers
    ('a.example.com, b.example.org;', ['a.example.com', 'b.example.org']),  # separated by comma
    ('*.example.com', ['example.com']),  # wildcard
    ('user.name@mx.example.com', ['mx.example.com']),  # local part of an address
    ('id 1.b9.b1afe75 id x.bd.69a6d55', []),  # message ids
    ('(8.12.0.beta16/8.12.0 v82.22 Exim 4.96)', []),  # versions
    ('xn--mx-example.xn--p1ai', ['xn--mx-example.xn--p1ai']),  # punycode TLD
]


def test_get_domain_ip_host_names() -> None:
    def check(text: str, expected: list[str]) -> None:
        assert eml_parser.routing.get_domain_ip(text) == expected

    tests.table.assert_all_cases(check, GET_DOMAIN_IP_HOST_NAMES_CASES)


def test_unclosed_parenthesis_does_not_hide_the_date() -> None:
    result = parse(
        'from a.example.com by b.example.org (8.12.2/BASENAME(x.example, .mc):RCS(rev: 1.23 ) with ESMTP id g99GvDmX; Wed, 9 Oct 2002 12:57:14 -0400 (EDT)'
    )

    assert result['by'] == ['b.example.org', 'x.example']
    assert result['date'].isoformat() == '2002-10-09T12:57:14-04:00'


def test_date_of_a_line_without_relay() -> None:
    result = parse('(qmail 18301 invoked by uid 500); 28 Sep 2002 16:21:17 -0000')

    assert result['warning'] == ['Nothing Parsable']
    assert result['date'].isoformat() == '2002-09-28T16:21:17+00:00'
    assert 'by' not in result


def test_date_of_a_line_in_brackets() -> None:
    result = parse('[from a.example.com by b.example.org with ESMTP; Wed, 28 Aug 2002 01:29:22 -0700  ]')

    assert result['date'].isoformat() == '2002-08-28T01:29:22-07:00'


def test_host_scan_is_linear() -> None:
    """The scan for host names backtracked over every label of a long run of labels (400 000 characters took 17 s)."""
    assert eml_parser.routing.get_domain_ip('a.' * 200_000 + 'x') == []
    assert eml_parser.routing.get_domain_ip('a.' * 200_000 + 'example.com') == ['a.' * 200_000 + 'example.com']


TWO_HOPS_VIA_THE_GATEWAY = b"""Received: from inner.example.org ([192.0.2.2]) by mx.example.com with ESMTP; Mon, 1 Jan 2024 10:01:00 +0000
Received: from outer.example.net ([192.0.2.1]) by mx.example.com with ESMTP; Mon, 1 Jan 2024 10:00:00 +0000
From: a@example.org
To: b@example.com

body
"""


def test_duplicate_gateway_warnings_are_strings() -> None:
    # Arrange: both entries match the gateway, so the second line gets two warnings
    parser = eml_parser.parser.EmlParser(pconf={'byhostentry': ['mx.example', 'example.com']})

    # Act
    header = parser.decode_email_bytes(TWO_HOPS_VIA_THE_GATEWAY)['header']

    # Assert
    assert 'warning' not in header['received'][0]
    assert header['received'][1]['warning'] == ['Duplicate SMTP by entrypoint', 'Duplicate SMTP by entrypoint']
    assert header['received_src'] == ['outer.example.net', '192.0.2.1']


# `received_domain`: the host names following "from" and "by" in the received lines. The cases are modelled on received lines of the
# SpamAssassin public corpus (with example names), where the former `regexes.recv_dom_regex` reported fragments and missed hosts.
# (received line, host names after "from" and "by")
RECEIVED_CASES = [
    # relays of current and historic mailers, merged and unparsable lines, punycode, internal names
    (
        'from mail-out-f12.example.net (mail-out-f12.example.net. [192.0.2.10]) by mx.example.com (postfix) with esmtps id 4w8x5k6zr2z9srk',
        ['mail-out-f12.example.net', 'mx.example.com'],
    ),
    (
        'from am7pr02mb6417.eu.prod.example.org (2001:db8:20b:2c4::17) by db9pr02mb7212.eu.prod.example.org with http',
        ['am7pr02mb6417.eu.prod.example.org', 'db9pr02mb7212.eu.prod.example.org'],
    ),
    (
        'from a.example.com by b.example.com; mon, 1 jan 2024 received: from c.example.org by d.example.org; mon, 1 jan 2024',
        ['a.example.com', 'b.example.com', 'c.example.org', 'd.example.org'],
    ),
    ('(from mail.example.com) by relay.example.net; mon, 1 jan 2024', ['mail.example.com', 'relay.example.net']),
    ('from xn--exmple-cua.de by mx.xn--e1afmkfd.example with esmtp', ['xn--exmple-cua.de', 'mx.xn--e1afmkfd.example']),
    ('from exchsrv.corp2 (imc.example.com [192.0.2.97]) by mx2.example.com (8.11.6/8.11.6) with esmtp', ['exchsrv.corp2', 'mx2.example.com']),
    ('from dev3.lab2000 ([198.51.100.30]) by relay.example.org (8.11.6/8.11.6) with esmtp', ['dev3.lab2000', 'relay.example.org']),
    ('from 198.51.100.101-generic ([198.51.100.101]) by mx.example.net (8.8.8/8.8.8) with smtp', ['198.51.100.101-generic', 'mx.example.net']),
    ('from localhost.localdomain by server1.internal', ['localhost.localdomain', 'server1.internal']),
    # names with an underscore (Exchange, Lotus), a single character label or a reverse DNS name were cut or missed
    (
        'from net_server.example.com (192-0-2-45.dsl.example.net [192.0.2.45]) by mx.example.org (8.9.3/8.9.3)',
        ['net_server.example.com', 'mx.example.org'],
    ),
    ('from mx07.example.com (192.0.2.27 [192.0.2.27]) by law_ref_mail.example.org with smtp', ['mx07.example.com', 'law_ref_mail.example.org']),
    ('from relay.mail_gw1.example.com by mx.example.com', ['relay.mail_gw1.example.com', 'mx.example.com']),
    ('from mail10.m.example.net (mail12.m.example.net [198.51.100.137]) by mx1.example.org (postfix)', ['mail10.m.example.net', 'mx1.example.org']),
    ('from 10.113.0.203.in-addr.arpa ([203.0.113.10]) by mx.labs.example.com', ['10.113.0.203.in-addr.arpa', 'mx.labs.example.com']),
    ('from mail.üxample.de by mx.пример.example with esmtp', ['mail.üxample.de', 'mx.пример.example']),
    # IP addresses, local parts of addresses, fragments of longer names, mailer versions and prose are not hosts
    ('from 192.168.1.2 (smtp.example.edu [192.168.1.2]) by mx.example.com', ['mx.example.com']),
    ('from 198.51.100.2 by web15.mail.example.com with http', ['web15.mail.example.com']),
    ('from 198.51.100.08 ([127.0.0.1]) by fileserver.example.com', ['fileserver.example.com']),
    ('from dialup.pub.examplea(203.357.369.35) by dialup(3.4.6.8)65d4rg654g;wed, 27 jun 2001', ['dialup.pub.examplea']),
    ('by mail.example.com. (8.12.5/8.12.5) with esmtp id g7mggjn4090705; thu, 22 aug 2002 (envelope-from john.doe@example.com)', ['mail.example.com']),
    ('from abc.xyz@example.net (unverified [192.0.2.11]) by mail.example.org (emwac smtprs 0.83)', ['mail.example.org']),
    ('from 10182839.55483860.8@bounce.example.com by mailhost with qmail-scanner-1.00', []),
    ('from srv2.domain_example (mail.example.edu [192.0.2.217]) by mx.labs.example.com', ['mx.labs.example.com']),
    ('from mail.example.net.m ([192.0.2.66]) by relay.example.org (8.11.6/8.11.6) with smtp', ['relay.example.org']),
    ('from ppp89-dialup1-1r7029.example.net_[192.0.2.118] [192.0.2.118] by mx.example.org (smtpd32-6.04)', ['mx.example.org']),
    ('from unknown (helo law?ref?mail.example.org) (192.0.2.28) by mail03.svc.example.net (qp 87693)', ['mail03.svc.example.net']),
    ('from mail.example.com\ufffdx by mx.example.com', ['mx.example.com']),
    ('from host.example/8.12.0 by mx.example.com', ['mx.example.com']),
    ('(qmail 4711 invoked by uid 500); 28 sep 2002 16:21:17 -0000', []),
    ('raised as a valueerror from message.get_all(), rather than', []),
]


def test_received_hosts() -> None:
    """Relays are reported in full; IP addresses, their first labels, local parts of addresses and fragments of longer names are not."""
    assert {line: eml_parser.regexes.recv_dom_regex.findall(line) for line, _ in RECEIVED_CASES} == dict(RECEIVED_CASES)


ROUTING_LINES = [
    'from mail-out-f12.example.net (mail-out-f12.example.net. [192.0.2.10]) by mx.example.com (postfix) with esmtps id 4w8x5k6zr2z9srk',
    'from net_server.example.com (192-0-2-45.dsl.example.net [192.0.2.45]) by mx.example.org (8.9.3/8.9.3)',
    'from srv2.domain_example (mail.example.edu [192.0.2.217]) by mx.labs.example.com',
    'from 192.168.1.2 (smtp.example.edu [192.168.1.2]) by mx.example.com',
    'from mail.üxample.de by mx.пример.example with esmtp',
]


def test_received_hosts_agree_with_routing() -> None:
    """Both patterns share the host grammar: a name after "from" or "by" with a TLD of letters is also a host of the routing."""
    disagreeing = {
        line: hosts
        for line in ROUTING_LINES
        if (hosts := [h for h in eml_parser.regexes.recv_dom_regex.findall(line) if h not in eml_parser.routing.get_domain_ip(line)])
    }

    assert disagreeing == {}


def test_received_domain_in_header() -> None:
    """End to end: the relays of all received lines, in order of first appearance, without IP addresses and fragments."""
    raw = (
        b'Received: from 192.168.1.2 (smtp.example.edu [192.168.1.2]) by net_server.example.com (8.9.3/8.9.3); Thu, 22 Aug 2002 17:42:46 +0100\r\n'
        b'Received: from srv2.domain_example (mail.example.edu [192.0.2.217]) by exchsrv.corp2 with esmtp; Thu, 22 Aug 2002 17:40:00 +0100\r\n'
        b'From: a@example.com\r\n\r\nbody\r\n'
    )

    header = eml_parser.parser.EmlParser().decode_email_bytes(raw)['header']

    assert header['received_domain'] == ['net_server.example.com', 'exchsrv.corp2']


MESSAGE = b"""Received: from relay.example.net (envelope-from <sender@example.net>) by mx.example.com for <john@example.com>; Mon, 1 Jan 2024 10:00:00 +0000
Received: from host (helo user@nodomain) by mx.example.com; Mon, 1 Jan 2024 09:00:00 +0000
From: a@example.org
To: john@example.com

body
"""

RECEIVED_EMAIL_CASES = [
    (False, ['sender@example.net', 'user@nodomain']),
    (True, ['sender@example.net']),
]


def test_received_email_reports_addresses() -> None:
    def check(force_tld: bool, expected: list[str]) -> None:
        # Arrange
        parser = eml_parser.parser.EmlParser(email_force_tld=force_tld, domain_force_tld=force_tld)

        # Act
        header = parser.decode_email_bytes(MESSAGE)['header']

        # Assert: addresses, not their domains, and the recipient of the "for" part is not repeated
        assert header['received_email'] == expected

    tests.table.assert_all_cases(check, RECEIVED_EMAIL_CASES)


RAW_EMAIL = (
    b'From: a@example.com\r\nTo: b@example.com\r\nSubject: hi\r\n'
    b'Received: from mx3.example.net (mx3.example.net [203.0.113.3]) by mx2.example.org for <c@example.com>; Mon, 5 Oct 2026 09:12:44 +0200\r\n'
    b'Received: from mx1.example.com (mx1.example.com [198.51.100.1]) by mx3.example.net for <d@example.com>; Mon, 5 Oct 2026 09:11:44 +0200\r\n'
    b'Received: from mx0.example.org (mx0.example.org [192.0.2.7]) by mx1.example.com for <c@example.com>; Mon, 5 Oct 2026 09:10:44 +0200\r\n'
    b'\r\nbody'
)

SCRIPT = """
import json, sys
import eml_parser.parser
header = eml_parser.parser.EmlParser().decode_email_bytes(sys.stdin.buffer.read())['header']
print(json.dumps({key: header.get(key) for key in ('received_email', 'received_domain', 'received_ip', 'received_foremail')}))
"""


def test_received_lists_are_in_order_of_first_appearance() -> None:
    header = eml_parser.parser.EmlParser().decode_email_bytes(RAW_EMAIL)['header']

    assert header['received_ip'] == ['203.0.113.3', '198.51.100.1', '192.0.2.7']
    assert header['received_foremail'] == ['c@example.com', 'd@example.com']
    assert header['received_domain'][:2] == ['mx3.example.net', 'mx2.example.org']


def test_received_lists_are_independent_of_hash_seed() -> None:
    results = set()

    for seed in ('0', '1', '2', '123', '4242'):
        env = {**os.environ, 'PYTHONHASHSEED': seed, 'PYTHONPATH': os.pathsep.join(sys.path)}
        out = subprocess.run([sys.executable, '-c', SCRIPT], input=RAW_EMAIL, capture_output=True, check=True, env=env)  # noqa: S603
        results.add(json.dumps(json.loads(out.stdout)))

    assert len(results) == 1


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


def test_for_without_address_is_omitted() -> None:
    # Arrange
    line = 'from a.example.com by b.example.com for nobody; Mon, 1 Jan 2024 10:00:00 +0000'

    # Act
    parsed = eml_parser.routing.parserouting(line)

    # Assert
    assert 'for' not in parsed
    assert parsed['by'] == ['b.example.com']


def test_received_addresses_without_valid_host_are_dropped_with_email_force_tld() -> None:
    # Arrange
    raw = b'Received: from a.example.com by b.example.com (sender x@y.123 and z@mail.example.com); Mon, 1 Jan 2024 10:00:00 +0000\n\nbody'

    # Act
    loose = eml_parser.parser.EmlParser().decode_email_bytes(raw)['header']
    strict = eml_parser.parser.EmlParser(email_force_tld=True).decode_email_bytes(raw)['header']

    # Assert
    assert loose['received_email'] == ['x@y.123', 'z@mail.example.com']
    assert strict['received_email'] == ['z@mail.example.com']


def test_invalid_byhostentry_setting_does_not_fail_the_parse() -> None:
    # Arrange
    raw = b'Received: from a.example.com ([192.0.2.1]) by mx.example.com; Mon, 1 Jan 2024 10:00:00 +0000\n\nbody'

    # Act
    header = eml_parser.parser.EmlParser(pconf={'byhostentry': 5}).decode_email_bytes(raw)['header']

    # Assert
    assert header['received'] == []
    assert 'received_ip' not in header
