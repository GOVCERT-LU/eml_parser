import pytest

import eml_parser.routing

TAIL = '; Mon, 5 Oct 2026 09:12:44 +0200'


def parse(line: str) -> dict:
    return eml_parser.routing.parserouting(line)


@pytest.mark.parametrize(
    ('line', 'expected_from', 'expected_by'),
    [
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
    ],
)
def test_sections(line: str, expected_from: list[str], expected_by: list[str]) -> None:
    result = parse(line)

    assert result['from'] == expected_from
    assert result['by'] == expected_by


def test_hosts_are_in_order_of_appearance() -> None:
    result = parse('from mail.example.com (mail.example.com [192.0.2.1] [2001:db8::1]) by mx.example.org' + TAIL)

    assert result['from'] == ['mail.example.com', '192.0.2.1', '2001:db8::1']


@pytest.mark.parametrize(
    ('line', 'expected_by'),
    [
        # version numbers are no host names
        ('from a.example.com by mx.example.org (Exim 4.96) id 1' + TAIL, ['mx.example.org']),
        ('from a.example.com by mx.example.org (8.12.2/8.12.2/20020902/$Revision: 1.30 $) with SMTP' + TAIL, ['mx.example.org']),
        # the domain of an address in angle brackets is no relay
        ('from a.example.com by mx.example.org (envelope-from <s@sender.example>) id 1' + TAIL, ['mx.example.org']),
        ('from a.example.com by mx.example.org with SMTP id <B001@msg.example>' + TAIL, ['mx.example.org']),
    ],
)
def test_by_contains_only_relays(line: str, expected_by: list[str]) -> None:
    assert parse(line)['by'] == expected_by


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


@pytest.mark.parametrize(
    ('line', 'expected'),
    [
        ('from a.example.com by b.example.com' + TAIL + ' (CEST)', '2026-10-05T09:12:44+02:00'),
        ('from a.example.com by b.example.com; Mon, 5 Oct 2026 09:12:44.123 -0500', '2026-10-05T09:12:44.123000-05:00'),
        ('from a.example.com by b.example.com; 5 Oct 2026 07:12:44 -0000', '2026-10-05T07:12:44+00:00'),
    ],
)
def test_date(line: str, expected: str) -> None:
    assert parse(line)['date'].isoformat() == expected


@pytest.mark.parametrize(
    'line', ['from a.example.com by b.example.com', 'from a.example.com by b.example.com; not a date', 'from a.example.com by b.example.com;']
)
def test_no_date_is_invented(line: str) -> None:
    assert 'date' not in parse(line)


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


@pytest.mark.parametrize(
    ('text', 'expected'),
    [('', ''), ('  ; x ;  ', 'x'), ('; ; x　;', 'x'), ('x', 'x')],
)
def test_cleanline_unicode_whitespace(text: str, expected: str) -> None:
    assert eml_parser.routing.cleanline(text) == expected


@pytest.mark.parametrize(
    ('line', 'expected_by'),
    [
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
    ],
)
def test_by_in_real_world_formats(line: str, expected_by: list[str]) -> None:
    assert parse(line)['by'] == expected_by


def test_line_in_brackets() -> None:
    result = parse(
        '[from pobox3.example.org (pobox3.example.org [192.0.2.242]) by motgate4.example.org (motgate4 2.1) with ESMTP id haa08361; Tue, 13 Nov 2001 07:51:10 -0700 (MST)]'
    )

    assert result['from'] == ['pobox3.example.org', '192.0.2.242']
    assert result['by'] == ['motgate4.example.org']


@pytest.mark.parametrize(
    'tail',
    [
        '; tue, 15 aug 2000 gmt',  # no time
        '; wed, 21 feb 2001 19:29: 59 -0500',  # blank in the time
        '; tue, 15 aug 2000 08:57:09 -04= 00',  # left over of a quoted-printable line break, dateutil would ignore it and return a wrong zone
        '; of, 15 ssa 2000 09:40:38 -0600',
    ],
)
def test_garbage_is_not_a_date(tail: str) -> None:
    assert 'date' not in parse('from a.example.com by b.example.com' + tail)


@pytest.mark.parametrize(
    ('text', 'expected'),
    [
        ('mail10.m.example.net', ['mail10.m.example.net']),  # single character labels
        ('mail_gw1.example.com', ['mail_gw1.example.com']),  # underscore, used by Exchange and Lotus servers
        ('a.example.com, b.example.org;', ['a.example.com', 'b.example.org']),  # separated by comma
        ('*.example.com', ['example.com']),  # wildcard
        ('user.name@mx.example.com', ['mx.example.com']),  # local part of an address
        ('id 1.b9.b1afe75 id x.bd.69a6d55', []),  # message ids
        ('(8.12.0.beta16/8.12.0 v82.22 Exim 4.96)', []),  # versions
        ('xn--mx-example.xn--p1ai', ['xn--mx-example.xn--p1ai']),  # punycode TLD
    ],
)
def test_get_domain_ip_host_names(text: str, expected: list[str]) -> None:
    assert eml_parser.routing.get_domain_ip(text) == expected


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
