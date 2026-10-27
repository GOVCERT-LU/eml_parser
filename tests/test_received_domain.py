"""Tests for `received_domain`: the host names following "from" and "by" in the received lines.

The cases are modelled on received lines of the SpamAssassin public corpus (with example names), where the former
`regexes.recv_dom_regex` reported fragments and missed hosts.
"""

import eml_parser.parser
import eml_parser.regexes
import eml_parser.routing

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
