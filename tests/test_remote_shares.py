"""Tests for UNC paths and file/smb URLs pointing to remote hosts."""

import hashlib

import pytest

import eml_parser.parser
import eml_parser.regexes


@pytest.mark.parametrize(
    ('text', 'host'),
    [
        (r'\\attacker.example.com\share\a.png', 'attacker.example.com'),
        (r'open "\\fileserver\public\doc.docx" now', 'fileserver'),
        (r'\\evil.example.net@SSL\DavWWWRoot\x.lnk', 'evil.example.net@SSL'),
        (r'\\evil.example.net@8080\x\y', 'evil.example.net@8080'),
        (r'\\?\UNC\srv.example.com\share\f', 'srv.example.com'),
        ('file://10.1.2.3/share/x.lnk', '10.1.2.3'),
        ('file:////evil.example.org/s/x', 'evil.example.org'),
        ('smb://203.0.113.9/c$', '203.0.113.9'),
    ],
)
def test_remote_share_is_found(text: str, host: str) -> None:
    """UNC paths (also the WebDAV forms) and file/smb URLs with a host."""
    match = eml_parser.regexes.unc_regex.search(text)

    assert match is not None
    assert (match.group('unc_host') or match.group('url_host')) == host


@pytest.mark.parametrize(
    'text', [r'C:\\Users\\Bob', r'"\\\\Users\\Bob"', r'regex \\d+\\w', r'path\\host\share', 'file:///C:/x.txt', 'file:/relative', r'\\host']
)
def test_local_and_escaped_paths_are_ignored(text: str) -> None:
    """Escaped text, drive paths, local file URLs and a bare host are not remote shares."""
    assert eml_parser.regexes.unc_regex.search(text) is None


@pytest.mark.parametrize(
    ('share', 'expected'),
    [
        (r'\\attacker.example.com\share', 'attacker.example.com'),
        (r'\\evil.example.net@SSL\DavWWWRoot\x', 'evil.example.net'),
        (r'\\3232235777\c$', '192.168.1.1'),
        (r'\\2001-db8--1.ipv6-literal.net\s', '2001:db8::1'),
        (r'\\fileserver\public', None),
        ('file://localhost/x', None),
    ],
)
def test_get_share_host(share: str, expected: str | None) -> None:
    """The host is an indicator only if it is a domain or an address."""
    assert eml_parser.parser.EmlParser().get_share_host(share) == expected


HTML = (
    '<img src="\\\\attacker.example.com\\share\\a.png"> see \\\\fileserver\\public\\doc.docx, \\\\203.0.113.9\\c$ and C:\\\\Users\\\\Bob '
    '<a href="file:////evil.example.org/s/x.lnk">x</a>'
)


def test_body_extraction() -> None:
    """The shares are reported and their hosts are added to the domains and IPs."""
    raw = f'From: a@example.com\r\nContent-Type: text/html\r\n\r\n{HTML}'.encode()
    body = eml_parser.parser.EmlParser(include_raw_body=True).decode_email_bytes(raw)['body'][0]

    assert body['unc'] == [
        '\\\\attacker.example.com\\share\\a.png',
        '\\\\fileserver\\public\\doc.docx',
        '\\\\203.0.113.9\\c$',
        'file:////evil.example.org/s/x.lnk',
    ]
    assert sorted(body['domain']) == ['attacker.example.com', 'evil.example.org']
    assert body['ip'] == ['203.0.113.9']


def test_hashed_mode() -> None:
    """Without raw body only hashes of the shares are reported."""
    raw = f'From: a@example.com\r\nContent-Type: text/html\r\n\r\n{HTML}'.encode()
    body = eml_parser.parser.EmlParser().decode_email_bytes(raw)['body'][0]

    assert 'unc' not in body
    assert body['unc_hash'][0] == hashlib.sha256(b'\\\\attacker.example.com\\share\\a.png').hexdigest()
