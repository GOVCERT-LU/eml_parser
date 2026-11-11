"""Validation of the hosts found in a message: domains, IP addresses in any notation browsers accept, and the IP whitelist."""

import collections.abc
import dataclasses
import encodings.punycode
import functools
import ipaddress
import socket
import typing
import urllib.parse

import idna
import publicsuffixlist

import eml_parser.constants
import eml_parser.regexes

IPAddress: typing.TypeAlias = ipaddress.IPv4Address | ipaddress.IPv6Address


@functools.cache
def get_public_suffix_list(accept_unknown: bool) -> publicsuffixlist.PublicSuffixList:
    """Return the public suffix list; it is parsed once per setting and shared, as parsing it takes about 40 ms and it is read-only afterwards.

    Args:
        accept_unknown: Whether names with an unknown top level domain are accepted.

    Returns:
        The parsed public suffix list.
    """
    return publicsuffixlist.PublicSuffixList(accept_unknown=accept_unknown)


def normalized_ip(text: str) -> IPAddress | None:
    """Parse an IP address for comparisons, independent of its notation.

    Brackets and the zone index are removed and an IPv4-mapped IPv6 address is its IPv4 address, so `2001:DB8:0::1`
    equals `2001:db8::1`, `[fe80::1%eth0]` equals `fe80::1` and `::ffff:192.0.2.1` equals `192.0.2.1`.

    Args:
        text: The address.

    Returns:
        The address, or None if the text is no IP address.
    """
    address_text = text.strip('[]').partition('%')[0]

    try:
        address = ipaddress.ip_address(address_text)
    except ValueError:
        return None

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped

    return address


def punycode(label: str) -> str:
    """Encode a label to punycode (RFC 3492), the same as `label.encode('punycode')` in O(n log n) instead of O(n²) time.

    The stdlib codec scans the whole label once per distinct code point to compute the insertion deltas, which is quadratic
    for labels of distinct code points: one of 1 000 takes 0.15 s, and a message may contain many. The deltas are computed
    here by counting the smaller code points before each position in a Fenwick tree; the stdlib still encodes them.

    Args:
        label: The label, of any length.

    Returns:
        The punycode of the label, without the `xn--` prefix.
    """
    length = len(label)
    smaller_tree = [0] * (length + 1)  # Fenwick tree over the positions of the code points encoded so far, basic ones first
    positions_by_code_point: dict[int, list[int]] = {}
    basic = []

    def mark_encoded(position: int) -> None:
        index = position + 1
        while index <= length:
            smaller_tree[index] += 1
            index += index & -index

    for position, char in enumerate(label):
        if char < '\x80':
            basic.append(char)
            mark_encoded(position)
        else:
            positions_by_code_point.setdefault(ord(char), []).append(position)

    deltas = []
    encoded_count = len(basic)
    delta = 0
    next_code_point = 0x80
    for code_point in sorted(positions_by_code_point):
        positions = positions_by_code_point[code_point]
        delta += (code_point - next_code_point) * (encoded_count + 1)
        previous_smaller = 0
        for position in positions:
            smaller = 0
            index = position
            while index:
                smaller += smaller_tree[index]
                index &= index - 1
            deltas.append(delta + smaller - previous_smaller)
            delta = 0
            previous_smaller = smaller
        delta = encoded_count - previous_smaller + 1
        for position in positions:
            mark_encoded(position)
        encoded_count += len(positions)
        next_code_point = code_point + 1

    extended = encodings.punycode.generate_integers(len(basic), deltas).decode('ascii')
    return f'{"".join(basic)}-{extended}' if basic else extended


def ascii_host(host: str) -> str | None:
    """Convert the host name of an URL to the ASCII form a browser resolves (domain to ASCII of the WHATWG URL standard).

    The host is percent-decoded and mapped with UTS #46, non-transitional like browsers: upper case and full width characters
    are folded, ignored characters such as U+200B or U+00AD are dropped and the ideographic full stop separates labels.
    Non-ASCII labels are converted to punycode (`аpple.com` with a Cyrillic "а" is `xn--pple-43d.com`, `faß.de` is
    `xn--fa-hia.de`). Unlike the `idna` codecs, symbols such as emoji are accepted, as browsers do (`💩.la` is `xn--ls8h.la`).

    Args:
        host (str): The host name of an URL.

    Returns:
        str: The host name in ASCII, or None if a browser rejects it (a disallowed or forbidden code point, a misplaced joiner,
        a label violating the bidi rule or starting with a combining mark).
    """
    if not host.isascii() or '%' in host:
        try:
            labels = idna.uts46_remap(urllib.parse.unquote(host), std3_rules=False, transitional=False).split('.')
            for position, label in enumerate(labels):
                if label.isascii():
                    continue

                idna.check_initial_combiner(label)
                idna.check_bidi(label)
                if not all(idna.valid_contextj(label, index) for index, char in enumerate(label) if char in '‌‍'):
                    return None

                labels[position] = f'xn--{punycode(label)}'
        except idna.IDNAError:
            return None

        host = '.'.join(labels)

    return None if eml_parser.regexes.forbidden_domain_char_regex.search(host) else host


@dataclasses.dataclass(frozen=True)
class IpWhitelist:
    """The IP addresses of `pconf['whiteip']`, which are not reported as indicators."""

    entries: collections.abc.Collection[str]  # as configured, compared as given
    addresses: frozenset[IPAddress]  # the entries which are IP addresses, see `normalized_ip()`

    @classmethod
    def from_entries(cls, entries: collections.abc.Collection[str]) -> 'IpWhitelist':
        """Build the whitelist of the configured entries.

        Args:
            entries: The configured entries.

        Returns:
            IpWhitelist: The whitelist.
        """
        addresses = set()

        for entry in entries:
            address = normalized_ip(str(entry))
            if address is not None:
                addresses.add(address)

        return cls(entries, frozenset(addresses))

    def __contains__(self, ip: object) -> bool:
        """Check whether an IP address is whitelisted, in any notation (see `normalized_ip()`)."""
        # Entries are also compared as given, as before addresses were parsed.
        if ip in self.entries:
            return True

        address = normalized_ip(str(ip))
        return address is not None and address in self.addresses


class HostValidator:
    """Decides whether a host is a valid domain or IP address, with the settings of an `EmlParser`."""

    def __init__(self, domain_force_tld: bool, ip_force_routable: bool) -> None:
        """Constructor.

        Args:
            domain_force_tld (bool): Require a known top level domain.
            ip_force_routable (bool): Require a globally routable IP address.
        """
        self._ip_force_routable = ip_force_routable
        self._psl = get_public_suffix_list(not domain_force_tld)
        # A file extension which is a TLD (or becomes one) is a domain and not a file name, so the public suffix list decides.
        self._file_extensions = frozenset(
            ext for ext in eml_parser.constants.FILE_EXTENSIONS if self._psl.publicsuffix(f'x.{ext}', accept_unknown=False) is None
        )
        # The same hosts occur over and over in a body; the verdict only depends on the settings, which are constant.
        self._cached_valid_domain_or_ip = functools.lru_cache(maxsize=32768)(self._valid_domain_or_ip)

    def is_file_name(self, domain: str) -> bool:
        """Check whether a domain-like string is rather a file name, e.g. *invoice.pdf*."""
        return domain.rpartition('.')[2].lower() in self._file_extensions

    def valid_domain_or_ip(self, data: str) -> str | None:
        """Determine whether the host of an IP address, e-mail address or domain is valid.

        Args:
            data (str): The IP address, e-mail address or domain.

        Returns:
            str: The IP address or the host, or None if it is not valid.
        """
        return self._cached_valid_domain_or_ip(data)

    def _valid_domain_or_ip(self, data: str) -> str | None:
        """Uncached implementation of `valid_domain_or_ip()`."""
        host = data.rpartition('@')[-1].strip(' \r\n\t[]')

        try:
            valid_ip = ipaddress.ip_address(host.partition('%')[0])
        except ValueError:
            # A top level domain is never numeric (RFC 3696, section 2): this rejects invalid addresses ("999.1.1.1") and version numbers ("v1.20.30").
            if host.rstrip('.').rpartition('.')[2].isdecimal():
                return None

            return host if self._psl.publicsuffix(host) else None

        # Not a precise filter for IPv4/IPv6 addresses. Can be enhanced with pconf whiteip ranges
        if self._ip_force_routable and not (valid_ip.is_global and not valid_ip.is_reserved):
            return None

        return str(valid_ip)

    def obfuscated_ip(self, host: str) -> str | None:
        """Resolve a host which is an IPv4 address in a notation browsers accept, e.g. `3232235777`, `0xC0A80101`, `0300.0250.0.1` or `127.1`.

        Args:
            host (str): The host name of an URL.

        Returns:
            str: The address in dotted decimal notation (if it passes the IP validation) or None.
        """
        if not eml_parser.regexes.ipv4_obfuscated_regex.fullmatch(host):
            return None

        try:
            return self.valid_domain_or_ip(socket.inet_ntoa(socket.inet_aton(host)))
        except OSError:
            return None

    def share_host(self, share: str) -> str | None:
        """Get the host of a remote file share reference (see `regexes.unc_regex`) if it is a domain or an IP address.

        A bare NetBIOS name such as *fileserver* is a host of the local network and no indicator; *localhost* is local as well.
        Encoded IPv6 addresses (`2001-db8--1.ipv6-literal.net`) are decoded and numeric hosts (a decimal IPv4 address) are resolved like in the URLs.

        Args:
            share: A match of `regexes.unc_regex`.

        Returns:
            str: The domain or IP address, or None.
        """
        match = eml_parser.regexes.unc_regex.match(share)
        if match is None:
            return None

        host = (match.group('unc_host') or match.group('url_host')).partition('@')[0].lower()  # `@SSL` and `@port` select WebDAV
        if host.endswith('.ipv6-literal.net'):
            host = host.removesuffix('.ipv6-literal.net').replace('-', ':')

        if '.' in host or ':' in host:
            return self.valid_domain_or_ip(host)

        return self.obfuscated_ip(host)
