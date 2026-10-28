"""Searching text for indicators: URLs, remote file shares, e-mail addresses, domains and IP addresses."""

import dataclasses
import html
import ipaddress
import logging
import re
import typing
import urllib.parse

import regex

import eml_parser.decode
import eml_parser.hosts
import eml_parser.regexes

logger = logging.getLogger(__name__)

# Whitespace and quote characters in front of an URL.
_URL_LEADING_JUNK = ' \t\n\r\f\v\'"«»“”‘’'

# Characters ending an URL found in text: what follows them is noise.
_URL_NOISE_REGEX = re.compile(r"""[', ")}\\]""")


@dataclasses.dataclass
class BodyIndicators:
    """The indicators found in a text part, in order of their first occurrence. The field names are the keys in the parse result."""

    uri: dict[str, None] = dataclasses.field(default_factory=dict)
    uri_noscheme: dict[str, None] = dataclasses.field(default_factory=dict)
    unc: dict[str, None] = dataclasses.field(default_factory=dict)
    email: dict[str, None] = dataclasses.field(default_factory=dict)
    domain: dict[str, None] = dataclasses.field(default_factory=dict)
    ip: dict[str, None] = dataclasses.field(default_factory=dict)


def sliding_windows(body: str, slice_step: int = 500, max_distance: int = 8192) -> typing.Iterator[str]:
    """Split a large string into consecutive slices which are cut at whitespace.

    Running the regular expressions over a 500K+ body at once causes time and memory issues, so the body is processed in slices.
    A slice is never cut in the middle of a token (URL, address, domain): it ends at the first whitespace found within
    *max_distance* characters after *slice_step* (or at the end of the body). Together the slices cover the complete body without gaps or overlaps.

    Args:
        body: Body to slice into smaller pieces.
        slice_step: Preferred length of a slice.
        max_distance: Maximum number of characters a slice is extended to reach the next whitespace. Tokens longer than
            this are cut. The default is the usual request line limit of web servers, which no sane URL exceeds.

    Yields:
        str: Consecutive slices of the body.
    """
    start = 0
    scanned = 0  # no whitespace was found before this position, so it is not searched again

    while len(body) - start > slice_step:
        end = start + slice_step
        boundary = eml_parser.regexes.window_slice_regex.search(body, max(end, scanned), end + max_distance)
        if boundary:
            end = boundary.start()
        elif len(body) - end <= max_distance:
            # No whitespace, but the body ends within reach, so the last token is complete.
            break
        else:
            scanned = end + max_distance

        yield body[start:end]
        start = end

    yield body[start:]


class IndicatorFinder:
    """Finds the indicators in a text, with the settings of an `EmlParser`."""

    def __init__(self, hosts: eml_parser.hosts.HostValidator, email_regex: regex.Pattern[str], include_www: bool, include_href: bool) -> None:
        """Constructor.

        Args:
            hosts (HostValidator): Validates the hosts of the indicators.
            email_regex (regex.Pattern[str]): Pattern used to find e-mail addresses.
            include_www (bool): Include potential URLs starting with www.
            include_href (bool): Include potential URLs in HREFs matching non-simple regular expressions.
        """
        self._hosts = hosts
        self._email_regex = email_regex
        self._include_www = include_www
        self._include_href = include_href

    def find(self, text: str, whitelist: eml_parser.hosts.IpWhitelist) -> BodyIndicators:
        """Find the URLs, remote file shares, e-mail addresses, domains and IP addresses in a text.

        Args:
            text: The text, e.g. a decoded body.
            whitelist: IP addresses which are left out.

        Returns:
            BodyIndicators: The valid indicators.
        """
        found = BodyIndicators()

        # Running the regular expressions over a 500K+ body at once causes time and memory issues, so the body is processed in slices.
        # Namespace declarations (Outlook HTML, SVG, XHTML) are identifiers, not links, and would be reported as indicators on nearly every mail.
        for body_slice in sliding_windows(eml_parser.regexes.xmlns_declaration_regex.sub(' ', text)):
            self._scan(body_slice, found, whitelist)

        self._add_url_hosts(found, whitelist)
        self._add_share_hosts(found, whitelist)

        return found

    def _scan(self, body_slice: str, found: BodyIndicators, whitelist: eml_parser.hosts.IpWhitelist) -> None:
        """Add the indicators found in one slice of a text to *found*."""
        for url in self.find_urls(body_slice):
            if ':/' in url[:10]:
                found.uri[url] = None
            else:
                found.uri_noscheme[url] = None

        for share in eml_parser.regexes.unc_regex.finditer(body_slice):
            found.unc[share.group(0).rstrip('.,;')] = None

        for match in self._email_regex.findall(body_slice):
            address = match.lower()
            if self._hosts.valid_domain_or_ip(address):
                found.email[address] = None

        self._add_domains(eml_parser.regexes.dom_regex.findall(body_slice), found.domain)

        for ip in eml_parser.regexes.ipv4_regex.findall(body_slice) + eml_parser.regexes.findall_ipv6(body_slice):
            if ':' in ip and not any(char.isdigit() for char in ip) and ip.count(':') < 3:
                # "::" or a scope resolution like "Add::dead" is not an address
                continue

            _add_ip(self._hosts.valid_domain_or_ip(ip.lower()), found.ip, whitelist)

    def _add_url_hosts(self, found: BodyIndicators, whitelist: eml_parser.hosts.IpWhitelist) -> None:
        """Add the domains and IP addresses of the URLs in *found*.

        URLs do not necessarily appear as-is in the body, as they may contain escaped entities, so the domains are extracted again
        from each URL. This runs once over the deduplicated URLs after slicing to keep the cost linear in the body size.
        The URLs are percent-decoded, as the target of a redirector is usually encoded (`?url=https%3A%2F%2Fevil.example%2F`).
        The host is also added in the ASCII form a browser resolves, which covers non-ASCII host names (`пример.рф`, `аpple.com`).
        """
        for url in [*found.uri, *found.uri_noscheme]:
            try:
                host = urllib.parse.urlparse(url if ':/' in url else f'//{url}').hostname
            except ValueError:
                host = None
            ascii_host = eml_parser.hosts.ascii_host(host.rstrip('.')) if host else None

            domain_candidates = eml_parser.regexes.dom_regex.findall(urllib.parse.unquote(url))
            if ascii_host and eml_parser.regexes.dom_regex.fullmatch(ascii_host):
                domain_candidates.append(ascii_host)
            self._add_domains(domain_candidates, found.domain)

            # http://3232235777/ is a valid URL for browsers but contains no dotted IP address
            if ascii_host:
                _add_ip(self._hosts.obfuscated_ip(ascii_host), found.ip, whitelist)

    def _add_share_hosts(self, found: BodyIndicators, whitelist: eml_parser.hosts.IpWhitelist) -> None:
        """Add the hosts of the remote file shares in *found*: it is contacted (and authenticated to) when the path is opened."""
        for share in found.unc:
            share_host = self._hosts.share_host(share)
            if not share_host:
                continue

            try:
                ipaddress.ip_address(share_host)
            except ValueError:
                found.domain[share_host] = None
            else:
                _add_ip(share_host, found.ip, whitelist)

    def _add_domains(self, candidates: typing.Iterable[str], domains: dict[str, None]) -> None:
        """Add the candidates which are valid domains, and not file names, lower-cased to *domains*."""
        for candidate in candidates:
            domain = candidate.lower()
            if not self._hosts.is_file_name(domain) and self._hosts.valid_domain_or_ip(domain):
                domains[domain] = None

    def find_urls(self, body: str) -> list[str]:
        """Find the URLs in a text.

        Args:
            body (str): Text input which should be searched for URLs.

        Returns:
            list: The valid URLs, unique, in order of their first occurrence.
        """
        if self._include_www:
            url_regex, comma_regex = eml_parser.regexes.url_regex_www, eml_parser.regexes.url_regex_www_comma
        else:
            url_regex, comma_regex = eml_parser.regexes.url_regex_simple, eml_parser.regexes.url_regex_comma

        # Several URLs separated by commas only are matched as one, split them.
        candidates: list[str] = []
        for found_url in url_regex.findall(body):
            candidates.extend(comma_regex.split(found_url))

        if self._include_href:
            for attribute_value in eml_parser.regexes.findall_href(body):
                candidates.append(eml_parser.decode.normalize_attribute_url(attribute_value))

        found_urls: dict[str, None] = {}
        for candidate in candidates:
            clean_url = self.clean_url(candidate)
            if clean_url is not None:
                found_urls[clean_url] = None

        return list(found_urls)

    def clean_url(self, url: str) -> str | None:
        """Validate an URL candidate and strip the noise around it.

        Args:
            url (str): A candidate found in a text.

        Returns:
            str: The URL, or None if it is no valid URL.
        """
        if '&' in url:
            url = html.unescape(url)

        if not any(dot in url for dot in '.。．｡') and '[' not in url and not eml_parser.regexes.url_numeric_host_regex.match(url.lstrip(_URL_LEADING_JUNK)):
            # if we found a URL like e.g. http://afafasasfasfas; that makes no
            # sense, thus skip it, but include http://[2001:db8::1] and http://3232235777 (a numeric host is an IPv4 address)
            # Browsers also separate the labels of a host by the ideographic and full width full stops (http://example。com).
            return None

        # Remove leading spaces and quote characters
        url = url.lstrip(_URL_LEADING_JUNK).replace('\r', '').replace('\n', '').replace('\t', '')

        try:
            url = urllib.parse.urlparse(url).geturl()
            has_host = self._has_valid_host(url)
        except ValueError:
            logger.warning('Unable to parse URL - %s', url)
            return None

        if not has_host:
            return None

        # let's try to be smart by stripping of noisy bogus parts
        url = _URL_NOISE_REGEX.split(url, maxsplit=1)[0]

        # filter bogus URLs
        if url.endswith('://'):
            return None

        return url

    def _has_valid_host(self, url: str) -> bool:
        """Whether an URL has a host which is a valid domain or IP address, see `clean_url()`.

        Raises:
            ValueError: If the URL cannot be parsed.
        """
        scheme_url = url
        if url.startswith('//'):
            # protocol-relative URL, i.e. the scheme of the document is used
            scheme_url = f'noscheme:{url}'
        elif ':/' not in scheme_url:
            scheme_url = f'noscheme://{url}'

        hostname = urllib.parse.urlparse(scheme_url).hostname
        if hostname is None:
            return False

        host = hostname.rstrip('.')

        # Without a scheme, a host without a dot or with a file extension is a relative reference like "images/logo.png", not a host.
        if scheme_url.startswith('noscheme:') and ('.' not in host or self._hosts.is_file_name(host)):
            return False

        return self._hosts.valid_domain_or_ip(host) is not None or self._hosts.obfuscated_ip(host) is not None


def _add_ip(ip: str | None, ips: dict[str, None], whitelist: eml_parser.hosts.IpWhitelist) -> None:
    """Add an IP address to *ips*, unless it is None or whitelisted."""
    if ip and ip not in whitelist:
        ips[ip] = None
