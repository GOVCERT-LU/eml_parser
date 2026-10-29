"""Searching text for indicators: URLs, remote file shares, e-mail addresses, domains and IP addresses."""

import bisect
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

# Characters which end an URL in text: around an URL they come from character references (`&quot;`, `&lt;http://example.com/&gt;`).
_URL_END_CHARS = frozenset('"<>')

# A host name in the DNS: labels of letters, digits, hyphens and underscores.
_DNS_NAME_REGEX = re.compile(r"""[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)*\.?""")

# The domain of the first address of a mailto URL: up to a separator of addresses, the query or the text after the address.
_MAILTO_DOMAIN_REGEX = re.compile(r"""[^@,;?]*@([^,;?%<>\s]*)""")

# What browsers strip from both ends of an URL attribute value: C0 control characters and space.
_C0_CONTROL_OR_SPACE = ''.join(map(chr, range(0x21)))

# Closing brackets which end an URL found in text unless the URL contains the opening one: "(see http://example.com/x)" ends before
# the ")", "http://en.wikipedia.org/wiki/Foo_(bar)" does not.
_URL_BRACKETS = {')': '(', '}': '{'}

# Punctuation which ends a sentence rather than an URL, removed from the end of an URL found in text.
_URL_TRAILING_PUNCTUATION = '.,;:!'


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

        # Namespace declarations (Outlook HTML, SVG, XHTML) are identifiers, not links, and would be reported as indicators on nearly every mail.
        text = eml_parser.regexes.xmlns_declaration_regex.sub(' ', text)

        for url in self.find_urls(text):
            if ':/' in url[:10]:
                found.uri[url] = None
            else:
                found.uri_noscheme[url] = None

        # Running the regular expressions over a 500K+ body at once causes time and memory issues, so the body is processed in slices.
        for body_slice in sliding_windows(text):
            self._scan(body_slice, found, whitelist)

        self._add_url_hosts(found, whitelist)
        self._add_share_hosts(found, whitelist)

        return found

    def _scan(self, body_slice: str, found: BodyIndicators, whitelist: eml_parser.hosts.IpWhitelist) -> None:
        """Add the indicators other than URLs found in one slice of a text to *found*."""
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
            host = _host_of(url)
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

    def find_urls(self, text: str) -> list[str]:
        """Find the URLs in a text.

        The values of HTML attributes are found in the whole text, as a tag or a value with white space may cross the boundary of a slice;
        URLs in text are searched in slices (see `sliding_windows()`). The URLs of the attributes starting in a slice follow the URLs
        found in its text.

        Args:
            text (str): Text input which should be searched for URLs.

        Returns:
            list: The valid URLs, unique, in order of their first occurrence.
        """
        if self._include_www:
            url_regex, comma_regex = eml_parser.regexes.url_regex_www, eml_parser.regexes.url_regex_www_comma
        else:
            url_regex, comma_regex = eml_parser.regexes.url_regex_simple, eml_parser.regexes.url_regex_comma

        attribute_spans = eml_parser.regexes.href_value_spans(text) if self._include_href else []
        attribute_starts = [start for start, _ in attribute_spans]
        attribute_urls = [self.clean_url(eml_parser.decode.normalize_attribute_url(text[start:end]), in_attribute=True) for start, end in attribute_spans]
        found_urls: dict[str, None] = {}
        next_attribute = 0
        offset = 0

        for body_slice in sliding_windows(text):
            for match in url_regex.finditer(body_slice):
                position = offset + match.start()
                span_index = bisect.bisect_right(attribute_starts, position) - 1
                inside_attribute = span_index >= 0 and position < attribute_spans[span_index][1]
                attribute_url = attribute_urls[span_index] if inside_attribute else None

                # Several URLs separated by commas only are matched as one, split them.
                for candidate in comma_regex.split(match.group()):
                    url = self.clean_url(candidate)
                    if url is None:
                        continue

                    # The text search sees only a part of an URL in an attribute value, e.g. up to a space ("http://example.com/a b"), or reads
                    # past its quote. That URL is the attribute URL; other URLs in the value (a missing closing quote) are reported themselves.
                    if attribute_url is not None and (attribute_url.startswith(url) or url.startswith(attribute_url)):
                        url = attribute_url

                    found_urls[url] = None

            offset += len(body_slice)
            while next_attribute < len(attribute_spans) and attribute_starts[next_attribute] < offset:
                if (url := attribute_urls[next_attribute]) is not None:
                    found_urls[url] = None
                next_attribute += 1

        return list(found_urls)

    def clean_url(self, url: str, *, in_attribute: bool = False) -> str | None:
        """Find where an URL candidate ends and validate it.

        The value of an HTML attribute is the URL as a browser takes it: with the character references decoded (see
        `decode.normalize_attribute_url()`), up to its closing quote, without the control characters and spaces at its ends. An URL in
        text ends where the text around it begins (see `_end_of_text_url()`). The URL is validated as it is returned.

        Args:
            url (str): A candidate found in a text, or the normalised value of an HTML attribute (with its opening quote).
            in_attribute (bool): Whether the candidate is the value of an HTML attribute.

        Returns:
            str: The URL, or None if it is no valid URL.
        """
        if in_attribute:
            url = (url[1:] if url[:1] in ('"', "'") else url).strip(_C0_CONTROL_OR_SPACE)
        else:
            if '&' in url:
                url = html.unescape(url)

            # Remove leading spaces and quote characters, and the characters browsers drop from URLs
            url = url.lstrip(_URL_LEADING_JUNK).replace('\r', '').replace('\n', '').replace('\t', '')
            url = url[: _end_of_text_url(url)]

        # Browsers decode the host before they look at it (`http://%31%30%31%2e%31/` is 101.0.0.1).
        decoded_url = urllib.parse.unquote(url) if '%' in url else url
        if not any(dot in decoded_url for dot in '.。．｡') and '[' not in decoded_url and not eml_parser.regexes.url_numeric_host_regex.match(decoded_url):
            # if we found a URL like e.g. http://afafasasfasfas; that makes no
            # sense, thus skip it, but include http://[2001:db8::1] and http://3232235777 (a numeric host is an IPv4 address)
            # Browsers also separate the labels of a host by the ideographic and full width full stops (http://example。com).
            return None

        try:
            url = urllib.parse.urlparse(url).geturl()
            has_host = self._has_valid_host(url)
        except ValueError:
            logger.warning('Unable to parse URL - %s', url)
            return None

        if not has_host or url.endswith('://'):
            return None

        return url

    def _is_host_name(self, host: str, has_scheme: bool) -> bool:
        """Whether the host of an URL is written like a host name: as browsers accept it, and without a scheme as a DNS name."""
        # A host with a code point browsers forbid as written (`|`, `^`, white space, ...) is none. A percent-encoded host is kept whatever it
        # decodes to: `www.example.com%40%65vil.example` is the obfuscation of an address, an indicator (its domains are taken from the
        # decoded URL, see `_add_url_hosts()`). An internationalised name must be valid.
        if eml_parser.regexes.forbidden_domain_char_regex.search(host.replace('%', '')):
            return False

        ascii_host = eml_parser.hosts.ascii_host(host)
        if has_scheme:
            return ascii_host is not None or '%' in host

        # Without a scheme, browsers take the value as a relative reference, it is reported as `host/path` only if it starts with a host
        # name: no "images/logo.png" (no dot or a file extension) nor `3D"mailto:a@example.com"` (undecoded quoted-printable).
        return '.' in host and not self._hosts.is_file_name(host) and ascii_host is not None and _DNS_NAME_REGEX.fullmatch(ascii_host) is not None

    def _has_valid_host(self, url: str) -> bool:
        """Whether an URL has a host which is a valid domain or IP address, see `clean_url()`.

        Raises:
            ValueError: If the URL cannot be parsed.
        """
        if url[:7].lower() == 'mailto:':
            # No authority: the host is the domain of the first address (`mailto:a@example.com, b@example.org?subject=x`,
            # `mailto:a@example.com%20<a@example.com>`).
            match = _MAILTO_DOMAIN_REGEX.match(url, 7)
            if match is None:
                return False
            host, has_scheme = match.group(1).rstrip('.').lower(), True
        else:
            scheme_url = url
            if url.startswith('//'):
                # protocol-relative URL, i.e. the scheme of the document is used
                scheme_url = f'noscheme:{url}'
            elif ':/' not in scheme_url:
                scheme_url = f'noscheme://{url}'

            parsed = urllib.parse.urlparse(scheme_url)
            if parsed.hostname is None:
                return False

            host, has_scheme = parsed.hostname.rstrip('.'), not scheme_url.startswith('noscheme:')
            if '[' in parsed.netloc:
                # Browsers accept only an IPv6 address in brackets, not the IPvFuture syntax which urllib accepts (`[v1.x]`).
                return eml_parser.hosts.normalized_ip(host) is not None and self._hosts.valid_domain_or_ip(host) is not None

        if any(char.isspace() for char in host) or not self._is_host_name(host, has_scheme):
            # The path of an attribute URL may contain white space, a host may not (browsers reject it).
            return False

        return self._hosts.valid_domain_or_ip(host) is not None or self._hosts.obfuscated_ip(host) is not None


def _host_of(url: str) -> str | None:
    """The host of an URL validated by `IndicatorFinder.clean_url()`: of a mailto URL the domain of its first address."""
    if url[:7].lower() == 'mailto:':
        match = _MAILTO_DOMAIN_REGEX.match(url, 7)
        return match.group(1) if match else None

    # Parsed like in clean_url(), so it can be parsed again.
    return urllib.parse.urlparse(url if ':/' in url else f'//{url}').hostname


def _end_of_text_url(url: str) -> int:
    """The length of an URL found in text, in front of the text which follows it.

    An URL in text ends at white space, at `"`, `<` or `>` (see `_URL_END_CHARS`), at a backslash, at a comma in front of the path (host names have none), at a closing
    bracket whose opening one is not part of the URL and at an apostrophe which is not between two letters or digits (`it's` stays,
    `'http://example.com/x',` ends before the quote). Sentence punctuation at the end is not part of the URL either.
    """
    scheme_end = url.find('://')
    authority_start = 0 if scheme_end == -1 else scheme_end + 3
    open_brackets = dict.fromkeys(_URL_BRACKETS.values(), 0)
    in_authority = True
    end = len(url)

    for index, char in enumerate(url):
        if index >= authority_start and char in '/?#':
            in_authority = False

        if char in _URL_END_CHARS or char.isspace() or char == '\\' or (char == ',' and in_authority and index >= authority_start):
            end = index
            break

        if char in open_brackets:
            open_brackets[char] += 1
        elif char in _URL_BRACKETS:
            if open_brackets[_URL_BRACKETS[char]] == 0:
                end = index
                break
            open_brackets[_URL_BRACKETS[char]] -= 1
        elif char == "'" and not (url[index - 1 : index].isalnum() and url[index + 1 : index + 2].isalnum()):
            end = index
            break

    return len(url[:end].rstrip(_URL_TRAILING_PUNCTUATION))


def _add_ip(ip: str | None, ips: dict[str, None], whitelist: eml_parser.hosts.IpWhitelist) -> None:
    """Add an IP address to *ips*, unless it is None or whitelisted."""
    if ip and ip not in whitelist:
        ips[ip] = None
