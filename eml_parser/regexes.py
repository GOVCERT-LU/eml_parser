# pylint: disable=line-too-long

"""This module contains a number of regular expressions used by this Library."""

import regex as re

__author__ = 'Toth Georges, Jung Paul'
__email__ = 'georges@trypill.org, georges.toth@govcert.etat.lu'
__copyright__ = 'Copyright 2013-2014 Georges Toth, Copyright 2013-present GOVCERT Luxembourg'
__license__ = 'AGPL v3+'

# regex compilation
# W3C HTML5 standard recommended regex for e-mail validation
# It also implements the 64 character limit on the local part (RFC 5321, section 2.4), with a safety factor.
# This mitigates an issue with quadratic complexity when searching for e-mail addresses in very long strings.
email_no_force_tld_regex = re.compile(r"""([a-zA-Z0-9.!#$%&'*+\-/=?^_`{|}~]{1,128}@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*)""")
email_force_tld_regex = re.compile(r"""([a-zA-Z0-9.!#$%&'*+\-/=?^_`{|}~]{1,128}@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)""")
email_regex = email_no_force_tld_regex


# regex for detecting RFC2047 encodings - used from https://dmorgan.info/posts/encoded-word-syntax/
# Only used to find out whether a value contains an encoded word. The parts must not contain "?" (or white space), otherwise the pattern is quadratic or worse for a value like "=?=?=?=?...".
email_regex_rfc2047 = re.compile(r"""=\?[^\s?]+\?[BbQq]\?[^\s?]+\?=""")

recv_dom_regex = re.compile(r"""(?:(?:from|by)\s+)([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]{2,})+)""")

dom_regex = re.compile(r"""(?:^|[\s(/<>|@'=])([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]{2,})+)(?=$|[\?\s#&/<>')])""", re.MULTILINE)

# An address must not be part of a longer dotted number or word ("1.2.3.4.5", "v1.2.3.4") nor be the first labels of a host name ("1.2.3.4.nip.io").
# The boundaries are ASCII only on purpose, as text in e.g. CJK scripts is often not separated by whitespace. A sentence ending dot is fine.
ipv4_regex = re.compile(r"""(?<![0-9A-Za-z_.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![0-9A-Za-z_])(?!\.[0-9A-Za-z_])""")

# From https://gist.github.com/mnordhoff/2213179 : IPv6 with zone ID (RFC 6874)
_IPV6_ADDRESS = r"""((?:[0-9a-f]{1,4}:){6}(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9a-f]{1,4}:){5}(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){4}(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9a-f]{1,4}:[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){3}(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9a-f]{1,4}:){,2}[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){2}(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9a-f]{1,4}:){,3}[0-9a-f]{1,4})?::[0-9a-f]{1,4}:(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9a-f]{1,4}:){,4}[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9a-f]{1,4}:){,5}[0-9a-f]{1,4})?::[0-9a-f]{1,4}|(?:(?:[0-9a-f]{1,4}:){,6}[0-9a-f]{1,4})?::)"""

# An address must not directly follow a word character, a dot or a colon (exception: the "IPv6:" tag of address literals) nor be followed by a word character
# or a colon and hex digit, otherwise parts of longer sequences such as "std::vector" or "1:2:3:4:5:6:7:8:9" would be reported.
ipv6_regex = re.compile(r"""(?:(?<![0-9A-Za-z_.:])|(?<=ipv6:))""" + _IPV6_ADDRESS + r"""(?![0-9A-Za-z_])(?!:[0-9a-f])""", flags=re.IGNORECASE)


def findall_ipv6(text: str) -> list[str]:
    """Find IPv6 addresses, skipping the (expensive) pattern for text which cannot contain one.

    An address has either a "::" or at least seven colons (six with an embedded IPv4 address), so most of the text is rejected by two cheap checks.

    Args:
        text (str): Text input which should be searched for IPv6 addresses.

    Returns:
        list: The addresses, in order of appearance.
    """
    if '::' in text or text.count(':') >= 6:
        return ipv6_regex.findall(text)

    return []


# simple version for searching for URLs
# character set based on http://tools.ietf.org/html/rfc3986
# url_regex_simple = re.compile(r'''(?:(?:https?|ftps?)://)(?:\S+(?::\S*)?@)?(?:(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,})))(?::\d{2,5})?(?:/[^\s]*)?''')
# regex updated from https://gist.github.com/gruber/8891611 but modified with:
#   - do not use a fixed list of TLDs but rather \w
#   - only check for URLs with scheme
#   - modify the end marker to allow any acceptable char according to the RFC3986

url_regex_comma = re.compile(r',(?=https?|ftps?)', flags=re.IGNORECASE)
url_regex_www_comma = re.compile(r',(?=https?|ftps?|www\d{0,3})', flags=re.IGNORECASE)

url_regex_simple = re.compile(
    r"""
\b
(?:https?|ftps?):
(?:/{1,3}|[a-z0-9%])
(?:
  \[[0-9a-f:.]{2,40}(?:%[^\x00-\x20\s\]]{1,100})?\]
|
  [^\x00-\x20\s`()<>{}\[\]\/'"«»“”‘’]+
)
(?:[\w\-._~%!$&'()*+,;=:/?#\[\]@\U00001000-\U0010FFFF]*[^\x00-\x20\s`!\[\]{};:'".,<>«»“”‘’])?
""",
    flags=re.IGNORECASE | re.VERBOSE,
)
url_regex_www = re.compile(
    r"""
(?:
# http/ftp schemes
    \b
    (?:https?|ftps?):
    (?:/{1,3}|[a-z0-9%])
    (?:
      \[[0-9a-f:.]{2,40}(?:%[^\x00-\x20\s\]]{1,100})?\]
    |
      [^\x00-\x20\s`()<>{}\[\]\/'"«»“”‘’]+
    )
    (?:[\w\-._~%!$&'()*+,;=:/?#\[\]@\U00001000-\U0010FFFF]*[^\x00-\x20\s`!\[\]{};:'".,<>«»“”‘’])?
|
# www address  (any preceding matched character needs to be removed afterward)
    (?:
    ^|[ \t\n\r\f\v\'\"«»“”‘’])
    www\d{0,3}[.](?:[-\w\u0900-\u2017\u2020-\U0010FFFF]{1,250}[.]){1,250}[-0-9a-z\w\u0900-\u0DFF]{2,30}[.]*  # Host Simple TLD regex
    (?::[0]*[1-9][0-9]{0,4})?  # Port
    (?:[\/#?](?:[\w\-._~%!$&'()*+,;=:/?#\[\]@\U00001000-\U0010FFFF]*[^\x00-\x20\s`!\[\]{};:'\".,<>«»“”‘’])) # Path, etc.
)
""",
    flags=re.IGNORECASE | re.VERBOSE,
)


# Search for URLs in the attributes of HTML tags: links and images, but also the targets of forms (phishing), frames, scripts, embedded objects and redirects.
# The scan overlaps with url_regex_simple, so simple URL content that starts with "<a " or "<img " still matches.
#
# Two-stage, linear in the length of the body: url_regex_href_attr locates the attribute values and findall_href() accepts a value only if
# the nearest "<" opens a tag which carries that attribute (see URL_HREF_TAG_ATTRS), with no ">" in between. The tag opening is bounded
# by URL_HREF_TAG_WINDOW, as neither a document nor a browser keeps a tag opening longer than that open. One value per tag opening is
# accepted (the first in text order), and attribute keywords are not matched as substrings of longer names: <form formaction="u"> yields
# nothing, as browsers do not treat the formaction attribute of a <form> as a fetch target.
url_regex_href_attr = re.compile(
    r"""
(xlink:href|href|src|formaction|action|data|background)
[\s/]*
=
\s*
((?:[\"][^\"]+)|[\'][^\']+|[^\s>]+)
""",
    flags=re.IGNORECASE | re.VERBOSE,
)

# Tag names which carry each attribute, compared case-insensitively. Any other [a-z:] tag name carries xlink:href only.
URL_HREF_TAG_ATTRS = {
    'href': frozenset(('a', 'area', 'link', 'base')),
    'src': frozenset(('img', 'script', 'iframe', 'frame', 'embed', 'source', 'audio', 'video', 'track', 'input', 'bgsound')),
    'action': frozenset(('form',)),
    'formaction': frozenset(('button', 'input')),
    'data': frozenset(('object',)),
    'background': frozenset(('body',)),
}

# Maximum size of the tag opening (from "<" to the attribute) which findall_href() verifies.
URL_HREF_TAG_WINDOW = 16384

_url_regex_href_tag_name = re.compile(r'[a-z:]+', flags=re.IGNORECASE)
_url_regex_href_ws_or_slash = ' \t\r\n\f\v/'


def findall_href(body: str) -> list:
    """Find the URL values of HTML attributes (href, src, action, formaction, data, background, and xlink:href).

    Args:
        body (str): Text input which should be searched for attribute URLs.

    Returns:
        list: The attribute values (quotes included), in order of appearance.
    """
    found: list = []
    last_end = 0
    for m in url_regex_href_attr.finditer(body):
        start = body.rfind('<', max(last_end, m.start(1) - URL_HREF_TAG_WINDOW), m.start(1))
        if start == -1:
            continue
        segment = body[start : m.start(1)]
        if '>' in segment:
            continue
        tname = _url_regex_href_tag_name.match(segment, 1)
        if tname is None or tname.end() >= len(segment) or segment[tname.end()] not in _url_regex_href_ws_or_slash:
            continue
        name = tname.group()
        attr = m.group(1).lower()
        if attr != 'xlink:href' and name.lower() not in URL_HREF_TAG_ATTRS[attr]:
            continue
        found.append(m.group(2))
        last_end = m.end(2)
    return found


# Characters which browsers remove from URLs, wherever they are (`ht&#9;tp://...` or a scheme broken over two lines is a valid URL).
url_drop_chars_table = str.maketrans('', '', '\t\n\r')

# A (quoted) value starting with a scheme followed by slashes or backslashes, i.e. http:\\\\host\\path
url_backslash_scheme_regex = re.compile(r"""[\"\']?[a-z][a-z0-9+.\-]*:[\\/]{2}""", re.IGNORECASE)

escape_special_regex_chars = re.compile(r"""([\^$\[\]()+?.])""")

window_slice_regex = re.compile(r"""\s""")

# Candidates for an IPv4 address in the notations of inet_aton(): http://3232235777/, 0xC0A80101, 0300.0250.0.1, 127.1 (validated by get_obfuscated_ip())
ipv4_obfuscated_regex = re.compile(r"""[0-9a-fA-FxX.]+""")

# URL whose host is a plain number (decimal or hexadecimal), e.g. http://3232235777/ or http://user@0xC0A80101:8080/
url_numeric_host_regex = re.compile(r"""[a-z][a-z0-9+.\-]*://(?:[^/?#@]*@)?(?:0x[0-9a-f]+|[0-9]+)(?:[:/?#]|$)""", re.IGNORECASE)

# A line which looks like a MIME multipart delimiter (RFC 2046, section 5.1.1), used to guess the boundary of broken multipart messages.
multipart_boundary_guess_regex = re.compile(r"""^--([0-9A-Za-z'()+_,./:=?\-]{1,69}[0-9A-Za-z'()+_,./:=?\-])[ \t]*\r?$""", re.MULTILINE)

# XML namespace declarations (xmlns="...", xmlns:v='...'): identifiers which look like URLs (http://www.w3.org/1999/xhtml) but are never fetched or visited.
xmlns_declaration_regex = re.compile(r"""\bxmlns(?::[\w.\-]{1,100})?\s*=\s*(?:"[^"]{0,2000}"|'[^']{0,2000}')""", flags=re.IGNORECASE)

# method=result pairs of an Authentication-Results header (RFC 8601); the method must not be the property of another one (header.d=, smtp.mailfrom=)
authentication_result_regex = re.compile(r"""(?<![\w.\-])(spf|dkim|dmarc|arc|auth|iprev|dkim-atps)\s*=\s*([a-z]+)""", re.IGNORECASE)

# the result at the start of a Received-SPF header (RFC 7208)
received_spf_regex = re.compile(r"""^\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b""", re.IGNORECASE)

# Remote file shares. UNC paths (`\\host\share\path`, also the WebDAV forms `\\host@SSL\DavWWWRoot\x` and `\\host@8080\x`, and the `\\?\UNC\host\share` prefix)
# as well as `file://host/share` and `smb://host/share` URLs. A client which opens such a path connects to the host and authenticates (leaking the NTLM hash)
# or fetches content from it, which makes them a classic phishing and credential theft primitive. The host is the indicator.
unc_regex = re.compile(
    r"""
    (?:
        (?<![\\\w:.])                              # not part of a longer token or an escaped path such as C:\\Users
        \\{2}(?:\?\\UNC\\)?
        (?P<unc_host>[a-z0-9-]+(?:\.[a-z0-9-]+)*(?:@(?:ssl|\d{1,5}))?)
        \\(?!\\)                                   # exactly one backslash: in escaped text (`\\\\Users\\\\Bob`) the separators are doubled
        [^\s\\/:*?"<>|]+                            # share name
        (?:\\[^\s"'<>|)\]]*)?                       # path
    |
        (?:file://(?!/)|file:////|smb://)            # `file:///C:/x` and `file://localhost/` are local
        (?P<url_host>[a-z0-9-]+(?:\.[a-z0-9-]+)*(?:@(?:ssl|\d{1,5}))?)
        (?:/[^\s"'<>)\]]*)?
    )
    """,
    flags=re.IGNORECASE | re.VERBOSE,
)
