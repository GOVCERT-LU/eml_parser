# pylint: disable=line-too-long

"""This module contains a number of regular expressions used by this Library."""

try:
    import regex as re
except ImportError:
    import re

__author__ = 'Toth Georges, Jung Paul'
__email__ = 'georges@trypill.org, georges.toth@govcert.etat.lu'
__copyright__ = 'Copyright 2013-2014 Georges Toth, Copyright 2013-present GOVCERT Luxembourg'
__license__ = 'AGPL v3+'

# regex compilation
# W3C HTML5 standard recommended regex for e-mail validation
# It also implements the 64 character limit on the local part (RFC 5321, section 2.4), with a safety factor.
# This mitigates an issue with quadratic complexity when searching for e-mail addresses in very long strings.
email_no_force_tld_regex = re.compile(r"""([a-zA-Z0-9.!#$%&'*+\-/=?^_`{|}~]{1,128}@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*)""", re.MULTILINE)
email_force_tld_regex = re.compile(r"""([a-zA-Z0-9.!#$%&'*+\-/=?^_`{|}~]{1,128}@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)""", re.MULTILINE)
email_regex = email_no_force_tld_regex


# regex for detecting RFC2047 encodings - used from https://dmorgan.info/posts/encoded-word-syntax/
email_regex_rfc2047 = re.compile(r"""=\?{1}([\w\S]+)\?{1}([B|Q|b|q])\?{1}([\w\S]+)\?{1}=""")

recv_dom_regex = re.compile(r"""(?:(?:from|by)\s+)([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]{2,})+)""", re.MULTILINE)

dom_regex = re.compile(r"""(?:^|[\s(/<>|@'=])([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]{2,})+)(?=$|[\?\s#&/<>')])""", re.MULTILINE)

# An address must not be part of a longer dotted number or word ("1.2.3.4.5", "v1.2.3.4") nor be the first labels of a host name ("1.2.3.4.nip.io").
# The boundaries are ASCII only on purpose, as text in e.g. CJK scripts is often not separated by whitespace. A sentence ending dot is fine.
ipv4_regex = re.compile(r"""(?<![0-9A-Za-z_.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![0-9A-Za-z_])(?!\.[0-9A-Za-z_])""")

# From https://gist.github.com/mnordhoff/2213179 : IPv6 with zone ID (RFC 6874)
_IPV6_ADDRESS = r"""((?:[0-9a-f]{1,4}:){6}(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9a-f]{1,4}:){5}(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){4}(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9a-f]{1,4}:[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){3}(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9a-f]{1,4}:){,2}[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){2}(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9a-f]{1,4}:){,3}[0-9a-f]{1,4})?::[0-9a-f]{1,4}:(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9a-f]{1,4}:){,4}[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9a-f]{1,4}:){,5}[0-9a-f]{1,4})?::[0-9a-f]{1,4}|(?:(?:[0-9a-f]{1,4}:){,6}[0-9a-f]{1,4})?::)"""

# An address must not directly follow a word character, a dot or a colon (exception: the "IPv6:" tag of address literals) nor be followed by a word character
# or a colon and hex digit, otherwise parts of longer sequences such as "std::vector" or "1:2:3:4:5:6:7:8:9" would be reported.
ipv6_regex = re.compile(r"""(?:(?<![0-9A-Za-z_.:])|(?<=ipv6:))""" + _IPV6_ADDRESS + r"""(?![0-9A-Za-z_])(?!:[0-9a-f])""", flags=re.IGNORECASE)

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
# regex overlaps with url_regex_simple, so simple URL content that starts with "<a " or "<img " still matches.
url_regex_href = re.compile(
    r"""
<(?:(?:a|area|link|base)[\s\/]+[^>]*?href
 |(?:img|script|iframe|frame|embed|source|audio|video|track|input|bgsound)[\s\/]+[^>]*?src
 |form[\s\/]+[^>]*?action
 |(?:button|input)[\s\/]+[^>]*?formaction
 |object[\s\/]+[^>]*?data
 |body[\s\/]+[^>]*?background
 |[a-z:]+[\s\/]+[^>]*?xlink:href)
[\s\/]*=\s*
((?:[\"][^\"]+)|[\'][^\']+|[^\s>]+)
""",
    flags=re.IGNORECASE | re.VERBOSE,
)

# Characters which browsers remove from URLs, wherever they are (`ht&#9;tp://...` or a scheme broken over two lines is a valid URL).
url_drop_chars_table = str.maketrans('', '', '\t\n\r')

# A (quoted) value starting with a scheme followed by slashes or backslashes, i.e. http:\\\\host\\path
url_backslash_scheme_regex = re.compile(r"""[\"\']?[a-z][a-z0-9+.\-]*:[\\/]{2}""", re.IGNORECASE)

date_regex = re.compile(r""";[ \w\s:,+\-()]+$""")
cleanline_regex = re.compile(r"""(^[;\s]{0,}|[;\s]{0,}$)""")

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

# a comment in a header, nested comments are removed from the inside out
header_comment_regex = re.compile(r"""\([^()]*\)""")

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
