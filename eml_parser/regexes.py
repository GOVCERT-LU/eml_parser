# -*- coding: utf-8 -*-
# pylint: disable=line-too-long

"""This module contains a number of regular expressions used by this Library."""

try:
    import regex as re
except ImportError:
    try:
        import re2 as re
    except ImportError:
        import re

__author__ = 'Toth Georges, Jung Paul'
__email__ = 'georges@trypill.org, georges.toth@govcert.etat.lu'
__copyright__ = 'Copyright 2013-2014 Georges Toth, Copyright 2013-present GOVCERT Luxembourg'
__license__ = 'AGPL v3+'

# regex compilation
# W3C HTML5 standard recommended regex for e-mail validation
email_regex = re.compile(r'''([a-zA-Z0-9.!#$%&'*+-/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*)''', re.MULTILINE)
email_force_tld_regex = re.compile(r'''([a-zA-Z0-9.!#$%&'*+-/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)''', re.MULTILINE)

recv_dom_regex = re.compile(r'''(?:(?:from|by)\s+)([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]{2,})+)''', re.MULTILINE)

dom_regex = re.compile(r'''(?:\s|[(/<>|@'=])([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]{2,})+)(?:$|\?|\s|#|&|[/<>')])''', re.MULTILINE)

ipv4_regex = re.compile(r'''(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})''')

# From https://gist.github.com/mnordhoff/2213179 : IPv6 with zone ID (RFC 6874)
ipv6_regex = re.compile(r'''((?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)''')

# simple version for searching for URLs
# character set based on http://tools.ietf.org/html/rfc3986
# url_regex_simple = re.compile(r'''(?:(?:https?|ftps?)://)(?:\S+(?::\S*)?@)?(?:(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,})))(?::\d{2,5})?(?:/[^\s]*)?''')
# regex updated from https://gist.github.com/gruber/8891611 but modified with:
#   - do not use a fixed list of TLDs but rather \w
#   - only check for URLs with scheme
#   - modify the end marker to allow any acceptable char according to the RFC3986

if re.__name__ == 're2':
    url_regex_simple = re.compile(r'''
    \b
    (?:https?|ftps?):
    (?:/{1,3}|[a-z0-9%])
    (?:
      \[[0-9a-f:.]{2,40}(?:%[^\x00-\x20\s\]]{1,100})?\]
    |
      [^\x00-\x20\s`()<>{}\[\]\/'"«»“”‘’]+
    )
    (?:[\w\-._~%!$&'()*+,;=:/?#\[\]@\x{00001000}-\x{0010FFFF}]*[^\x00-\x20\s`!\[\]{};:'".,<>«»“”‘’])?
    ''', flags=re.IGNORECASE | re.VERBOSE)
else:
    url_regex_simple = re.compile(r'''
    \b
    (?:https?|ftps?):
    (?:/{1,3}|[a-z0-9%])
    (?:
      \[[0-9a-f:.]{2,40}(?:%[^\x00-\x20\s\]]{1,100})?\]
    |
      [^\x00-\x20\s`()<>{}\[\]\/'"«»“”‘’]+
    )
    (?:[\w\-._~%!$&'()*+,;=:/?#\[\]@\U00001000-\U0010FFFF]*[^\x00-\x20\s`!\[\]{};:'".,<>«»“”‘’])?
    ''', flags=re.IGNORECASE | re.VERBOSE)

date_regex = re.compile(r''';[ \w\s:,+\-()]+$''')
noparenthesis_regex = re.compile(r'''\([^()]*\)''')
cleanline_regex = re.compile(r'''(^[;\s]{0,}|[;\s]{0,}$)''')

escape_special_regex_chars = re.compile(r'''([\^$\[\]()+?.])''')

window_slice_regex = re.compile(r'''\s''')
