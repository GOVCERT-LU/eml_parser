# -*- coding: utf-8 -*-
# pylint: disable=line-too-long

"""This module contains a number of regular expressions used by this Library.
"""

import re

__author__ = 'Toth Georges, Jung Paul'
__email__ = 'georges@trypill.org, georges.toth@govcert.etat.lu'
__copyright__ = 'Copyright 2013-2014 Georges Toth, Copyright 2013-present GOVCERT Luxembourg'
__license__ = 'AGPL v3+'


# regex compilation
# W3C HTML5 standard recommended regex for e-mail validation
email_regex = re.compile(r'''([a-zA-Z0-9.!#$%&'*+-/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*)''', re.MULTILINE)
email_force_tld_regex = re.compile(r'''([a-zA-Z0-9.!#$%&'*+-/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)''', re.MULTILINE)
parsing_email_force_tld = False    # control flag used to determine if the user requested a stricter e-mail parsing (incl. TLD)

recv_dom_regex = re.compile(r'''(?:(?:from|by)\s+)([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]{2,})+)''', re.MULTILINE)

dom_regex = re.compile(r'''(?:\s|[(/<>|@'=])([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]{2,})+)(?:$|\?|\s|#|&|[/<>')])''', re.MULTILINE)
ipv4_regex = re.compile(r'''((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))''', re.MULTILINE)


# From https://gist.github.com/mnordhoff/2213179 : IPv6 with zone ID (RFC 6874)
ipv6_regex = re.compile(r'''((?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)''')

# simple version for searching for URLs
# character set based on http://tools.ietf.org/html/rfc3986
# url_regex_simple = re.compile(r'''(?i)\b((?:(hxxps?|https?|ftps?)://)[^ ]+)''', re.VERBOSE | re.MULTILINE)
url_regex_simple = re.compile(r'''(([a-z]{3,}s?://)[a-z0-9\-_:]+(\.[a-z0-9\-_]+)*''' +
                              r'''(/[a-z0-9_\-.~!*'();:@&=+$,/  ?%#\[\]]*)?)''',
                              re.VERBOSE | re.MULTILINE | re.I)

priv_ip_regex = re.compile(r'''^(((10(\.\d{1,3}){3})|(192\.168(\.\d{1,3}){2})|(172\.(([1][6-9])|([2]\d)|([3][0-1]))(\.\d{1,3}){2}))|(127(\.\d{1,3}){3})|(::1))''')

date_regex = re.compile(r''';[ \w\s:,+\-()]+$''')
noparenthesis_regex = re.compile(r'''\([^()]*\)''')
cleanline_regex = re.compile(r'''(^[;\s]{0,}|[;\s]{0,}$)''')

escape_special_regex_chars = re.compile(r'''([\^$\[\]()+?.])''')
