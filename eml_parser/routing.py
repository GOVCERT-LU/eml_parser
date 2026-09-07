"""This module is used for parsing the received lines into a machine readable structure."""

import re
import typing

import eml_parser.decode
import eml_parser.regexes


def noparenthesis(line: str) -> str:
    """Remove nested parentheses, until no pairs of matching parentyheses are present.

    Args:
        line (str): Input text to search in for parentheses.

    Returns:
        str: Return a string with all text in matching parentheses removed. For example,
        noparenthesis('a((b)c(d') == 'a(c(d'
    """
    fragments: list[list[str]] = [[]]
    for ch in line:
        if ch == '(':
            fragments.append([ch])
        else:
            fragments[-1].append(ch)
        if ch == ')' and len(fragments) > 1:
            fragments.pop()
    return ''.join(ch for w in fragments for ch in w)


def cleanline(line: str) -> str:
    """Remove space and ; from start/end of line.

    Args:
        line (str): Line to clean.

    Returns:
        str: Cleaned string.
    """
    if line == '':
        return line

    return eml_parser.regexes.cleanline_regex.sub('', line)


def get_domain_ip(line: str) -> list[str]:
    """Method returns all domains, IPv4 and IPv6 addresses found in a given string.

    Args:
        line (str): String to search in.

    Returns:
        list: Unique list of strings with matches
    """
    m = eml_parser.regexes.dom_regex.findall(' ' + line) + eml_parser.regexes.ipv4_regex.findall(line) + eml_parser.regexes.ipv6_regex.findall(line)

    return list(set(m))


def parserouting(line: str) -> dict[str, typing.Any]:
    """This method tries to parse an e-mail header received line and extract machine-readable information.

    Note that there are a large number of formats for these lines
    and a lot of weird ones which are not commonly used.
    We try our best to match a large number of formats.

    Args:
        line (str): Received line to be parsed.

    Returns:
        dict: Returns a dict with the extracted information.
    """
    #    if re.findall(reg_date, line):
    #        return 'date\n'
    # Preprocess the line to simplify from/by/with/for border detection.
    out = {}  # type: typing.Dict[str, typing.Any]  # Result
    out['src'] = line
    line = line.lower()  # Convert everything to lowercase
    npline = line.replace(')', ' ) ')  # normalise space # Re-space () ")by " exists often
    npline = npline.replace('(', ' ( ')  # normalise space # Re-space ()
    npline = npline.replace(';', ' ; ')  # normalise space # Re-space ;
    npline = noparenthesis(npline)  # Remove any "()"
    npline = ' '.join(npline.split())  # normalise space
    npline = npline.strip('\n')  # Remove any new-line
    raw_find_data = eml_parser.regexes.date_regex.findall(npline)  # extract date on end line.

    # Detect "sticked lines"
    if ' received: ' in npline:
        out['warning'] = ['Merged Received headers']
        return out

    if raw_find_data:
        npdate = raw_find_data[0]  # Remove spaces and starting ;
        npdate = npdate.lstrip(';')  # Remove Spaces and stating ; from date
        npdate = npdate.strip()
    else:
        npdate = ''

    npline = npline.replace(npdate, '')  # Remove date from input line
    npline = npline.strip(' ')  # Remove any border WhiteSpace

    borders = ['from ', 'by ', 'with ', 'for ']

    # Scan the line to determine the order, and presence of each "from/by/with/for" words
    raw_matches: list[tuple[int, str]] = []
    for word in borders:
        pos = npline.find(word)
        if pos != -1:
            raw_matches.append((pos, word))

    if not raw_matches:
        out['warning'] = ['Nothing Parsable']
        return out

    # Sort keywords sequentially by their appearance order in the header
    tout = sorted(raw_matches, key=lambda match: match[0])

    reg = ''
    for i, item in enumerate(tout):
        field = item[1].strip()
        kw = item[1]

        # Capture lazily until the next keyword
        reg += kw + r'(?P<' + field + r'>.*?)'

        if i + 1 >= len(tout):
            # Last field captures lazily until a date separator ';' or end of string
            reg += '(?:;|$)'

    reparse = re.compile(reg)
    reparseg = reparse.search(line)

    # Fill the data
    if reparseg is not None:
        for item in borders:  # type: ignore
            try:
                out[item.strip()] = cleanline(reparseg.group(item.strip()))  # type: ignore
            except (LookupError, ValueError, AttributeError):
                pass

    if npdate:
        out['date'] = eml_parser.decode.robust_string2date(npdate)

    # Fixup for "From" in "for" field
    # ie google, do that...
    if out.get('for'):
        # include spaces in test, otherwise there will be an exception with domains containing "from" in itself
        if ' from ' in out.get('for', ''):
            temp = re.split(' from ', out['for'])
            out['for'] = temp[0]
            out['from'] = f"""{out['from']} {' '.join(temp[1:])}"""

        m = eml_parser.regexes.email_regex.findall(out['for'])
        if m:
            out['for'] = list(set(m))
        else:
            del out['for']

    # Now.. find IP and Host in from
    if out.get('from'):
        out['from'] = get_domain_ip(out['from'])
        if not out.get('from', []):  # if array is empty remove
            del out['from']

    # Now.. find IP and Host in from
    if out.get('by'):
        out['by'] = get_domain_ip(out['by'])
        if not out.get('by', []):  # If array is empty remove
            del out['by']

    return out
