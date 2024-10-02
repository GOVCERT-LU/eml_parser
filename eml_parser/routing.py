"""This module is used for parsing the received lines into a machine readable structure."""

import re
import typing

import eml_parser.decode
import eml_parser.regexes


def noparenthesis(line: str) -> str:
    """Remove nested parenthesis, until none are present.

    @FIXME rewrite this function.

    Args:
        line (str): Input text to search in for parenthesis.

    Returns:
        str: Return a string with all parenthesis removed.
    """
    # check empty string
    if not line:
        return line

    line_ = line

    while True:
        lline = line_
        line_ = eml_parser.regexes.noparenthesis_regex.sub('', line_)
        if lline == line_:
            break

    return line_


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
    """This method tries to parsed a e-mail header received line and extract machine readable information.

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
    result: list[dict[str, typing.Any]] = []

    # Scan the line to determine the order, and presence of each "from/by/with/for" words
    for word in borders:
        candidate = list(borders)
        candidate.remove(word)
        for endword in candidate:
            if word in npline:
                loc = npline.find(word)
                end = npline.find(endword)
                if end < loc or end == -1:
                    end = 0xFFFFFFF  # Kindof MAX 31 bits
                result.append({'name_in': word, 'pos': loc, 'name_out': endword, 'weight': end + loc})
                # print({'name_in': word, 'pos': loc, 'name_out': endword, 'weight': end+loc})

    # Create the word list... "from/by/with/for" by sorting the list.
    if not result:
        out['warning'] = ['Nothing Parsable']
        return out

    tout = []
    for word in borders:
        result_max = 0xFFFFFFFF
        line_max: dict[str, typing.Any] = {}
        for eline in result:
            if eline['name_in'] == word and eline['weight'] <= result_max:
                result_max = eline['weight']
                line_max = eline

        if line_max:
            tout.append([line_max.get('pos'), line_max.get('name_in')])

    # structure is list[list[int, str]]
    # we sort based on the first element of the sub list, i.e. int
    tout = sorted(tout, key=lambda x: typing.cast(int, x[0]))

    # build regex.
    reg = ''
    for item in tout:
        reg += item[1] + '(?P<' + item[1].strip() + '>.*)'  # type: ignore
    if npdate:
        # escape special regex chars
        reg += eml_parser.regexes.escape_special_regex_chars.sub(r"""\\\1""", npdate)

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
