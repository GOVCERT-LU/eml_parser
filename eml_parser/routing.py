"""This module is used for parsing the received lines into a machine readable structure."""

import datetime as dt
import typing

import regex

import eml_parser.decode
import eml_parser.regexes

# What cleanline() removes: the semicolon and everything the regular expression class \s matches (all Unicode white space).
_CLEANLINE_CHARS = ';' + ''.join(char for char in map(chr, range(0x3001)) if char.isspace())

_DELIMITERS = str.maketrans('()[],;<>"', '         ')

# The domain of an address in angle brackets (the sender in "(envelope-from <a@b>)", a message id) is no relay.
_ANGLE_ADDRESS = regex.compile(r"""<[^<>\s]*@[^<>\s]*>""")

# What a date can consist of: words, numbers, and the separators of its time and zone. Anything else is not a date, e.g. "-04= 00".
_DATE = regex.compile(r"""[\w\s:,+.\-]+""")

# A host name in a received line: labels of letters, digits, hyphens and underscores (Exchange and Lotus servers use them: `mail_gw1.example.com`),
# any label may be a single character (`mail10.m.example.net`). The last label (TLD) consists of letters only, or is punycode (`xn--p1ai`): ids
# (`1.b9.b1afe75`), versions (`v82.22`, `8.12.0.beta16`) and the like are no hosts. A name followed by `/<digit>` is a mailer version
# (`8.12.0.beta16/8.12.0`). The labels are matched possessively (a label only if another one follows, labels do not start with a hyphen): the last label can only be the TLD, and
# backtracking would make the scan quadratic on long runs of `a.a.a.`. An optional `*.` is dropped, the domain of user@host is a host, user.name@host is not.
_HOST = regex.compile(rf"""(?<![\w.\-/])(?:\*\.)?({eml_parser.regexes.RECEIVED_HOST_LABELS}{eml_parser.regexes.RECEIVED_HOST_TLD})(?![\w\-@]|\.\w|/\d)""")

# The tokens which matter for the structure of a received line. Parentheses delimit comments, which are skipped when looking for the keywords.
# A keyword is a whole word, i.e. it is not part of a host name or an address (toby, before, nearby, ...).
_STRUCTURE = regex.compile(r"""[()]|;|(?<![^\s);\[])(?:from|by|with|for)(?=[\s(]|$)|(?<=\s)received:(?=\s)""")


def cleanline(line: str) -> str:
    """Remove space and ; from start/end of line.

    Args:
        line (str): Line to clean.

    Returns:
        str: Cleaned string.
    """
    return line.strip(_CLEANLINE_CHARS)


def get_domain_ip(line: str) -> list[str]:
    """Method returns all domains, IPv4 and IPv6 addresses found in a given string.

    Args:
        line (str): String to search in.

    Returns:
        list: Unique list of strings with matches, in order of first appearance (domains, then IPv4, then IPv6 addresses).
    """
    found: list[str] = []

    # Brackets and parentheses delimit a host as well as white space does: "by notes.example.com(Lotus SMTP MTA)", "by [mail.example.com]"
    line = line.translate(_DELIMITERS)

    if '.' in line:
        found += _HOST.findall(line)
        found += eml_parser.regexes.ipv4_regex.findall(line)

    if ':' in line:
        found += eml_parser.regexes.ipv6_regex.findall(line)

    return list(dict.fromkeys(found))


def _remove_comments(line: str, comments: list[tuple[int, int]], start: int) -> str:
    """Cut the comments out of the end of a line and normalise the white space.

    Args:
        line: The line.
        comments: Start and end of the comments in the line (nested ones too, as an enclosing parenthesis might never be closed).
        start: Position in the line to start at.

    Returns:
        str: The text from start to the end of the line, without comments.
    """
    parts = []
    for comment_start, comment_end in sorted(comments):
        if comment_end > start:
            parts.append(line[start : max(start, comment_start)])
            start = max(start, comment_end)

    parts.append(line[start:])

    return ' '.join(' '.join(parts).split())


def _parse_date(line: str, comments: list[tuple[int, int]], separators: list[int]) -> dt.datetime | None:
    """Parse the date behind the last semicolon of a received line.

    Args:
        line: The line.
        comments: Start and end of the comments in the line.
        separators: Positions of the semicolons outside of comments.

    Returns:
        The date, or None if there is none. An unparsable date is not reported (robust_string2date() would make up a default date), nor is
        one which is not made of date characters, as dateutil ignores whatever it does not know and returns a wrong time.
    """
    if not separators:
        return None

    # A line wrapped in brackets ends with one
    date = _remove_comments(line, comments, separators[-1] + 1).removesuffix(']').rstrip()
    if not _DATE.fullmatch(date) or not any(char.isdigit() for char in date):
        return None

    parsed_date = eml_parser.decode.robust_string2date(date)
    return None if parsed_date.isoformat() == eml_parser.decode.default_date else parsed_date


def parserouting(line: str, email_regex: regex.Pattern[str] = eml_parser.regexes.email_no_force_tld_regex) -> dict[str, typing.Any]:
    """This method tries to parse an e-mail header received line and extract machine-readable information.

    Note that there are a large number of formats for these lines
    and a lot of weird ones which are not commonly used.
    We try our best to match a large number of formats.

    The line is split in one pass. The first *from*, *by*, *with* and *for* outside of comments (parentheses) start a section, which ends where
    the next one starts. The last section ends at the semicolon in front of the date. The text of a section, comments included, is the value
    of *with*, and is searched for hosts and addresses for *from*, *by* and *for*.

    Args:
        line (str): Received line to be parsed.
        email_regex (regex.Pattern[str], optional): Pattern used to extract e-mail addresses from the 'for' field.

    Returns:
        dict: Returns a dict with the extracted information.
    """
    out: dict[str, typing.Any] = {'src': line}
    line = line.lower()

    # Collect the structural tokens outside of comments. A closing parenthesis removes everything since its opening one; an unbalanced
    # opening parenthesis does not start a comment.
    open_comments: list[tuple[int, int]] = []
    comments: list[tuple[int, int]] = []
    tokens: list[tuple[str, int, int]] = []
    for match in _STRUCTURE.finditer(line):
        kind = match.group()

        if kind == '(':
            open_comments.append((len(tokens), match.start()))
        elif kind == ')':
            if open_comments:
                mark, start = open_comments.pop()
                del tokens[mark:]
                comments.append((start, match.end()))
        else:
            tokens.append((kind, match.start(), match.end()))

    # The first occurrence of each keyword starts a section, later ones are part of the text. The last semicolon is the one in front of the date.
    sections: dict[str, tuple[int, int]] = {}
    separators: list[int] = []
    for kind, start, end in tokens:
        if kind == ';':
            separators.append(start)
        elif kind == 'received:':
            # Detect "sticked lines"
            out['warning'] = ['Merged Received headers']
            return out
        elif kind not in sections:
            sections[kind] = (start, end)

    if not sections:
        # Lines such as "(qmail 4711 invoked by uid 500); 28 Sep 2002 16:21:17 -0000" have a date but no relay.
        out['warning'] = ['Nothing Parsable']
        date = _parse_date(line, comments, separators)
        if date is not None:
            out['date'] = date
        return out

    ordered = sorted((start, end, keyword) for keyword, (start, end) in sections.items())
    for position, (_, end, keyword) in enumerate(ordered):
        if position + 1 < len(ordered):
            stop = ordered[position + 1][0]
        else:
            # The last section ends at the first semicolon after it.
            stop = next((start for start in separators if start > end), len(line))

        value = cleanline(line[end:stop])
        if value:
            out[keyword] = value

    date = _parse_date(line, comments, separators)
    if date is not None:
        out['date'] = date

    # Fixup for "From" in "for" field
    # ie google, do that...
    if out.get('for'):
        # include spaces in test, otherwise there will be an exception with domains containing "from" in itself
        if ' from ' in out['for']:
            before, _, after = out['for'].partition(' from ')
            out['for'] = before
            out['from'] = f'{out.get("from", "")} {after}'

        found = email_regex.findall(out['for'])
        if found:
            out['for'] = list(dict.fromkeys(found))
        else:
            del out['for']

    # Now.. find IP and Host in from and by. The domain of an address in angle brackets, e.g. the one of the sender in
    # "(envelope-from <a@sender.example>)" or of a message id, is no relay.
    for keyword in ('from', 'by'):
        if out.get(keyword):
            text = _ANGLE_ADDRESS.sub(' ', out[keyword]) if '<' in out[keyword] else out[keyword]
            out[keyword] = get_domain_ip(text)
            if not out[keyword]:  # if array is empty remove
                del out[keyword]

    return out
