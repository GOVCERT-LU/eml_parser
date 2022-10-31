# Changelog
All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.17.2]
### Fixes
- When serialising RFC822 payloads, use a custom policy which has no limits on line-lenthgs as this breaks badly encoded messages.

## [v1.17.1]
### Fixes
- Fix issue #76 "If a CR or LF is found in a malformed email address header fields (From/To/etc.), the ValueError breaks the parsing." (@malvidin, @cccs-rs)

## [v1.17.0]
### Added
- Add Public Suffix List validation options for URLs and email addresses. (@malvidin)
- Add ip_force_routable option to filter out non-routable IPs. (@malvidin)
- Add domain_force_tld option to filter out domains with invalid TLDs. (@malvidin)
- Add include_www option to include potential URLs without a scheme. (@malvidin)
- Add IP, domain, and Public Suffix List filtering tests. (@malvidin)
- Add www_regex and dom_regex tests. (@malvidin)
- Add optional matching for HTML SRC and HREF. (@malvidin)

### Changes
- Moved URL parsing options to EmlParser from get_uri_ondata. (@malvidin)

### Fixes
- Ensure string_sliding_window_loop includes the last slice of the body. (@malvidin)
- Keep subsequent URLs if URLs are comma separated. (@malvidin)
- Fix linter warnings.
- Add typing dev dependencies.

## [v1.16.0]
### Fixes
- Fix catastrophic backtracking on url regex, add related tests for backtracking, unicode, and IPv6. (thanks @malvidin)
- Add Unicode character ranges for re2. (thanks @malvidin)
- Add tests for url_regex_simple, change where parens are matched in url_regex_simple, specify which re engine needs which expression. (thanks @malvidin)
- Match URLs with trailing ? with url_regex_simple. (thanks @malvidin)

## [v1.15.0]
### Added
- As has been reported in #62 and #63 there can be issues with certain regular expressions (in this case URL regex) where the regex engine just runs forever (commonly referred to "catastrophic backtracking").
In order to make testing two seemingly popular (and with good cross-platform wheel support) alternative regex engines easier, two *extra* flags have been introduced:
  - **regex** - for testing the [regex](https://pypi.org/project/regex/) library
  - **pyre2** - for testing the [pyre2](https://pypi.org/project/pyre2/) library

  **Note-1:** These are temporary extra tags which may be removed in future releases.

  **Note-2:** eml_parser will transparently use regex if it is found, or pyre2 (in that order).

### Changes
- *eml_parser.regex* has been renamed to *eml_parser.regexes* in order not to clash with the *regex* python module.

## [v1.14.8]
### Changes
- Converted the documentation to mkdocs.

### Fixed
- Fixed a bug in FROM header field parsing. In case the *display name* part contained an e-mail address, that one was naively used instead of properly parsing the field.

## [v1.14.7]
### Changes
- Cleanup example scripts.

### Fixed
- Handle extra case of when chardet detects VISCII text which Python is currently unable to decode (thanks @cccs-rs #59).

### Added
- Add multipart boundary marker as discussed in #56, in order to easier distinguish parts.

## [v1.14.6]
### Fixed
- Fixed a major bug which resulted in not all URLs being returned because of a variable which was overwritten instead of being extended.
- Handle URL parsing issue and only emit a warning with the problematic URL but do not break the rest of the parsing.
- Filter out any scheme-only URLs.
- Make sure the URL parsing regex only matches URLs with scheme (as it is supposed to).

### Changes
- Try to detect partial URLs (looking for a scheme) and extend the sliced body window accordingly. This allows for better URL extraction.


## [v1.14.5]
### Fixed
- Prevent routing.parserouting() from throwing an exception on unparsable receive lines (thanks @kinoute #54).

### Changes
- Do not unnecessarily call *eml_parser.decode.robust_string2date* on an empty string.

## [v1.14.4]
### Fixed
- Fix routing.parserouting() to handle domains containing the word 'from' by themselves (thanks @jgru #51).

## [v1.14.3]
### Changed
Adapted the *examples/simple_test.py* to use the eml_parser class instead of the deprecated method.

### Fixed
- When parsing URLs from the body:
    - do not try to replace "hxxp" by "http" as we do not parse "hxxp" anyway (legacy)
    - skip URLs with no "."
    - update the regex for searching for URLs based on https://gist.github.com/gruber/8891611 in order to prevent infinite runs in certain cases (thanks @kevin-dunas)

## [v1.14.2]
### Fixed
Implemented a workaround for an upstream bug (https://bugs.python.org/issue30681) which breaks EML parsing if the source EML contains an unparsable date-time field (thanks @nth-attempt).

## [v1.14.1]
### Fixed
Fixed a bug which prevented correct attachment parsing in certain situations (thanks @ninoseki).

## [v1.14.0]
### Changed
Use simple less time consuming regular expression for searching for IPv4 addresses, in turn use *ipaddress* for both IPv4 and IPv6 address validation which is fast and gives in turn leads to more correct matches.

## [v1.13.0]
### Added
- Simplify the code by using a sliding window body slicing method

### Changed
- Use alternative URL extraction regular-expression
- Fix other regular-expressions (non-required escaping and ^)
  - No longer support parsing h**xx**p(s) style URLs

### Fixed
- In some cases the extracted features (i.e. domain, IP, URL, e-mail) were not correct due to wrongfully cutting through the body. This has been fixed by extending the text slice to a character unrelated to the match pattern.

## [v1.12.0]
### Added
- Added **EmlParser** class in order to simplify inner workings.
- Moved typing annotations inline.

### Changed
- Replaced a couple of regular expression used by simpler string operations for improved parsing speed.
- Renamed (internal) method *give_dom_ip* to *give_dom_ip*.
- Simplify mime-type detection

### Deprecated
- Deprecated Python support for versions <3.7.
- Deprecated the usage of *eml_parser.decode_email* and *eml_parser.decode_email_b*. You should use the class instead.

### Fixed
- Fixed docstrings.
- Removed any broad *Exception* usage.
- Fixed import orders.
- Extra requires option *file-magic* was renamed to *filemagic* -> pip does not seem to work with "-" in the name.