# Changelog
All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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