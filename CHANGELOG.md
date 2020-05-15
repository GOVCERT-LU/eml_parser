# Changelog
All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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