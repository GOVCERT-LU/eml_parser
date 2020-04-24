# Changelog
All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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