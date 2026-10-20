# Changelog
All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v4.3.0]
### Fixes
- Fix the collection of all header fields being quadratic in the number of fields (MSL-2026-030, reported by YUN GU (DrNbnonono)): `Message.get_all()` was called once per header name and scans every field each time, so a compliant 1 MiB message of 21 000 small fields took 44 s to parse, against 11 ms for the same 1 MiB in one field. The fields are grouped by name in one pass now (21 000 fields: 1.2 s). The output is unchanged.
### Changes
- Limit the structured parsing of header fields per message as defence in depth: structured parsing costs up to about 0.6 ms per address or `Received` field, so a message of many small fields kept a worker busy in proportion to its size even with linear parsing. At most `constants.MAX_PARSED_HEADER_FIELDS` (10 000) fields and `constants.MAX_PARSED_HEADER_BYTES` (2 MiB) of values, counted over the message and all its MIME parts, are parsed. The values beyond are kept raw in the output, like values longer than `constants.MAX_PARSED_HEADER_SIZE`, and the message reports a `HeaderParsingLimitDefect` in `header.defect`. The first occurrence of the sender, recipient, subject, date, message id and `Content-*` fields of the message and of each part (`constants.ALWAYS_PARSED_HEADERS`) is always parsed, so junk fields in front of them cannot hide them. Real messages have a few dozen to a few hundred fields; 40 000 `Cc` fields took 30 s and take 7.7 s now.
### Tests
- Add performance scaling tests (`tests/test_performance_scaling.py`) which fail if the parsing cost grows faster than linearly with the number of header fields, body indicators, MIME parts, attachments or nesting levels, by counting function calls (deterministic) and measuring CPU time. They are marked `slow` and only run with `pytest --run-slow` (option added in `tests/conftest.py`).

## [v4.2.1]
### Fixes
- Fix `regexes.email_regex_rfc2047` having a super-linear run time: a header value consisting of `=?` repeated 20 KB took 77 s to scan, which allowed a crafted header to stall the parser. The pattern is linear now. It also no longer accepts `|` as the encoding of an encoded word (`[B|Q|b|q]`).
- Fix the order of `received_email`, `received_domain`, `received_ip` and `received_foremail` being random between runs (depending on `PYTHONHASHSEED`) as they were built from a `set`, and the same for the addresses returned by `decode.workaround_bug_27257()`. They are returned in order of first appearance now.
- Fix the header cache in `CustomPolicy` suppressing log warnings: the warnings about an unfixable `Message-ID` or an unparseable `Date` were emitted inside the cached method, so they were only logged once per unique header value and silent for every later message. The warnings are logged on every access now, and the `Date` warning reports the parse error instead of a traceback.
### Changes
- Cache the result of the header parsing in `CustomPolicy`: the `email` module parses a header again on every access (`get()`, `get_all()`, `items()`), and about two thirds of all parses were repeats. The cache is bounded to 1024 entries.
- Only run the IPv6 pattern (`regexes.findall_ipv6()`) on text containing `::` or at least six colons, as no address can exist without. Together with the header cache, parsing is about twice as fast (800 mails, 6.7 s against 3.1 s, same output).
- Remove code that did nothing or was needlessly long: the `re` fallback in `regexes` (the `regex` module is a hard dependency), the `re.MULTILINE` flag of patterns without anchors, the redundant lookups of the `Date` header, ordered sets built with `Counter` and loops that only fill a list (the hashes of the IOCs, the lists of attachments and bodies). The output is unchanged.

## [v4.2.0]
### Fixes
- Fix `decode.robust_string2date()` replacing the UTC offset of dates parsed by dateutil with UTC: dateutil returns an offset without a name (`tzname()` is `None`) and every such date was treated as a date without time zone, so `Mon, 5 Oct 2026 09:12:44.123 +0200` (fractional seconds, which the `email` module does not parse) was reported two hours off. Only dates without an offset are set to UTC now.
- Fix `routing.parserouting()` mistaking host names ending in a keyword for `by`, `for`, `with` or `from` (`from toby (toby.example.com [192.0.2.1]) by mx.example.org` lost the `from` section, and the IP of the sending host was reported as `by`) and keywords inside comments (`(Postfix, from userid 1000)`, `(using TLS by default)`) starting a section. The keywords are found in one pass over the line, as whole words outside of parentheses.
- Fix `routing.parserouting()` and `routing.get_domain_ip()` reporting version numbers (`Exim 4.96`, `v82.22`, `8.12.0.beta16/8.12.0`), message ids (`86256895.00832fb3`, `1.b9.b1afe75`), the domains of addresses in angle brackets (`(envelope-from <s@sender.example>)`) and the local part of addresses (`user.name@host`) as hosts. The last label of a host name must consist of letters (or be punycode), and a host name is no longer lost when it is followed by a comma or a comment (`by mx.example(Lotus SMTP)`), is in square brackets, contains an underscore (`mail_gw1.example.com`, used by Exchange and Lotus servers) or has a single character label (`mail10.m.example.net`). A received line wrapped in `[...]` is parsed.
- Fix `routing.parserouting()` and `routing.cleanline()` being quadratic for runs of semicolons or white space (a line with 40 000 semicolons took six seconds).
- Fix `routing.parserouting()` not reporting the `date` of lines with fractional seconds (`07:24:22.501 +0000`), AM/PM, a comment with an unclosed parenthesis in front of it, a line wrapped in `[...]` or other characters the old date pattern did not know (and no longer accepting garbage such as `-04= 00` that dateutil turned into a wrong date), and reporting empty strings for empty `from`, `by`, `with` and `for` sections (they are omitted now). Lines without any relay but with a date (`(qmail 4711 invoked by uid 500); 28 Sep 2002 16:21:17 -0000`) keep the `Nothing Parsable` warning and now also have their `date`.
- The lists of `routing.get_domain_ip()` and of `for` are in order of first appearance and no longer depend on `PYTHONHASHSEED`.
### Changes
- Rewrite `routing.parserouting()`: instead of several passes over the line (lower case, space normalisation, comment removal, date pattern, dynamic pattern per line) it finds the structure in one pass with one regular expression and takes the sections from the original line. It is about twice as fast (about 35 µs against 58 µs per line on real received lines). Removed the unused `regexes.cleanline_regex` and `regexes.date_regex`.

## [v4.1.0]
### Fixes
- Fix `decode.decode_string()` returning the literal string `'None'` whenever `charset_normalizer` could not detect an encoding (`str(None)`). This made the intended fallback unreachable and silently discarded the content, including any IOCs in it. The fallback is now UTF-8 followed by latin-1, which cannot fail and therefore always preserves the ASCII parts of the input.
- Fix the `ignore_bad_start` option, which could never work as intended: the check for a header in the first line compared bytes to a list and was always true, and the rebuilt data had all line feeds removed, so for LF-only files the headers and the body were merged into one line (and the body hash of valid messages changed). The garbage in front of the first header field is now skipped by slicing the original data, which also removes the documented performance penalty of this option.
- Fix `decode.export_to_json()` raising `TypeError` for results created with `include_attachment_data=True`, as `decode.json_serial()` could not serialize the `bytes` attachment data. It is now exported as (base64) text.
- Fix `decode.json_serial()` raising `OverflowError` for timezone aware dates close to `datetime.min`/`datetime.max` (e.g. `Date: Fri, 31 Dec 9999 23:59:59 -0500`) when converting them to UTC, which allowed a crafted `Date` header to break `export_to_json()`. Such dates are now exported with their original offset.
- Fix `decode.rfc2047_decode()` raising `LookupError` for RFC2047 encoded words with an unknown charset (e.g. `=?foo-bar?q?x?=`), which allowed a crafted header to abort the parsing of the whole message. The charset is now detected instead.
- Fix the order of the parsed headers (`header['header']`) being random between runs (depending on `PYTHONHASHSEED`) as it was built from a `set`. Headers are now returned in the order of their first occurrence in the message. Additionally, headers whose names only differ in case (e.g. `X-Foo` and `x-foo`) no longer have their values duplicated.
- Fix all attachments without a file name being named `part-000`. The counter used by `traverse_multipart()` was passed by value and thus never advanced between parts. It is now shared by the whole traversal, so unnamed attachments are numbered `part-000`, `part-001`, ... (every attachment consumes a number). As a consequence the `counter` argument of `traverse_multipart()` and `prepare_multipart_part_attachment()` is now an iterator instead of an `int`.
- Security: Stop using `uuid.uuid1()` for the internal body and attachment ids, as version 1 UUIDs embed the MAC address of the host and a timestamp and so leak information about the machine running the parser. Random version 4 UUIDs are used instead.
- `EmlParser` no longer rebinds `eml_parser.regexes.email_regex` at construction time; the e-mail regex is per-instance state passed to `CustomPolicy`, `parserouting()` and `workaround_bug_27257()`, so parsers with different `email_force_tld` settings can coexist (also across threads).
- Fix URLs without scheme (e.g. `www.example.com/path`) being completely missing from the result in the default (hashed) mode. They are now reported as `uri_noscheme_hash` (SHA-256 of the lower-cased value, like `uri_hash`). With `include_raw_body=True` they were already reported as `uri_noscheme`.
- Fix `decode.robust_string2date()` filling in the missing parts of incomplete dates (e.g. `March 2024`, `Tue, 5 Mar` or `12:30`) from the current date, which made the result depend on the day of the analysis. Missing parts are now taken from `1970-01-01`.
- Fix the reported `defect` list consisting of empty strings (`str()` of most stdlib defects is empty). The name of the defect class, e.g. `NoBoundaryInMultipartDefect`, is reported now, followed by the message if there is one.
- Fix body text (and header fragments) being decoded with `errors='ignore'`, which dropped undecodable bytes and glued the neighbouring characters together, creating indicators which are not in the message (`http://good\xff.evil.com` became `http://good.evil.com`). Undecodable bytes in the body are now replaced with a space, so they separate indicators instead of joining them or becoming part of them. An unknown charset falls back to charset detection instead of dropping all non-ASCII characters (new `decode.decode_body()`).
- Fix the URL lists of the body being non-deterministic or full of duplicates: `uri` and `uri_noscheme` were built from a `set` (order depending on `PYTHONHASHSEED`, which also made the derived `domain` and `ip` lists random) and `uri_hash` held one entry per occurrence of a URL. All are now unique and in order of first appearance.
- Fix `string_sliding_window_loop()` cutting tokens in half and losing parts of large bodies (the rewind logic could move the end of a slice behind its start, so text was skipped and URLs, domains and addresses at slice borders were missed or truncated). Slices now end at the next whitespace and cover the body completely. The unused look-around heuristics are removed, which also makes parsing of large bodies faster.
- Detect the encoding of a body if decoding it with the declared charset loses bytes (declared charsets are often wrong, e.g. `us-ascii` for UTF-8 text), so non-ASCII indicators are not replaced by U+FFFD. Bodies larger than `decode.MAX_CHARSET_DETECTION_SIZE` are exempt to keep parsing fast.
- Fix false positive indicators: IPv4 and IPv6 addresses are no longer extracted from inside longer dotted numbers, words or host names (`1.2.3.4.5`, `v1.2.3.4`, `1.2.3.4.nip.io`, `std::vector`, `1:2:3:4:5:6:7:8:9`), names with a numeric top level domain (`999.1.1.1`, `v1.20.30`) are no longer accepted as hosts, and file names (`invoice.pdf`, see the new `eml_parser.constants.FILE_EXTENSIONS`) are not reported as domains, unless the extension is a top level domain according to the public suffix list (e.g. `evil.zip`).
- Fix multipart messages with a missing, wrong or not found boundary yielding no body and no attachment at all, hiding all URLs, e-mail addresses and attachments in them. Such parts are now split using the first line looking like a delimiter, nested ones too, and a part without any delimiter is scanned as text (`EmlParser.repair_multipart()`). The defects are still reported.
- Fix indicators in attachments which carry links being missed: only inline text and `.htm`/`.html` attachments were scanned like the text of the e-mail. Now attachments with a content type (`image/svg+xml`, `application/javascript`, ...) or extension (`.txt`, `.url`, `.svg`, `.js`, `.vbs`, `.ps1`, `.hta`, `.bat`, `.ics`, `.eml`, ...; see `eml_parser.constants`) of scripts, shortcuts, web pages, SVG and invitations are scanned, up to `MAX_TEXT_ATTACHMENT_SIZE` (10 MiB). Data attachments (XML, JSON, CSV, logs) are not scanned as they mostly consist of namespace and schema URLs. Scanned attachments also remain in the attachment list.
- Fix XML namespace declarations (`xmlns="http://www.w3.org/TR/REC-html40"`, as in every Outlook HTML mail or SVG) being reported as URLs and domains. They are skipped when scanning bodies; the raw body is unchanged.
- Fix file names in the path of a URL (`http://host/dl/payload.docx`) being reported as domains.
- Fix `parse_email()` raising `UnicodeEncodeError` for `message/rfc822` attachments whose text the generator cannot encode (the size of the attachment is now calculated from a lossy rendering instead).
- Fix the multipart repair (`EmlParser.repair_multipart()`) looping forever if the stdlib decodes the guessed boundary (e.g. an encoded word like `=?x?q?=ff?=b`), and raising `RecursionError` for thousands of nested multiparts. Such parts are now scanned as text.
- Fix `parse_authentication_results()` being quadratic for a header with deeply nested comments (it now uses `decode.noparenthesis()`, which works in one pass).
- Fix hostile headers raising `TypeError` (RFC 2047 words in the relaxed header parsing path) or `ValueError` (address parts with CR/LF) in `parse_email()` and `headeremail2list()`, and `decode.robust_string2date()` raising `decimal.InvalidOperation` for absurd numbers in a date.
- Fix headers with huge values taking minutes to parse: the structured header parsers of the stdlib are quadratic in the length of a value (a Content-Type with 400 KB of parameters took a minute). Values longer than `constants.MAX_PARSED_HEADER_SIZE` (8 KiB) are not run through them; addresses are still extracted, other values are kept as text and an overlong `Date` is the default date.
- Fix the scan for URLs in HTML attributes (with `include_href`) being quadratic on bodies with a long tag opening without `>` (1.4 MB of `<form ` took 87 s): the old pattern restarted a lazy scan at every `<tag` position. The scan is now two-stage and linear: it locates the attribute values (`regexes.url_regex_href_attr`) and verifies that the nearest tag opening (up to `regexes.URL_HREF_TAG_WINDOW` characters) carries the attribute (`regexes.findall_href()`). Three minor behaviour differences vs. the old pattern are documented in `eml_parser.regexes.py`.
### Changes
- Move `routing.noparenthesis()` to `decode.noparenthesis()`, as it is no longer specific to the received lines, and add the optional `replacement` argument (inserted in place of every removed pair).
- Cache the validation of host names and IP addresses per `EmlParser` instance (bounded LRU), as bodies contain the same hosts over and over. `domain_force_tld` and `ip_force_routable` must therefore not be changed after construction.
### Added
- Report URLs whose host is an IPv4 address in an obfuscated notation (`http://3232235777/`, `http://0xC0A80101/`, `http://0xC0.0xA8.1.1/`, `http://127.1/`), which browsers resolve like normal addresses and which are a common phishing/filter evasion trick; their address is added to the observed IPs (honouring `ip_force_routable` and `whiteip`). New `EmlParser.get_obfuscated_ip()`, based on `socket.inet_aton()`.
- Extract URLs from more HTML attributes: `form action`, `button`/`input` `formaction`, `iframe`/`frame`/`script`/`embed`/`source`/`audio`/`video`/`track`/`input` `src`, `area`/`link`/`base` `href`, `object data`, `body background`, `xlink:href`. These are the usual targets of phishing forms, hidden frames, remote scripts and redirects. Attribute values are normalised like a browser does before use (`decode.normalize_attribute_url()`: character references, tabs and line breaks inside the scheme, backslashes), protocol-relative URLs (`//host/path`) are reported and relative references (`images/logo.png`, `page.html`) are no longer mistaken for hosts.
- Add `anomaly` to attachments which disguise their type: `filename-bidi-control` (right-to-left override U+202E and friends), `filename-control-chars`, `filename-double-extension` (`invoice.pdf.exe`), `filename-trailing-dot-or-space`, `filename-padding` (a run of spaces hiding the real extension) and `extension-content-mismatch` (a PE/ELF executable named like a document or picture or without extension). New module `eml_parser.anomalies`.
- Add `header.authentication` with the SPF, DKIM, DMARC (and ARC, iprev, ...) results found in the `Authentication-Results` and `Received-SPF` headers, e.g. `{"spf": ["pass"], "dkim": ["fail"]}`. These headers can be forged by the sender and are only meaningful if added by a server you trust.
- Detect remote file shares in bodies and text attachments: UNC paths (`\\host\share\file`, the WebDAV forms `\\host@SSL\DavWWWRoot\x` and `\\host@8080\x`, `\\?\UNC\host\share`) and `file://host/share`, `file:////host/share` and `smb://host/share` URLs. Opening such a path makes the client contact and authenticate to the host (NTLM hash leak) or fetch content from it. They are reported as `unc` (`unc_hash` without `include_raw_body`) and their host is added to the observed domains and IPs (numeric hosts and encoded IPv6 `*.ipv6-literal.net` are resolved; bare NetBIOS names, `localhost`, escaped text such as `C:\\Users\\Bob` and local `file:///C:/` URLs are ignored).
- Create `EmlParser` objects much faster (about 0.1 ms instead of about 40 ms): the public suffix list is parsed once per setting of `domain_force_tld` and shared by all parsers instead of once per parser. This matters most when a new parser is created for every message and makes the test suite about three times faster.

## [v4.0.0]
### Breaking
- Set minimum supported Python version to 3.11.
- Upgrade typing syntax for Python 3.11.
### Changes
- Security & Performance: Make the regex package a core dependency instead of an optional extra, as its engine evaluates the address/URL patterns in linear time even on pathological input (no catastrophic backtracking), which removes the remaining ReDoS primitive of the stdlib re fallback regardless of header length, and additionally speeds up parsing of large or malformed files.

## [v3.0.5]
### Fixes
- Security & Performance: Fix $O(n^2)$ algorithmic complexity DoS in body URL/domain extraction by re-extracting domains once from the deduplicated URL set after slicing, instead of re-scanning the entire accumulated URL list on every sliding-window slice (thanks @manus-pi - GHSA-mx3x-26cx-vw34).
- Fix the e-mail address parsing regex by limiting the local-part length, mitigating an issue with quadratic complexity when searching for e-mail addresses in very long strings (thanks Arpit Jain / @arpitjain099).

## [v3.0.4]
### Fixes
- Security & Performance: Fix $O(n^4)$ algorithmic complexity DoS in routing.parserouting by replacing static npdate regex matching with non-greedy sequence terminators (thanks @iam-niranjan).

## [v3.0.3]
### Fixes
- Fix `AttributeError` crash in `rfc2047_decode()` when decoding header values that contain no RFC2047 encoded-word (e.g. plain ASCII). `email.header.decode_header()` returns `str` fragments in that case instead of `bytes`, which was previously assumed unconditionally.
- Fix `email_no_force_tld_regex`/`email_force_tld_regex` incorrectly matching a comma (`,`) as part of an e-mail local-part due to an unescaped hyphen forming an unintended character range (`+` to `/`) in the regex character class. This could cause two comma-separated addresses to be merged into a single, invalid match.
- Fix a potential crash in `headeremail2list()` when a header contains an unquoted display name ending in a bare period (e.g. `Test.<test@example.com>`). The stdlib's `email.headerregistry` parser can itself raise on this input, and the exact exception type it raises for this case has varied across Python versions; this exception is now caught and we fall back to regex-based e-mail extraction instead of propagating the error.
- Fix PLW2901 issues

## [v3.0.2]
### Changes
- Reduce the time complexity of receive line parsing from quadratic to linear
- Properly handle HTML entities in extracted URLs
- Catch the *RecursionError* that can occur when parsing certain headers involving e-mail addresses,
  and fall back to regex-based parsing

## [v3.0.1]
### Changes
- Address unlimited recursion issue by raising *RecursionError* if *MULTIPART_RECURSION_LIMIT* has been reached (defaults to 100).

## [v3.0.0]
### Breaking
- Set minimum supported Python version to 3.10 with 3.9 being EoL.
- Upgrade typing syntax for Python 3.10

## [v2.0.1]
### Fixes
- Fix path traversal vulnerability in the example code "examples/recursively_extract_attachments.py" (#88, thanks @redyank)

## [v2.0.0]
### Breaking
- Set minimum supported Python version to 3.9
- Remove pyre2 as it hasn't been updated in a long time and regex seems to be the better lib here
- Remove long deprecated methods "decode_email", "decode_email_b"

### Changes
- Add ruff config
- Add Python 3.12 to tests

## [v1.17.5]
### Changes
- Remove obsolete methods.
- Rework hashing wrapper methods.

### Added
- Add a custom e-mail parsing policy for fixhing invalid values as soon as possible.
  - Currently implemented for invalid message-id and date parsing.

## [v1.17.4]
### Changes
- Renamed eml_parser.eml_parser to eml_parser.parser to make imports safer. This should not break any usage but nonetheless
  make sure to verify that you are not importing eml_parser.eml_parser.
- While adding tests for Python 3.11, cchardet fails to install. Turns out it seems to be abandoned and as such it has been
  replaced with [charset-normalizer](https://github.com/Ousret/charset_normalizer).
- Migrate setup.cfg to pyproject.toml

### Fixes
- Fix typing and linter issues.

## [v1.17.3]
### Fixes
- Fix parsing bad message-id formats #79.

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
