# eml_parser

[![Documentation Status](https://readthedocs.org/projects/eml-parser/badge/)](http://eml-parser.readthedocs.io)
[![PyPI](https://badge.fury.io/py/eml-parser.svg)](https://badge.fury.io/py/eml-parser)
[![PyPI pyversions](https://img.shields.io/pypi/pyversions/eml-parser.svg)](https://pypi.python.org/pypi/eml-parser/)

**Turn any e-mail into structured, indicator-rich JSON, even the broken and the malicious ones.**

eml_parser is a Python library for parsing `.eml` files. It returns everything you would otherwise dig out of a
message by hand: headers, the mail route, bodies, attachments and the indicators of compromise (IOCs) hiding in them.
It is built at [GOVCERT.LU](https://github.com/GOVCERT-LU) for incident response, phishing triage, threat intelligence
and mail analysis pipelines, where messages are rarely well formed and are sometimes crafted to break parsers.

## Why eml_parser?

- **Indicators, not just fields.** URLs, domains, IP addresses, e-mail addresses and remote file shares are extracted
  from the text, the HTML (including `href`, `src`, form actions, frames and scripts), and from attachments which
  carry links (SVG, scripts, shortcuts, calendar invitations, ...).
- **Phishing tricks are spotted.** Obfuscated IPs (`http://3232235777/`, `http://0xC0A80101/`), UNC and WebDAV paths
  (`\\host\share`, `file://`, `smb://`) and disguised attachments (`invoice.pdf.exe`, right-to-left override
  characters, executables posing as documents) are reported.
- **Sender authentication at a glance.** SPF, DKIM, DMARC and ARC results from `Authentication-Results` and
  `Received-SPF` are collected in `header.authentication`.
- **Robust against broken mail.** Missing or wrong multipart boundaries, bad charsets, invalid dates, garbage in front
  of the headers and other defects do not make the content disappear; defects are reported instead.
- **Hardened for hostile input.** Parsing time stays linear for pathological headers, deeply nested structures and
  huge bodies, and crafted headers can not crash the parser.
- **Deterministic results.** The same message gives the same output on every run, with unique indicators in order of
  first appearance.
- **Safe to share.** By default URLs, domains, IPs and addresses are reported as SHA-256 hashes; plain values are
  opt-in with `include_raw_body=True`.
- **Fast.** Built on the linear-time [`regex`](https://pypi.org/project/regex/) engine, and creating a parser is cheap
  enough to do it for every message.

## Installation

```shell
pip install eml_parser[filemagic]
```

Python 3.11 or newer is required.

> :warning: **Note:** The `filemagic` extra installs [file-magic](https://pypi.org/project/file-magic/) to determine the
> mime types of attachments. [python-magic](https://pypi.org/project/python-magic/) is a drop-in replacement, so if
> either of the two is installed, you are fine. Only if neither is available no mime types are determined.
> If you don't want to / cannot use the extra, install via:
>
> ```shell
> pip install eml_parser
> ```

### Known Issues

#### **OSX** users

Make sure to install libmagic, else eml_parser will not work.

## Quick start

```python
import eml_parser

ep = eml_parser.EmlParser()

with open('sample.eml', 'rb') as fhdl:
    parsed_eml = ep.decode_email_bytes(fhdl.read())

print(parsed_eml['header']['subject'])
print(parsed_eml['header'].get('authentication'))  # only present if the message has such headers
```

`decode_email('sample.eml')` reads a file by path, `decode_email_bytes()` takes the raw message. The result is a plain
`dict`; `eml_parser.decode.export_to_json()` turns it into a JSON string (dates, hashes and attachment data included).

The parser can be tuned with a few options, for example:

```python
ep = eml_parser.EmlParser(
    include_raw_body=True,      # report plain URLs, domains, IPs, ... instead of hashes, and keep the body text
    include_attachment_data=True,  # keep the (base64 encoded) content of the attachments
    parse_attachments=True,     # hash and inspect attachments
    domain_force_tld=True,      # only accept domains with a valid TLD (public suffix list)
    ip_force_routable=True,     # ignore private and reserved IP addresses
    email_force_tld=True,       # only accept e-mail addresses with a TLD
    pconf={'whiteip': ['192.168.1.1'], 'whitefor': ['postmaster@example.com']},
)
```

See the [API documentation](http://eml-parser.readthedocs.io) for all options. Ready-to-run scripts are in
[examples/](examples/).

## What you get

Fields are only present when there is something to report (for example `authentication`, `defect` and `anomaly`).

| Where | Field | Content |
| --- | --- | --- |
| `header` | `from`, `to`, `cc`, `subject`, `date` | Decoded addresses and subject, `date` as an ISO 8601 string |
| | `received` | The hops of the mail route: `from`, `by`, `with`, `for`, `date`, plus the raw line in `src` |
| | `received_domain`, `received_ip`, `received_foremail` | Domains, IPs and recipients found along the route |
| | `authentication` | SPF, DKIM, DMARC, ARC, ... results, e.g. `{"spf": ["pass"]}` |
| | `header` | All raw header fields, in order of appearance |
| | `defect` | Structural problems found in the message, e.g. `NoBoundaryInMultipartDefect` |
| `body[]` | `content_type`, `hash`, `boundary` | One entry per text part, with the SHA-256 of its content |
| | `uri`, `uri_noscheme`, `unc`, `email`, `domain`, `ip` | Indicators (with `include_raw_body=True`) |
| | `uri_hash`, `uri_noscheme_hash`, `unc_hash`, `email_hash`, `domain_hash`, `ip_hash` | The same indicators as SHA-256 (default) |
| `attachment[]` | `filename`, `extension`, `size` | Name, extension and size |
| | `hash` | MD5, SHA-1, SHA-256 and SHA-512 |
| | `mime_type`, `mime_type_short` | As detected by libmagic |
| | `anomaly` | Tricks to disguise the type, see below |

### Attachment anomalies

`anomaly` lists `filename-bidi-control`, `filename-control-chars`, `filename-double-extension`,
`filename-trailing-dot-or-space`, `filename-padding` and `extension-content-mismatch` when they apply.

### Example

This is the (abridged) result for a small phishing message with failing authentication, an obfuscated IP in a link, a
network share and a double-extension executable ([samples/sample_phishing.eml](samples/sample_phishing.eml); the raw
headers and the content headers of the parts are left out):

```json
{
  "attachment": [
    {
      "filename": "invoice.pdf.exe",
      "size": 256,
      "extension": "exe",
      "hash": {
        "md5": "00a2126b03824e2eaa5cc87ca2cbda1d",
        "sha1": "8836fcadc9faa02c011534401b5112f4cdf0b5d4",
        "sha256": "eef52d1656582cb18a4f2deba3aed5256f754e45998dc718845b013bccb44186",
        "sha512": "621d591638d18f6b7c44d14dae8953f5cc8ad7952e8235b10d9c886a4fe7b07fb1c4302bbaca1d5e0076772800db757c040359204b51bd528ed6d86611a4dd38"
      },
      "anomaly": [
        "filename-double-extension"
      ],
      "mime_type": "PE Unknown PE signature 0 (Control Panel Item), for MS Windows",
      "mime_type_short": "application/vnd.microsoft.portable-executable"
    }
  ],
  "body": [
    {
      "uri_hash": [
        "35ccde66a6e0749bb26440355987c3bf73b351c3d0e7cb5a3cc21c648ccb73d8",
        "9d7dc809de40ea7fb9fe30883a2dfc2351b90b9bc08316d7a39bcf3d3282de41"
      ],
      "unc_hash": [
        "201e3c9d007c6c6255482794cac37a235dc8083554f06b65e2c96d56e4aaf2e9"
      ],
      "domain_hash": [
        "25349124a554706674aebacad6d82390be22a3d44d2939b5805a41b022a33d53",
        "c9a1f844464610c0a2d7489e46e76cb8b51478a0a307818fbf9f677aa26522c7"
      ],
      "ip_hash": [
        "c5eb5a4cc76a5cdb16e79864b9ccd26c3553f0c396d0a21bafb7be71c1efcd8c"
      ],
      "content_type": "text/html",
      "hash": "aac2579a09161cb15583d1d628b11613a14a69e1589f2e72ab907cba1c6d7395",
      "boundary": "BOUND"
    }
  ],
  "header": {
    "subject": "Invoice 4711 - action required",
    "from": "billing@pay-secure.example",
    "to": [
      "victim@example.org"
    ],
    "date": "2026-10-05T07:12:40+00:00",
    "received": [
      {
        "src": "from mail.badhost.example (mail.badhost.example [203.0.113.7]) by mx.example.org (postfix) with esmtps id 4f2a31 for <victim@example.org>; mon, 05 oct 2026 09:12:44 +0200",
        "from": [
          "203.0.113.7",
          "mail.badhost.example"
        ],
        "by": [
          "mx.example.org"
        ],
        "with": "esmtps id 4f2a31",
        "for": [
          "victim@example.org"
        ],
        "date": "2026-10-05T07:12:44+00:00"
      }
    ],
    "received_domain": [
      "mx.example.org",
      "mail.badhost.example"
    ],
    "received_ip": [
      "203.0.113.7"
    ],
    "received_foremail": [
      "victim@example.org"
    ],
    "authentication": {
      "spf": [
        "fail"
      ],
      "dkim": [
        "none"
      ],
      "dmarc": [
        "fail"
      ]
    }
  }
}
```

With `include_raw_body=True` the indicators of the body are reported in clear text instead of hashes. Note that the
obfuscated IP in the link is resolved and the share host is added to the domains:

```json
{
  "uri": [
    "http://3232235777/login",
    "https://pay-secure.example/collect"
  ],
  "unc": [
    "\\\\files.evil.example\\share\\invoice.lnk"
  ],
  "domain": [
    "pay-secure.example",
    "files.evil.example"
  ],
  "ip": [
    "192.168.1.1"
  ]
}
```

## Contributing

Please feel free to send me your comments / pull requests.

For the changelog, please see [CHANGELOG.md](CHANGELOG.md).
