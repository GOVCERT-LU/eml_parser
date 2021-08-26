[![Code Health](https://codebeat.co/badges/d631cfb2-a7f8-476a-9d2e-58e58db95bc8)](https://codebeat.co/projects/github-com-govcert-lu-eml_parser-master)
[![Travis CI](https://travis-ci.com/GOVCERT-LU/eml_parser.svg?branch=master)](https://travis-ci.com/GOVCERT-LU/eml_parser)
[![Documentation Status](https://readthedocs.org/projects/eml-parser/badge/)](http://eml-parser.readthedocs.io)
[![PyPI](https://badge.fury.io/py/eml-parser.svg)](https://badge.fury.io/py/eml-parser)
[![PyPI pyversions](https://img.shields.io/pypi/pyversions/eml-parser.svg)](https://pypi.python.org/pypi/eml-parser/)

eml_parser serves as a python module for parsing eml files and returning various
information found in the e-mail as well as computed information.

Extracted and generated information include but are not limited to:
- attachments
  - hashes
  - names
- from, to, cc
- received servers path
- subject
- list of URLs parsed from the text content of the mail (including HTML body/attachments)

Please feel free to send me your comments / pull requests.

For the changelog, please see [CHANGELOG.md](CHANGELOG.md).

### Installation:
```shell script
pip install eml_parser[filemagic]
```

:warning: **Note:** If you don't want to / cannot use file-magic (e.g. if you are using python-magic), install via:
```shell script
pip install eml_parser
```

### Known Issues
#### **OSX** users
Make sure to install libmagic, else eml_parser will not work.

#### Python <=3.7.4 "rare header field parsing issue"
It has been reported (in #60) that there are parsing issues in some particular cases which seem
to be caused by a bug in the *email* module of the Python standard library. At least versions <=3.7.4 are affected.

Python versions >=3.7.11 are not affected. If you do get *KeyError* exceptions on header field parsing, you should
consider upgrading to a more recent version of Python.

-> Please open an issue if the error persists after upgrading.


### Example usage:
```python
import datetime
import json
import eml_parser


def json_serial(obj):
  if isinstance(obj, datetime.datetime):
      serial = obj.isoformat()
      return serial


with open('sample.eml', 'rb') as fhdl:
  raw_email = fhdl.read()

ep = eml_parser.EmlParser()
parsed_eml = ep.decode_email_bytes(raw_email)

print(json.dumps(parsed_eml, default=json_serial))
```


Which gives for a minimalistic EML file something like this:
```json
  {
    "body": [
      {
        "content_header": {
          "content-language": [
            "en-US"
          ]
        },
        "hash": "6c9f343bdb040e764843325fc5673b0f43a021bac9064075d285190d6509222d"
      }
    ],
    "header": {
      "received_src": null,
      "from": "john.doe@example.com",
      "to": [
        "test@example.com"
      ],
      "subject": "Sample EML",
      "received_foremail": [
        "test@example.com"
      ],
      "date": "2013-04-26T11:15:47+00:00",
      "header": {
        "content-language": [
          "en-US"
        ],
        "received": [
          "from localhost\tby mta.example.com (Postfix) with ESMTPS id 6388F684168\tfor <test@example.com>; Fri, 26 Apr 2013 13:15:55 +0200"
        ],
        "to": [
          "test@example.com"
        ],
        "subject": [
          "Sample EML"
        ],
        "date": [
          "Fri, 26 Apr 2013 11:15:47 +0000"
        ],
        "message-id": [
          "<F96257F63EAEB94C890EA6CE1437145C013B01FA@example.com>"
        ],
        "from": [
          "John Doe <john.doe@example.com>"
        ]
      },
      "received_domain": [
        "mta.example.com"
      ],
      "received": [
        {
          "with": "esmtps id 6388f684168",
          "for": [
            "test@example.com"
          ],
          "by": [
            "mta.example.com"
          ],
          "date": "2013-04-26T13:15:55+02:00",
          "src": "from localhost by mta.example.com (postfix) with esmtps id 6388f684168 for <test@example.com>; fri, 26 apr 2013 13:15:55 +0200"
        }
      ]
    }
  }
```