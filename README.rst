.. image:: https://landscape.io/github/GOVCERT-LU/eml_parser/master/landscape.svg?style=flat
   :target: https://landscape.io/github/GOVCERT-LU/eml_parser/master
   :alt: Code Health

.. image:: https://www.quantifiedcode.com/api/v1/project/468b8039f5a94528aaa9d7a25ecc68eb/badge.svg
   :target: https://www.quantifiedcode.com/app/project/468b8039f5a94528aaa9d7a25ecc68eb
   :alt: Code issues

.. image:: https://travis-ci.org/GOVCERT-LU/eml_parser.svg?branch=static_types
    :target: https://travis-ci.org/GOVCERT-LU/eml_parser

.. image:: https://readthedocs.org/projects/eml-parser/badge/
   :alt: Documentation Status
   :scale: 100%
   :target: http://eml-parser.readthedocs.io

.. image:: https://badge.fury.io/py/eml-parser.svg
    :target: https://badge.fury.io/py/eml-parser


eml_parser serves as a python module for parsing eml files and returning various
information found in the e-mail as well as computed information.

Extracted and generated information include but are not limited to:

  - attachments
    - hashes
    - names
  - from, to, cc
  - received servers path
  - subject
  - list of URLs parsed from the text content of the mail (including HTML
    body/attachments)

Please feel free to send me your comments / pull requests.

Install the latest version using pip:

.. code-block:: bash

  pip install eml-parser


**Note for OSX users**::

  Make sure to install libmagic, else eml_parser will not work.


**Warning**::

  This release is only compatible with Python3. The last release to be compatible with
  Python2 is v1.2. If you do require Python2 support, please download that version.
  You are strongly encouraged though to use Python3 as there are many parsing improvements
  and much better RFC support.


Example on how to use:

.. code-block:: python

  import eml_parser


  def json_serial(obj):
      if isinstance(obj, datetime.datetime):
          serial = obj.isoformat()
          return serial


  with open('sample.eml', 'rb') as fhdl:
      raw_email = fhdl.read()

  parsed_eml = eml_parser.eml_parser.decode_email_b(raw_email)

  print(json.dumps(parsed_eml, default=json_serial))


Which gives for a minimalistic EML file something like this:

.. code-block:: json

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
