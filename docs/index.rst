.. image:: https://codebeat.co/badges/d631cfb2-a7f8-476a-9d2e-58e58db95bc8
   :target: https://codebeat.co/projects/github-com-govcert-lu-eml_parser-master
   :alt: Code Health

.. image:: https://travis-ci.com/GOVCERT-LU/eml_parser.svg?branch=master
    :target: https://travis-ci.com/GOVCERT-LU/eml_parser

.. image:: https://readthedocs.org/projects/eml-parser/badge/
   :alt: Documentation Status
   :scale: 100%
   :target: http://eml-parser.readthedocs.io

.. image:: https://badge.fury.io/py/eml-parser.svg
    :target: https://badge.fury.io/py/eml-parser


Welcome to eml-parser's documentation!
======================================
  eml_parser serves as a python module for parsing eml files and returning various
  information found in the e-mail.

  Information include but are not limited to:
    - attachments
      - hashes
      - names
    - from, to, cc
    - received servers path
    - subject
    - list of URLs parsed from the text content of the mail (including HTML
      body/attachments)

Please feel free to send me your comments / pull requests.

Install the latest version using pip::

  pip install eml-parser


.. toctree::
   :maxdepth: 2
   :caption: Contents:

   api



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
