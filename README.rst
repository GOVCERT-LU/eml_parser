.. image:: https://landscape.io/github/GOVCERT-LU/eml_parser/master/landscape.svg?style=flat
   :target: https://landscape.io/github/GOVCERT-LU/eml_parser/master
   :alt: Code Health

.. image:: https://www.quantifiedcode.com/api/v1/project/468b8039f5a94528aaa9d7a25ecc68eb/badge.svg
   :target: https://www.quantifiedcode.com/app/project/468b8039f5a94528aaa9d7a25ecc68eb
   :alt: Code issues

.. image:: https://readthedocs.org/projects/eml-parser/badge/
   :alt: Documentation Status
   :scale: 100%
   :target: http://eml-parser.readthedocs.io


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
