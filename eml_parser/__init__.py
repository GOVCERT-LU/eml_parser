# -*- coding: utf-8 -*-

"""eml_parser serves as a python module for parsing eml files and returning various \
information found in the e-mail as well as computed information."""

from . import eml_parser
from .eml_parser import EmlParser

__all__ = ['eml_parser', 'EmlParser']
