import os.path
import pytest
from email.message import EmailMessage
from email.headerregistry import Address
import email.utils
import email.policy
import dateutil.parser

import eml_parser.eml_parser


my_execution_dir = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.split(my_execution_dir)[0]
samples_dir = os.path.join(parent_dir, 'samples')


class TestRouting(object):
    def test_noparenthesis(self):
        test_input = {'(test)': '',
                      '((test))': '',
                      '(((test) (bla)))': '',
                      '(test) foo': ' foo',
                      }

        for test, expected_result in test_input.items():
            assert eml_parser.routing.noparenthesis(test) == expected_result
