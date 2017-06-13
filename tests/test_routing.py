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

    def test_cleanline(self):
        test_input = {'   ;': '',
                      '  test  ': 'test',
                      ';  test;  ': 'test',
                      }

        for test, expected_result in test_input.items():
            assert eml_parser.routing.cleanline(test) == expected_result

    def test_give_dom_ip(self):
        test_input = {' 192.168.1.1 abc bla bla www.example.com sdsf ::1 test ': ['192.168.1.1', '::1', 'www.example.com'],
                      }

        for test, expected_result in test_input.items():
            print(test, sorted(eml_parser.routing.give_dom_ip(test)))
            assert eml_parser.routing.give_dom_ip(test) == expected_result
