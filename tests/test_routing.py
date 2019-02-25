import datetime
import os.path

import eml_parser.eml_parser
import eml_parser.routing

my_execution_dir = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.split(my_execution_dir)[0]
samples_dir = os.path.join(parent_dir, 'samples')


class TestRouting:
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
        test_input = {
            ' 192.168.1.1 abc bla bla www.example.com sdsf ::1 test ': ['192.168.1.1', '::1', 'www.example.com'],
        }

        for test, expected_result in test_input.items():
            assert sorted(eml_parser.routing.give_dom_ip(test)) == sorted(expected_result)

    def test_parserouting(self):
        test_input = {'test1': (
            '''Received: from mta1.example.com (mta1.example.com [192.168.1.100]) (using TLSv1 with cipher ADH-AES256-SHA (256/256 bits)) (No client certificate requested) by mta.example2.com (Postfix) with ESMTPS id 6388F684168 for <info@example.com>; Fri, 26 Apr 2013 13:15:55 +0200 (CEST)''',
            {'by': ['mta.example2.com'],
             'for': ['info@example.com'],
             'from': ['mta1.example.com', '192.168.1.100'],
             'src': 'Received: from mta1.example.com (mta1.example.com [192.168.1.100]) (using TLSv1 with cipher ADH-AES256-SHA (256/256 bits)) (No client certificate requested) by mta.example2.com (Postfix) with ESMTPS id 6388F684168 for <info@example.com>; Fri, 26 Apr 2013 13:15:55 +0200 (CEST)',
             'with': 'esmtps id 6388f684168',
             'date': datetime.datetime(2013, 4, 26, 13, 15, 55, tzinfo=datetime.timezone(datetime.timedelta(0, 7200)))})
        }

        for test_number, test in test_input.items():
            test_output = eml_parser.routing.parserouting(test[0])

            assert test_output['src'] == test[1]['src']
            assert test_output['with'] == test[1]['with']
            assert test_output['date'] == test[1]['date']

            assert len(test_output['by']) == len(test[1]['by'])
            assert len(test_output['for']) == len(test[1]['for'])
            assert len(test_output['from']) == len(test[1]['from'])

            for test_key in ('by', 'for', 'from'):
                for k in test_output[test_key]:
                    assert k in test[1][test_key]

                for k in test[1][test_key]:
                    assert k in test_output[test_key]
