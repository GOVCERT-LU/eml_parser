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
            assert sorted(eml_parser.routing.get_domain_ip(test)) == sorted(expected_result)

    def test_parserouting(self):
        test_input = {
            'test1': (
                '''Received: from mta1.example.com (mta1.example.com [192.168.1.100]) (using TLSv1 with cipher ADH-AES256-SHA (256/256 bits)) (No client certificate requested) by mta.example2.com (Postfix) with ESMTPS id 6388F684168 for <info@example.com>; Fri, 26 Apr 2013 13:15:55 +0200 (CEST)''',
                {'by': ['mta.example2.com'],
                 'for': ['info@example.com'],
                 'from': ['mta1.example.com', '192.168.1.100'],
                 'src': 'Received: from mta1.example.com (mta1.example.com [192.168.1.100]) (using TLSv1 with cipher ADH-AES256-SHA (256/256 bits)) (No client certificate requested) by mta.example2.com (Postfix) with ESMTPS id 6388F684168 for <info@example.com>; Fri, 26 Apr 2013 13:15:55 +0200 (CEST)',
                 'with': 'esmtps id 6388f684168',
                 'date': datetime.datetime(2013, 4, 26, 13, 15, 55, tzinfo=datetime.timezone(datetime.timedelta(0, 7200)))
                 }
            ),

            'test2': (
                # Tests a received entry which has *from* as part of a field.
                '''Received: by f321.i.example.com with local (envelope-from <b8u3hkqlkj@example.com>) id 1khYpb-0001XE-KE for someone@here-from-there.com; Tue, 24 Nov 2020 16:58:07 +0300''',
                {'for': ['someone@here-from-there.com'],
                 'src': 'Received: by f321.i.example.com with local (envelope-from <b8u3hkqlkj@example.com>) id 1khYpb-0001XE-KE for someone@here-from-there.com; Tue, 24 Nov 2020 16:58:07 +0300',
                 'with': 'local (envelope-from <b8u3hkqlkj@example.com>) id 1khypb-0001xe-ke',
                 'date': datetime.datetime(2020, 11, 24, 16, 58, 7, tzinfo=datetime.timezone(datetime.timedelta(seconds=10800)))
                 }
            ),

            'test3': (
                # C.f. github issue #54; unsupported line; point of this test is to make sure we properly catch related exceptions
                r'''Received: from)by ismtpd0112p1sjc2.abc.net (SG) with ESMTP id\n B4glDdmiQcqJYrMuLIqjUQfor <p-j.a@sdf.com>; Fri, 29 Jan 2021\n 07:24:22.501 +0000 (UTC)''',
                {
                    'src': r'Received: from)by ismtpd0112p1sjc2.abc.net (SG) with ESMTP id\n B4glDdmiQcqJYrMuLIqjUQfor <p-j.a@sdf.com>; Fri, 29 Jan 2021\n 07:24:22.501 +0000 (UTC)'
                }
            )
        }

        for test_number, test in test_input.items():
            test_output = eml_parser.routing.parserouting(test[0])

            # get all keys from the test case
            supported_keys = [x for x in test[1]]

            for sk in supported_keys:
                # make sure key is also in output
                assert sk in test_output

                if isinstance(test[1][sk], list):
                    # check if lengths match
                    assert len(test_output[sk]) == len(test[1][sk])

                    # check content
                    for e in test[1][sk]:
                        assert e in test_output[sk]

                else:
                    assert test_output[sk] == test[1][sk]

            # make sure all keys from generated output are also in the test case
            for k in test_output:
                assert k in test[1]
