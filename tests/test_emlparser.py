# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
import os.path
import json
import datetime
import pytest
from email.message import EmailMessage
from email.headerregistry import Address
import email.utils
import email.policy

import eml_parser.eml_parser


my_execution_dir = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.split(my_execution_dir)[0]
samples_dir = os.path.join(parent_dir, 'samples')


def recursive_compare(element_a: dict, element_b: dict):
    '''Function for recursively comparing two variables and check if they are equal.
    The idea behind this function is to check two objects generated from JSON strings.
    Types which are supported by JSON are supported here as well.

    Args:
        element_a (dict): Object A to compare to object B.
        element_b (dict): Object B to compare to object A.

    Raises:
        AssertionError: Raises an AssertionError whenever differences are found while
                        comparing the objects.
    '''
    if isinstance(element_a, dict):
        assert isinstance(element_b, dict)

        for element_a_key, element_a_value in element_a.items():
            assert element_a_key in element_b

            recursive_compare(element_a_value, element_b[element_a_key])

    elif isinstance(element_a, list):
        assert isinstance(element_b, list)

        for element_a_value in element_a:
            assert element_a_value in element_b

            recursive_compare(element_a_value, element_b[element_b.index(element_a_value)])

    elif type(element_a) in (str, int, bool, None):
        assert type(element_a) is type(element_b)
        assert element_a == element_b

    else:
        raise ValueError('No idea how to handle - {}'.format(type(element_a)))


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""

    if isinstance(obj, datetime.datetime):
        serial = obj.isoformat()
        return serial


class TestEMLParser(object):
    def test_get_file_hash(self):
        with open(os.path.join(samples_dir, 'sample.eml'), 'rb') as fhdl:
            raw_email = fhdl.read()

        pre_computed_hashes = {'sha256': '99798841db2f773a11ead628526ab4d6226187e20ca715e3439bb7375806b275',
                               'md5': '2c5e3f62e6d2b1511a0f5e7476bca46a',
                               'sha512': '3a3d78e6cb8a5e0740fbfdf36083d9da950a60843bb240990ab30fa4062e608a17770a582de3d13b5240727531cfb98a826fbcc6aadd371f541acabb7c9f98e7',
                               'sha1': 'effbc0f4702f8d8d1d4911a6f0228013919c2cdc'
                               }

        assert eml_parser.eml_parser.get_file_hash(raw_email) == pre_computed_hashes

    def test_wrap_hash_sha256(self):
        assert eml_parser.eml_parser.wrap_hash_sha256('www.example.com') == '80fc0fb9266db7b83f85850fa0e6548b6d70ee68c8b5b412f1deea6ebdef0404'

    def test_get_uri_ondata(self):
        test_urls = '''Lorem ipsum dolor sit amet, consectetur adipiscing elit.
        Mauris consectetur mi tortor, http://www.example.com consectetur iaculis orci ultricies sit amet.
        Mauris "http://www.example.com/test1?bla" ornare lobortis ex nec dictum. Aliquam blandit arcu ac lorem iaculis aliquet.
        Praesent a tempus dui, eu feugiat diam. Interdum http://www.example.com/a/b/c/d/ et malesuada fames ac ante ipsum primis in faucibus.
        Suspendisse ac rutrum leo, non vehicula purus. Quisque quis sapien lorem. Nunc velit enim,
        placerat quis vestibulum at, hxxps://www.example2.com condimentum non velit.'''

        expected_result = ['http://www.example.com', 'http://www.example.com/test1?bla', 'http://www.example.com/a/b/c/d/', 'https://www.example2.com']

        assert eml_parser.eml_parser.get_uri_ondata(test_urls) == expected_result

    def test_headeremail2list_1(self):
        msg = EmailMessage()
        msg['Subject'] = 'Test subject éèàöüä${}'
        msg['From'] = Address("John Doe", "john.doe", "example.com")
        msg['To'] = (Address("Jané Doe", "jane.doe", "example.com"),
                     Address("James Doe", "james.doe", "example.com"))
        msg.set_content('''Hi,
Lorem ipsüm dolor sit amét, consectetur 10$ + 5€ adipiscing elit. Praesent feugiat vitae tellus et molestie. Duis est ipsum, tristique eu pulvinar vel, aliquet a nibh. Vestibulum ultricies semper euismod. Maecenas non sagittis elit. Mauris non feugiat leo. Cras vitae quam est. Donec dapibus justo ut dictum viverra. Aliquam eleifend tortor mollis, vulputate ante sit amet, sodales elit. Fusce scelerisque congue risus mollis pellentesque. Sed malesuada erat sit amet nisl laoreet mollis. Suspendisse potenti. Fusce cursus, tortor sit amet euismod molestie, sem enim semper quam, eu ultricies leo est vel turpis.
''')

        assert sorted(eml_parser.eml_parser.headeremail2list(mail=msg, header='to')) == ['james.doe@example.com', 'jane.doe@example.com']

    def test_headeremail2list_2(self):
        '''Here we test the headeremail2list function using an input which should trigger
        a email library bug 27257
        '''
        with open(os.path.join(samples_dir, 'sample_bug27257.eml'), 'rb') as fhdl:
            raw_email = fhdl.read()

        msg = email.message_from_bytes(raw_email, policy=email.policy.default)

        # just to be sure we still hit bug 27257 (else there is no more need for the workaround)
        with pytest.raises(AttributeError):
            msg.items()

        # our parsing function should trigger an exception leading to the parsing
        # using a workaround
        assert eml_parser.eml_parser.headeremail2list(mail=msg, header='to') == ['test@example.com']

    def test_parse_email_1(self):
        """Parses a generated sample e-mail and tests it against a known good result"""
        msg = EmailMessage()
        msg['Subject'] = 'Test subject éèàöüä${}'
        msg['From'] = Address("John Doe", "john.doe", "example.com")
        msg['To'] = (Address("Jané Doe", "jane.doe", "example.com"),
                     Address("James Doe", "james.doe", "example.com"))
        msg.set_content('''Hi,
      Lorem ipsüm dolor sit amét, consectetur 10$ + 5€ adipiscing elit. Praesent feugiat vitae tellus et molestie. Duis est ipsum, tristique eu pulvinar vel, aliquet a nibh. Vestibulum ultricies semper euismod. Maecenas non sagittis elit. Mauris non feugiat leo. Cras vitae quam est. Donec dapibus justo ut dictum viverra. Aliquam eleifend tortor mollis, vulputate ante sit amet, sodales elit. Fusce scelerisque congue risus mollis pellentesque. Sed malesuada erat sit amet nisl laoreet mollis. Suspendisse potenti. Fusce cursus, tortor sit amet euismod molestie, sem enim semper quam, eu ultricies leo est vel turpis.
      ''')

        good_output_json = r'''{"header": {"header": {"content-transfer-encoding": ["quoted-printable"], "content-type": ["text/plain; charset=\"utf-8\""], "from": ["John Doe <john.doe@example.com>"], "subject": ["Test subject \u00e9\u00e8\u00e0\u00f6\u00fc\u00e4${}"], "to": ["Jan\u00e9 Doe <jane.doe@example.com>, James Doe <james.doe@example.com>"], "mime-version": ["1.0"]}, "from": "john.doe@example.com", "subject": "Test subject \u00e9\u00e8\u00e0\u00f6\u00fc\u00e4${}", "received": [], "date": "1970-01-01T00:00:00+00:00", "to": ["jane.doe@example.com", "james.doe@example.com"]}, "body": [{"content_header": {"content-transfer-encoding": ["quoted-printable"], "content-type": ["text/plain; charset=\"utf-8\""]}, "hash": "f765993eba20df87927f5bf6e947696d48bdf936e75508b9d126bbe8aa1a1497", "content_type": "text/plain"}]}'''
        good_output = json.loads(good_output_json)

        test_output_json = json.dumps(eml_parser.eml_parser.parse_email(msg), default=json_serial)
        test_output = json.loads(test_output_json)

        recursive_compare(good_output, test_output)

    def test_parse_email_2(self):
        """Parses the e-mails from the samples folder"""
        for k in os.listdir(samples_dir):
            test = eml_parser.eml_parser.decode_email(os.path.join(samples_dir, k))

        for k in os.listdir(samples_dir):
            with open(os.path.join(samples_dir, k), 'rb') as fhdl:
                raw_email = fhdl.read()
                test = eml_parser.eml_parser.decode_email_b(raw_email)

    def test_parse_email_3(self):
        """Parses the e-mails from the samples folder while keeping raw data"""
        for k in os.listdir(samples_dir):
            test = eml_parser.eml_parser.decode_email(os.path.join(samples_dir, k), include_raw_body=True, include_attachment_data=True)

        for k in os.listdir(samples_dir):
            with open(os.path.join(samples_dir, k), 'rb') as fhdl:
                raw_email = fhdl.read()
                test = eml_parser.eml_parser.decode_email_b(raw_email, include_raw_body=True, include_attachment_data=True)

    def test_parse_email_4(self):
        """Parses the e-mails from the samples folder while keeping raw data and passing
        in a filtering config 'pconf'"""
        pconf = {'whiteip': ['192.168.1.1'],
                 'whitefor': ['a@example.com'],
                 'byhostentry': ['example.com']
                 }

        for k in os.listdir(samples_dir):
            test = eml_parser.eml_parser.decode_email(os.path.join(samples_dir, k), include_raw_body=True, include_attachment_data=True, pconf=pconf)

        for k in os.listdir(samples_dir):
            with open(os.path.join(samples_dir, k), 'rb') as fhdl:
                raw_email = fhdl.read()
                test = eml_parser.eml_parser.decode_email_b(raw_email, include_raw_body=True, include_attachment_data=True, pconf=pconf)
