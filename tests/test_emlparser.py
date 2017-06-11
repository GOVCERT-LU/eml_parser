import os.path
import pytest
from email.message import EmailMessage
from email.headerregistry import Address
import email.utils
import email.policy

import eml_parser.eml_parser


my_execution_dir = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.split(my_execution_dir)[0]
samples_dir = os.path.join(parent_dir, 'samples')


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
