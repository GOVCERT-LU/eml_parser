# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
from __future__ import annotations

import datetime
import email.policy
import email.utils
import json
import pathlib
import typing
from email.headerregistry import Address
from email.message import EmailMessage

import pytest

import eml_parser.eml_parser

my_execution_dir = pathlib.Path(__file__).resolve().parent
parent_dir = my_execution_dir.parent
samples_dir = pathlib.Path(parent_dir, 'samples')


def deep_flatten_object(obj: typing.Any) -> dict:
    """The output generated by eml_parser is a nested structure of a mix of dicts and lists.
    A simple comparison will not work here, thus what we use this function for is to convert
    the path to a value, through the structure, to a string.
    Then we fill a new dictionary with the path as key and value as a list of values (as there
    can be more than one value per key).

    Args:
        obj (object): Any of dict, list, set, tuple

    Returns:
        dict: Returns a dict with the result.
    """

    def sub(obj: typing.Any, res: list) -> typing.Iterator[typing.Tuple[str, typing.Any]]:
        if type(obj) == dict:
            for k, v in obj.items():
                yield from sub(v, res + [k])
        elif type(obj) == list:
            for v in obj:
                yield from sub(v, res)
        elif obj is None:
            yield ("_".join(res), '')
        else:
            yield ("_".join(res), obj)

    flat_kv: typing.Dict[str, typing.List[str]] = {}
    for k, v in sub(obj, []):
        if k not in flat_kv:
            flat_kv[k] = [v]
        else:
            flat_kv[k].append(v)

    return flat_kv


def recursive_compare(element_a: typing.Dict[str, str], element_b: typing.Dict[str, str]) -> None:
    """This function flattens both input elements and compares them recursively.

    Args:
        element_a (dict): Input element a.
        element_b (dict): Input element b.
    """
    element_a_flat = deep_flatten_object(element_a)
    element_b_flat = deep_flatten_object(element_b)

    for k in sorted(element_a_flat):
        assert k in element_b_flat

        for v in element_a_flat[k]:
            assert v in element_b_flat[k]


def json_serial(obj: typing.Any) -> typing.Optional[str]:
    """JSON serializer for objects not serializable by default json code"""

    if isinstance(obj, datetime.datetime):
        serial = obj.isoformat()
        return serial

    return None


class TestEMLParser:
    def test_get_file_hash(self):
        with pathlib.Path(samples_dir, 'sample.eml').open('rb') as fhdl:
            raw_email = fhdl.read()

        pre_computed_hashes = {'sha256': '99798841db2f773a11ead628526ab4d6226187e20ca715e3439bb7375806b275',
                               'md5': '2c5e3f62e6d2b1511a0f5e7476bca46a',
                               'sha512': '3a3d78e6cb8a5e0740fbfdf36083d9da950a60843bb240990ab30fa4062e608a17770a582de3d13b5240727531cfb98a826fbcc6aadd371f541acabb7c9f98e7',
                               'sha1': 'effbc0f4702f8d8d1d4911a6f0228013919c2cdc'
                               }

        assert eml_parser.eml_parser.EmlParser.get_file_hash(raw_email) == pre_computed_hashes

    def test_wrap_hash_sha256(self):
        assert eml_parser.eml_parser.EmlParser.wrap_hash_sha256(
            'www.example.com') == '80fc0fb9266db7b83f85850fa0e6548b6d70ee68c8b5b412f1deea6ebdef0404'

    def test_get_uri_ondata(self):
        test_urls = '''Lorem ipsum dolor sit amet, consectetur adipiscing elit.
        Mauris consectetur mi tortor, http://www.example.com consectetur iaculis orci ultricies sit amet.
        Mauris "http://www.example.com/test1?bla" ornare lobortis ex nec dictum. Aliquam blandit arcu ac lorem iaculis aliquet.
        Praesent a tempus dui, eu feugiat diam. Interdum http://www.example.com/a/b/c/d/ et malesuada fames ac ante ipsum primis in faucibus.
        Suspendisse ac rutrum leo, non vehicula purus. Quisque quis sapien lorem. Nunc velit enim, <img src=image.example.com/test.jpg>
        placerat quis vestibulum at, https://www.example2.com condimentum non velit.'''

        expected_result = ['http://www.example.com', 'http://www.example.com/test1?bla',
                           'http://www.example.com/a/b/c/d/', 'https://www.example2.com']

        assert eml_parser.eml_parser.EmlParser(include_href=False).get_uri_ondata(test_urls) == expected_result

    def test_get_uri_href_ondata(self):
        test_urls = '''<html><body>Lorem ipsum dolor sit amet, consectetur adipiscing elit.
        Mauris consectetur mi tortor, <a href="example.com">consectetur iaculis</a> orci ultricies sit amet.
        <center><img src="http://47fee4f03182a2437d6d-359a8ec3a1ca7be00e972dc7374155\r\n16.r50.cf3.example.com/img1.jpg" />Play a cool game!
        Mauris <a href="example.com/test1?bla"><img src=image.example.com/test.jpg></a> ex nec dictum. Aliquam blandit arcu ac lorem iaculis aliquet.
        Praesent a tempus dui, eu feugiat diam. Interdum <a href="example.com/a/b/c/d/">et malesuada</a> fames ac ante ipsum primis in faucibus.
        Suspendisse ac rutrum leo, non vehicula purus. Quisque <a href="http://www.example.com?t1=v1&amp;t2=v2">quis</a> sapien lorem. Nunc velit enim,
        placerat quis vestibulum at, <a href="example2.com">condimentum </a> non velit.</html></body>'''

        expected_result = ['http://www.example.com?t1=v1&t2=v2', 'example.com', 'http://47fee4f03182a2437d6d-359a8ec3a1ca7be00e972dc737415516.r50.cf3.example.com/img1.jpg',
                           'example.com/test1?bla', 'image.example.com/test.jpg', 'example.com/a/b/c/d/', 'example2.com']

        assert eml_parser.eml_parser.EmlParser(include_href=True, email_force_tld=True).get_uri_ondata(test_urls) == expected_result

    def test_get_uri_href_commas_ondata(self):
        test_urls = '''
        http://www.example.com?t1=v1&t2=v2,https://www.example.com, http://www1.example.com?t1=v1&t2=v2, https://www1.example.com, 
        http://www2.example.com,https://www3.example.com
        '''

        expected_result = ['http://www.example.com?t1=v1&t2=v2', 'https://www.example.com',
                           'http://www1.example.com?t1=v1&t2=v2', 'https://www1.example.com',
                           'http://www2.example.com', 'https://www3.example.com']

        assert eml_parser.eml_parser.EmlParser(include_www=True).get_uri_ondata(test_urls) == expected_result

    def test_get_valid_tld_uri_href_ondata(self):
        test_urls = '''<html><body>Lorem ipsum dolor sit amet, consectetur adipiscing elit.
        Mauris consectetur mi tortor, <a href="example.com">consectetur iaculis</a> orci ultricies sit amet.
        Mauris <a href="example.com/test1?bla"><img src=image.example.jpg/test.jpg></a> ex nec dictum. Aliquam blandit arcu ac lorem iaculis aliquet.
        Praesent a tempus dui, eu feugiat diam. Interdum <a href="example.com/a/b/c/d/">et malesuada</a> fames ac ante ipsum primis in faucibus.
        Suspendisse ac rutrum leo, non vehicula purus. Quisque <a href="http://www.example.com?t1=v1&amp;t2=v2">quis</a> sapien lorem. Nunc velit enim,
        placerat quis vestibulum at, <a href="example2.com">condimentum </a> non velit.</html></body>
        '''

        expected_result = ['http://www.example.com?t1=v1&t2=v2', 'example.com', 'example.com/test1?bla',
                           'example.com/a/b/c/d/', 'example2.com']

        assert eml_parser.eml_parser.EmlParser(include_href=True, domain_force_tld=True).get_uri_ondata(test_urls) == expected_result

    def test_get_uri_re_backtracking(self):
        """Ensure url_regex_simple does not cause catastrophic backtracking (Issue 63), test with re instead of re2 or regex"""
        test_urls = '''
        Lorem ipsum dolor sit amet, http://xxxxxxxxxx.example.com������������������������������������������������������������������������������������������������������������������������������������������������ consectetur adipiscing elit.
        '''

        expected_result = ['http://xxxxxxxxxx.example.com������������������������������������������������������������������������������������������������������������������������������������������������']

        assert eml_parser.eml_parser.EmlParser(domain_force_tld=False).get_uri_ondata(test_urls) == expected_result

    def test_get_uri_unicode_ondata(self):
        """Ensure url_regex includes Unicode in domains and paths"""
        test_urls = '''
        Lorem ipsum dolor sit amet http://💌.example.คอม , http://💌.example.คอม/📮/📧/📬.png consectetur https://💩.la adipiscing elit.
        '''

        expected_result = ['http://💌.example.คอม', 'http://💌.example.คอม/📮/📧/📬.png', 'https://💩.la']

        assert eml_parser.eml_parser.EmlParser(include_www=False, domain_force_tld=True).get_uri_ondata(test_urls) == expected_result

    def test_get_uri_ipv6_ondata(self):
        """Ensure url_regex includes URLs with IPv6 hosts, including zone Indexes"""
        test_urls = '''
        Lorem ipsum dolor sit amet http://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]
        http://[fe80::1ff:fe23:4567:890a%25eth0]/6️⃣ consectetur adipiscing elit.
        '''

        expected_result = ['http://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]', 'http://[fe80::1ff:fe23:4567:890a%25eth0]/6️⃣']

        assert eml_parser.eml_parser.EmlParser(ip_force_routable=False).get_uri_ondata(test_urls) == expected_result

    def test_get_uri_ipv6_routable_ondata(self):
        """Ensure url_regex can exclude private and other unallocated IPv6 hosts in URLs."""
        test_urls = '''
        Curabitur vel neque lacinia, consequat erat id http://[2001:0db8:85a3:0000:0000:8a2e:0370:7334], 
        venenatis sem. Etiam dignissim ullamcorper http://[2606:2800:220:1:248:1893:25c8:1946] risus non pulvinar. 
        Etiam dui tortor http://[fe80::1ff:fe23:4567:890a%25eth0]/6️⃣, posuere et iaculis sed, accumsan a erat.
        '''

        expected_result = ['http://[2606:2800:220:1:248:1893:25c8:1946]']

        assert eml_parser.eml_parser.EmlParser(ip_force_routable=True).get_uri_ondata(test_urls) == expected_result

    def test_get_uri_www_ondata(self):
        test_urls = '''
        www91.example.com@www92.example.com  www93.example.com@example.com  
        www94......example.com/path  not.www95.example.com:443/path
        www2.example.com:443/path 'www3.example.com/path' ‘www4.example.com#abc’  www5.example.com:443?def   \nwww6.example.com.../path
        www7.example.com/?# www8.example.com?/#  www9.example.com#?/  www10.example.com/?
        https://www01.example.com/path  https://www02.example.com..../path  https://www03.example.com/  
        http://www04.example.com/?# http://www05.example.com?/#  http://www06.example.com#?/  http://www07.example.com/?
        '''

        expected_result = ['www2.example.com:443/path', 'www3.example.com/path', 'www4.example.com#abc',
                           'www5.example.com:443?def', 'www6.example.com.../path', 'www7.example.com/', 'www8.example.com?/',
                           'www9.example.com#?/', 'www10.example.com/',
                           'https://www01.example.com/path', 'https://www02.example.com..../path', 'https://www03.example.com/',
                           'http://www04.example.com/', 'http://www05.example.com?/', 'http://www06.example.com#?/', 'http://www07.example.com/']

        assert eml_parser.eml_parser.EmlParser(include_www=True).get_uri_ondata(test_urls) == expected_result

    def test_headeremail2list_1(self):
        msg = EmailMessage()
        msg['Subject'] = 'Test subject éèàöüä${}'
        msg['From'] = Address("John Doe", "john.doe", "example.com")
        msg['To'] = (Address("Jané Doe", "jane.doe", "example.com"),
                     Address("James Doe", "james.doe", "example.com"))
        msg.set_content('''Hi,
Lorem ipsüm dolor sit amét, consectetur 10$ + 5€ adipiscing elit. Praesent feugiat vitae tellus et molestie. Duis est ipsum, tristique eu pulvinar vel, aliquet a nibh. Vestibulum ultricies semper euismod. Maecenas non sagittis elit. Mauris non feugiat leo. Cras vitae quam est. Donec dapibus justo ut dictum viverra. Aliquam eleifend tortor mollis, vulputate ante sit amet, sodales elit. Fusce scelerisque congue risus mollis pellentesque. Sed malesuada erat sit amet nisl laoreet mollis. Suspendisse potenti. Fusce cursus, tortor sit amet euismod molestie, sem enim semper quam, eu ultricies leo est vel turpis.
''')
        ep = eml_parser.eml_parser.EmlParser()
        ep.msg = msg

        assert sorted(ep.headeremail2list(header='to')) == ['james.doe@example.com',
                                                            'jane.doe@example.com']

    def test_headeremail2list_2(self):
        """Here we test the headeremail2list function using an input which should trigger
        a email library bug 27257
        """
        with pathlib.Path(samples_dir, 'sample_bug27257.eml').open('rb') as fhdl:
            raw_email = fhdl.read()

        msg = email.message_from_bytes(raw_email, policy=email.policy.default)

        # just to be sure we still hit bug 27257 (else there is no more need for the workaround)
        with pytest.raises(AttributeError):
            msg.items()

        ep = eml_parser.eml_parser.EmlParser()
        ep.msg = msg

        # our parsing function should trigger an exception leading to the parsing
        # using a workaround
        assert ep.headeremail2list(header='to') == ['test@example.com']

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

        ep = eml_parser.eml_parser.EmlParser()
        ep.msg = msg

        test_output_json = json.dumps(ep.parse_email(), default=json_serial)
        test_output = json.loads(test_output_json)

        recursive_compare(good_output, test_output)

    def test_parse_email_2(self):
        """Parses the e-mails from the samples folder"""
        ep = eml_parser.eml_parser.EmlParser()

        for k in samples_dir.iterdir():
            if k.suffix == ".eml":
                _ = ep.decode_email(k)

        for k in samples_dir.iterdir():
            if k.suffix == ".eml":
                with k.open('rb') as fhdl:
                    raw_email = fhdl.read()
                    _ = ep.decode_email_bytes(raw_email)

    def test_parse_email_3(self):
        """Parses the e-mails from the samples folder while keeping raw data"""
        ep = eml_parser.eml_parser.EmlParser(include_raw_body=True, include_attachment_data=True)

        for k in samples_dir.iterdir():
            if k.suffix == ".eml":
                _ = ep.decode_email(k)

        for k in samples_dir.iterdir():
            if k.suffix == ".eml":
                with k.open('rb') as fhdl:
                    raw_email = fhdl.read()
                    _ = ep.decode_email_bytes(raw_email)

    def test_parse_email_4(self):
        """Parses the e-mails from the samples folder while keeping raw data and passing
        in a filtering config 'pconf'"""
        pconf = {'whiteip': ['192.168.1.1'],
                 'whitefor': ['a@example.com'],
                 'byhostentry': ['example.com']
                 }
        ep = eml_parser.eml_parser.EmlParser(include_raw_body=True, include_attachment_data=True, pconf=pconf)

        for k in samples_dir.iterdir():
            if k.suffix == ".eml":
                _ = ep.decode_email(k)

        for k in samples_dir.iterdir():
            if k.suffix == ".eml":
                with k.open('rb') as fhdl:
                    raw_email = fhdl.read()
                    _ = ep.decode_email_bytes(raw_email)

    def test_parse_email_5(self):
        """Parses a generated sample e-mail and tests it against a known good result. In this test
        we want to specifically ignore e-mail addresses without TLD."""
        msg = EmailMessage()
        msg['Subject'] = 'Test subject éèàöüä${}'
        msg['From'] = Address("John Doe", "john.doe", "example")
        msg['To'] = (Address("Jané Doe", "jane.doe", "example.com"),
                     Address("James Doe", "james.doe", "example.com"))
        msg['Cc'] = (Address("Jané Doe", "jane.doe", "example"),
                     Address("James Doe", "james.doe", "example"))
        msg.set_content('''Hi,
      Lorem ipsüm dolor sit amét, consectetur 10$ + 5€ adipiscing elit. Praesent feugiat vitae tellus et molestie. Duis est ipsum, tristique eu pulvinar vel, aliquet a nibh. Vestibulum ultricies semper euismod. Maecenas non sagittis elit. Mauris non feugiat leo. Cras vitae quam est. Donec dapibus justo ut dictum viverra. Aliquam eleifend tortor mollis, vulputate ante sit amet, sodales elit. Fusce scelerisque congue risus mollis pellentesque. Sed malesuada erat sit amet nisl laoreet mollis. Suspendisse potenti. Fusce cursus, tortor sit amet euismod molestie, sem enim semper quam, eu ultricies leo est vel turpis.
      You should subscribe by replying to test-reply@example.
      ''')

        ep = eml_parser.eml_parser.EmlParser(email_force_tld=True)

        good_output_json = r'''{"body": [{"content_header": {"content-type": ["text/plain; charset=\"utf-8\""], "content-transfer-encoding": ["quoted-printable"]}, "content_type": "text/plain", "hash": "07de6840458e398906e73b2cd188d0da813a80ee0337cc349228d983b5ec1c7e"}], "header": {"subject": "Test subject \u00e9\u00e8\u00e0\u00f6\u00fc\u00e4${}", "from": "john.doe@example", "to": ["jane.doe@example.com", "james.doe@example.com"], "date": "1970-01-01T00:00:00+00:00", "received": [], "header": {"cc": ["Jan\u00e9 Doe <jane.doe@example>, James Doe <james.doe@example>"], "from": ["John Doe <john.doe@example>"], "content-type": ["text/plain; charset=\"utf-8\""], "mime-version": ["1.0"], "subject": ["Test subject \u00e9\u00e8\u00e0\u00f6\u00fc\u00e4${}"], "to": ["Jan\u00e9 Doe <jane.doe@example.com>, James Doe <james.doe@example.com>"], "content-transfer-encoding": ["quoted-printable"]}}}'''
        good_output = json.loads(good_output_json)

        test_output_json = json.dumps(ep.decode_email_bytes(msg.as_bytes()), default=json_serial)
        test_output = json.loads(test_output_json)

        recursive_compare(good_output, test_output)

    def test_parse_email_6(self):
        with pathlib.Path(samples_dir, 'sample_attachments.eml').open('rb') as fhdl:
            raw_email = fhdl.read()

        ep = eml_parser.eml_parser.EmlParser(include_attachment_data=True)
        test = ep.decode_email_bytes(raw_email)

        attachment_filenames = ['test.csv', 'document.pdf', 'text.txt']

        attachments = test.get('attachment', [])
        assert len(attachments) == len(attachment_filenames)

        for attachment in attachments:
            filename = attachment.get('filename', '')
            assert filename in attachment_filenames

    def test_parse_email_7(self):
        """Parse the sample file and make sure the currently unparsable date is returned as is.

        See https://bugs.python.org/issue30681 for details.
        """
        with pathlib.Path(samples_dir, 'sample_date_parsing.eml').open('rb') as fhdl:
            raw_email = fhdl.read()

        ep = eml_parser.eml_parser.EmlParser()
        test = ep.decode_email_bytes(raw_email)

        assert test['header']['header']['orig-date'][0] == 'Wed Jul 2020 23:11:43 +0100'

    def test_parse_email_8(self):
        """Parse the sample file and make sure the currently unparsable date is returned as is.

        See https://github.com/GOVCERT-LU/eml_parser/issues/48 for details.
        """
        with pathlib.Path(samples_dir, 'github_issue_48.eml').open('rb') as fhdl:
            raw_email = fhdl.read()

        ep = eml_parser.eml_parser.EmlParser()
        test = ep.decode_email_bytes(raw_email)

        assert test['body'][0]['hash'] == '4c8b6a63156885b0ca0855b1d36816c54984e1eb6f68277b46b55b4777cfac89'

    def test_parse_email_9(self):
        """Parses an email and verifies that www URLs with no scheme are extracted, and that URLs at the end of a message body are extracted"""
        with pathlib.Path(samples_dir, 'sample_body_noscheme_url.eml').open('rb') as fhdl:
            raw_email = fhdl.read()

        ep = eml_parser.eml_parser.EmlParser(include_raw_body=True)
        test = ep.decode_email_bytes(raw_email)

        assert sorted(test['body'][0]['uri_noscheme']) == ['www.example.com/a/b/c/d/', 'www.example.com/test1?bla']
        assert sorted(test['body'][0]['uri']) == ['http://www.example.com/', 'https://www.example2.com']

    def test_parse_email_from_email_email(self):
        """Parses a generated sample e-mail and tests it against a known good result. In this test
        we want to specifically test for correct from address parsing where the from field contains two e-mail addresses."""
        msg = EmailMessage()
        msg['Subject'] = 'Test subject éèàöüä${}'
        msg['From'] = Address("john@fake-example.com", "john", "example.com")
        msg['To'] = (Address("Jané Doe", "jane.doe", "example.com"),
                     Address("James Doe", "james.doe", "example.com"))
        msg.set_content('''Hi,
      Lorem ipsüm dolor sit amét, consectetur 10$ + 5€ adipiscing elit. Praesent feugiat vitae tellus et molestie. Duis est ipsum, tristique eu pulvinar vel, aliquet a nibh. Vestibulum ultricies semper euismod. Maecenas non sagittis elit. Mauris non feugiat leo. Cras vitae quam est. Donec dapibus justo ut dictum viverra. Aliquam eleifend tortor mollis, vulputate ante sit amet, sodales elit. Fusce scelerisque congue risus mollis pellentesque. Sed malesuada erat sit amet nisl laoreet mollis. Suspendisse potenti. Fusce cursus, tortor sit amet euismod molestie, sem enim semper quam, eu ultricies leo est vel turpis.
      You should subscribe by replying to test-reply@example.
      ''')

        ep = eml_parser.eml_parser.EmlParser()

        good_output_json = r'''{"body": [{"content_header": {"content-type": ["text/plain; charset=\"utf-8\""], "content-transfer-encoding": ["quoted-printable"]}, "content_type": "text/plain", "hash": "07de6840458e398906e73b2cd188d0da813a80ee0337cc349228d983b5ec1c7e"}], "header": {"subject": "Test subject \u00e9\u00e8\u00e0\u00f6\u00fc\u00e4${}", "from": "john@example.com", "to": ["jane.doe@example.com", "james.doe@example.com"], "date": "1970-01-01T00:00:00+00:00", "received": [], "header":{"content-transfer-encoding": ["quoted-printable"], "from": ["\"john@fake-example.com\" <john@example.com>"], "content-type": ["text/plain; charset=\"utf-8\""], "to": ["Jan\u00e9 Doe <jane.doe@example.com>, James Doe <james.doe@example.com>"], "subject": ["Test subject \u00e9\u00e8\u00e0\u00f6\u00fc\u00e4${}"], "mime-version": ["1.0"]}}}'''
        good_output = json.loads(good_output_json)

        test_output_json = json.dumps(ep.decode_email_bytes(msg.as_bytes()), default=json_serial)
        test_output = json.loads(test_output_json)

        recursive_compare(good_output, test_output)

    def test_parse_email_to_email_email(self):
        """Parses a generated sample e-mail and tests it against a known good result. In this test
        we want to specifically test for correct to address parsing where the to field contains two e-mail addresses."""
        msg = EmailMessage()
        msg['Subject'] = 'Test subject éèàöüä${}'
        msg['From'] = Address("john@fake-example.com", "john", "example.com")
        msg['To'] = (Address("jane@fake-example.com", "jane.doe", "example.com"),
                     Address("James Doe", "james.doe", "example.com"))
        msg.set_content('''Hi,
      Lorem ipsüm dolor sit amét, consectetur 10$ + 5€ adipiscing elit. Praesent feugiat vitae tellus et molestie. Duis est ipsum, tristique eu pulvinar vel, aliquet a nibh. Vestibulum ultricies semper euismod. Maecenas non sagittis elit. Mauris non feugiat leo. Cras vitae quam est. Donec dapibus justo ut dictum viverra. Aliquam eleifend tortor mollis, vulputate ante sit amet, sodales elit. Fusce scelerisque congue risus mollis pellentesque. Sed malesuada erat sit amet nisl laoreet mollis. Suspendisse potenti. Fusce cursus, tortor sit amet euismod molestie, sem enim semper quam, eu ultricies leo est vel turpis.
      You should subscribe by replying to test-reply@example.
      ''')

        ep = eml_parser.eml_parser.EmlParser()

        good_output_json = r'''{"body": [{"content_header": {"content-type": ["text/plain; charset=\"utf-8\""], "content-transfer-encoding": ["quoted-printable"]}, "content_type": "text/plain", "hash": "07de6840458e398906e73b2cd188d0da813a80ee0337cc349228d983b5ec1c7e"}], "header": {"subject": "Test subject \u00e9\u00e8\u00e0\u00f6\u00fc\u00e4${}", "from": "john@example.com", "to": ["jane.doe@example.com", "james.doe@example.com"], "date": "1970-01-01T00:00:00+00:00", "received": [], "header":{"content-transfer-encoding": ["quoted-printable"], "from": ["\"john@fake-example.com\" <john@example.com>"], "content-type": ["text/plain; charset=\"utf-8\""], "to": ["\"jane@fake-example.com\" <jane.doe@example.com>, James Doe <james.doe@example.com>"], "subject": ["Test subject \u00e9\u00e8\u00e0\u00f6\u00fc\u00e4${}"], "mime-version": ["1.0"]}}}'''
        good_output = json.loads(good_output_json)

        test_output_json = json.dumps(ep.decode_email_bytes(msg.as_bytes()), default=json_serial)
        test_output = json.loads(test_output_json)

        recursive_compare(good_output, test_output)

    def test_parse_email_newline_quopri(self):
        """Make sure we can parse RFC2047 encoded header fields with CR/LF embedded (which is invalid)."""
        ep = eml_parser.eml_parser.EmlParser()
        sample = samples_dir / 'sample_gh_issue_76.eml'

        with sample.open('rb') as fhdl:
            output = ep.decode_email_bytes(fhdl.read())

        assert output['header']['from'] == 'badname@example.com'
        assert output['header']['to'] == ['badname@example.com']
        assert output['header']['cc'] == ['badname@example.com']
        assert output['header']['header']['from'] == ['\n <badname@example.com>']
        assert output['header']['header']['to'] == ['\n <badname@example.com>']
        assert output['header']['header']['cc'] == ['\r <badname@example.com>']
