import eml_parser.eml_parser


class TestEMLParser(object):
    def test_get_file_extension(self):
        assert eml_parser.eml_parser.get_file_extension('test.txt') == 'txt'
        assert eml_parser.eml_parser.get_file_extension('test') == ''
        assert eml_parser.eml_parser.get_file_extension('tést.txt') == 'txt'

    def test_get_file_hash(self):
        with open('samples/sample.eml', 'rb') as fhdl:
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
