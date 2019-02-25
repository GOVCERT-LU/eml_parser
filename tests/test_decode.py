import os.path

import dateutil.parser

import eml_parser.decode
import eml_parser.eml_parser

my_execution_dir = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.split(my_execution_dir)[0]
samples_dir = os.path.join(parent_dir, 'samples')


class TestDecode:
    def test_decode_field(self):
        test_subjects = {
            'Die Bezahlung mit Ihrer Kreditkarte wurde erfolgreich durchgeführt.': '=?utf-8?B?RGllIEJlemFobHVuZyBtaXQgSWhyZXIgS3JlZGl0a2FydGUgd3VyZGUgZXJmb2xncmVpY2ggZHVyY2hnZWbDvGhydC4=?=',
            'Abmahnung Ihrer offenen Rechnung über 236,00 Euro': '=?utf-8?q?Abmahnung Ihrer offenen Rechnung =C3=BCber 236,00 Euro?=',
            'Account Analysis (Notice)': '=?utf-8?B?QWNjb3VudCBBbmFseXNpcyAoTm90aWNlKQ==?=',
            'Account Review Department (Notice)': '=?utf-8?B?QWNjb3VudCBSZXZpZXcgRGVwYXJ0bWVudCAoTm90aWNlKQ==?=',
            'John Doe Abmahnung Ihrer nicht beglichenen Rechnung über 818,00 Euro': '=?utf-8?q?John Doe Abmahnung Ihrer nicht beglichenen Rechnung =C3=BCber 818,00 Euro?=',
            '"Jane Doé" <jane.doe@example.com>': '"=?utf-8?q?Jane Do=C3=A9?=" <jane.doe@example.com>',
            '"Jane Doe" <jane.doe@example.com>': '"=?utf-8?Q?Jane_Doe?=" <jane.doe@example.com>',
            '"Geschäftsstelle www.example.com" <test@example.com>': '"=?utf-8?q?Gesch=C3=A4ftsstelle www.example.com?=" <test@example.com>',
            'ÑÓÇáÉ ÊÌÑíÈíÉ': '=?Windows-1252?B?0dPH4ckgyszR7cjtyQ==?=',
            'attachment; filename="Document N°': '=?utf-8?q?attachment=3B_filename=3D=22Document_N=C2=B0?=',
            'Sécuriser vos achats sur Internet': '=?utf-8?q?S=C3=A9curiser_vos_achats_sur_Internet?=',
            '[Spam]': '=?utf-8?Q?=5BSpam=5D?=',
            'Léa Lala-Lulu <lealalalulu@example.com>': '=?iso-8859-1?Q?L=E9a_Lala-Lulu?= <lealalalulu@example.com>',
            '''[Spam][SPAM]\r
 Cliente Example Bank''': '=?utf-8?Q?=5BSpam=5D?= =?utf-8?Q?=5BSPAM=5D=0D=0A=20Cliente=20Example=20Bank?='
            }

        for clear, encoded in test_subjects.items():
            assert eml_parser.decode.decode_field(encoded) == clear

    def test_robust_string2date(self):
        """Test the converter function, it should never return the default date
        on the provided input
        """
        default_date = '1970-01-01T00:00:00+0000'
        default_date_date = dateutil.parser.parse(default_date)
        test_input = ['Mon, 12 Jun 2017 22:25:19 +0200',
                      'Mon, 12 Jun 2017 20:24:43 +0000 (UTC)',
                      'Mon, 12 Jun 2017 16:24:21 -0400',
                      '12 Jun 2017 22:01:19.5933'
                      ]

        for test in test_input:
            assert eml_parser.decode.robust_string2date(test) != default_date_date
