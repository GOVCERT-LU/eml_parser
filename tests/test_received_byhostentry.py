import eml_parser.parser

TWO_HOPS_VIA_THE_GATEWAY = b"""Received: from inner.example.org ([192.0.2.2]) by mx.example.com with ESMTP; Mon, 1 Jan 2024 10:01:00 +0000
Received: from outer.example.net ([192.0.2.1]) by mx.example.com with ESMTP; Mon, 1 Jan 2024 10:00:00 +0000
From: a@example.org
To: b@example.com

body
"""


def test_duplicate_gateway_warnings_are_strings() -> None:
    # Arrange: both entries match the gateway, so the second line gets two warnings
    parser = eml_parser.parser.EmlParser(pconf={'byhostentry': ['mx.example', 'example.com']})

    # Act
    header = parser.decode_email_bytes(TWO_HOPS_VIA_THE_GATEWAY)['header']

    # Assert
    assert 'warning' not in header['received'][0]
    assert header['received'][1]['warning'] == ['Duplicate SMTP by entrypoint', 'Duplicate SMTP by entrypoint']
    assert header['received_src'] == ['outer.example.net', '192.0.2.1']
