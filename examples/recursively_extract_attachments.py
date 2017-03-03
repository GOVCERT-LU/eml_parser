#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function, unicode_literals

#
# Simple example showing how to parse all .eml files in the current folder
# and extract any attachments to a pre-configured folder
#

import os
import base64
import eml_parser


# where to save attachments to
outpath = '.'


for k in os.listdir('.'):
    if k.endswith('.eml'):
        print('Parsing: {}'.format(k))

        m = eml_parser.decode_email(k, include_attachment_data=True)

        for a_id, a in m['attachments'].items():
            if a['filename'] == '':
                filename = a_id
            else:
                filename = a['filename']

            filename = os.path.join(outpath, filename)

            print('\tWriting attachment: {}'.format(filename))
            with open(filename, 'wb') as a_out:
                a_out.write(base64.b64decode(a['raw']))

        print
