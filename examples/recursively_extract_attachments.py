#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# Simple example showing how to parse all .eml files in the current folder
# and extract any attachments to a pre-configured folder
#

import argparse
import base64
import datetime
import email.header
import pathlib

import eml_parser


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""

    if isinstance(obj, datetime.datetime):
        serial = obj.isoformat()
        return serial
    elif isinstance(obj, email.header.Header):
        print(str(obj))
        raise Exception('object cannot be of type email.header.Header')
    elif isinstance(obj, bytes):
        return obj.decode('utf-8', errors='ignore')

    raise TypeError(f'Type "{str(type(obj))}" not serializable')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-p', dest='path',
                        help='Path to scan for EML files.', required=True)
    parser.add_argument('-o', dest='outpath', default='.',
                        help='Path where to save attachments in (default is current directory).')

    options = parser.parse_args()

    scan_path = pathlib.Path(options.path)
    out_path = pathlib.Path(options.outpath)

    if not scan_path.is_dir():
        raise SystemExit('Specified path is not accessible')

    if not out_path.is_dir():
        out_path.mkdir()

    ep = eml_parser.EmlParser(include_attachment_data=True)

    for k in scan_path.iterdir():
        if k.suffix == '.eml':
            print(f'Parsing: {str(k)}')

            m = ep.decode_email(k)

            if 'attachment' in m:
                for a in m['attachment']:
                    out_filepath = out_path / a['filename']

                    print(f'\tWriting attachment: {out_filepath}')
                    with out_filepath.open('wb') as a_out:
                        a_out.write(base64.b64decode(a['raw']))

                print()


if __name__ == '__main__':
    main()
