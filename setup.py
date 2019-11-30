# -*- coding: utf-8 -*-
import os.path

import setuptools

f = open(os.path.join(os.path.dirname(__file__), 'README.rst'))
long_description = f.read().strip()
f.close()

install_requires = ['python-dateutil',
                    'cchardet',
                    'typing; python_version < "3.5"'
                    ]

setuptools.setup(name='eml_parser',
                 description='Python EML parser library',
                 license='AGPLv3+',
                 long_description=long_description,
                 version='1.11.6',
                 author='Georges Toth',
                 author_email='georges.toth@govcert.etat.lu',
                 url='https://github.com/GOVCERT-LU/eml_parser',
                 keywords='email',
                 packages=setuptools.find_packages(),
                 package_data={'eml_parser': ['py.typed']},
                 classifiers=['Development Status :: 5 - Production/Stable',
                              'License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',
                              'Intended Audience :: Developers',
                              'Operating System :: OS Independent',
                              'Programming Language :: Python :: 3.5',
                              'Programming Language :: Python :: 3.6',
                              'Programming Language :: Python :: 3.7',
                              'Programming Language :: Python :: Implementation :: CPython',
                              'Topic :: Communications :: Email'
                              ],
                 extras_require={
                     'file-magic': ["file-magic"]
                 },
                 install_requires=install_requires,
                 )
