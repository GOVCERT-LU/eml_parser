# -*- coding: utf-8 -*-
import os.path
from setuptools import setup

__version__ = '1.8'


f = open(os.path.join(os.path.dirname(__file__), 'README.rst'))
long_description = f.read().strip()
f.close()

install_requires = ['python-dateutil',
                    'file-magic',
                    'cchardet',
                    'typing',
                    ]

setup(name='eml_parser',
      description='Python EML parser library',
      license='AGPLv3+',
      long_description=long_description,
      version=__version__,
      author='Georges Toth',
      author_email='georges.toth@govcert.etat.lu',
      url='https://github.com/GOVCERT-LU/eml_parser',
      keywords='email',
      packages=['eml_parser'],
      classifiers=['Development Status :: 5 - Production/Stable',
                   'License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',
                   'Intended Audience :: Developers',
                   'Operating System :: OS Independent',
                   'Programming Language :: Python :: 3.4',
                   'Programming Language :: Python :: 3.5',
                   'Programming Language :: Python :: 3.6',
                   'Programming Language :: Python :: Implementation :: CPython',
                   'Topic :: Communications :: Email'
                   ],
      install_requires=install_requires,
      )
