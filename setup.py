# -*- coding: utf-8 -*-
import os.path
from setuptools import setup

VERSION = (1, 1)
__version__ = VERSION
__versionstr__ = '.'.join(map(str, VERSION))


f = open(os.path.join(os.path.dirname(__file__), 'README.rst'))
long_description = f.read().strip()
f.close()

install_requires = ['python-dateutil',
                    'file-magic',
                    'cchardet'
                    ]

setup(name='eml_parser',
      description='Python EML parser library',
      license = 'AGPLv3+',
      long_description=long_description,
      version=__versionstr__,
      author='Georges Toth',
      author_email='georges.toth@govcert.etat.lu',
      packages=['eml_parser'],
      classifiers=['Development Status :: 5 - Production/Stable',
                   'License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',
                   'Intended Audience :: Developers',
                   'Operating System :: OS Independent',
                   'Programming Language :: Python :: 2.7',
                   'Programming Language :: Python :: 3',
                   'Programming Language :: Python :: Implementation :: CPython',
                   ],
      install_requires=install_requires,
      )
