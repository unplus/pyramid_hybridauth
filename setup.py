# -*- coding:utf-8 -*-
u"""
    pyramid_hybridauth
    ~~~~~~~~~~~~~~~~~~

    Pyramid Hybrid Auth Package.

    It provides Pyramid authentication in conjunction with external services

    using OAuth.

    :copyright: © unplus Inc. All rights reserved.
"""
from setuptools import setup, find_packages


install_requires = [
    'rauth',
    'pyramid',
    ]

tests_require = [
    ]

setup(name='pyramid_hybridauth',
      version='0.1.0',
      description='Pyramid hybrid auth.',
      long_description=__doc__,
      classifiers=[
          "Programming Language :: Python",
          "Framework :: Pylons",
      ],
      author='yoshi',
      author_email='yoshi@unplus.net',
      url='https://github.com/unplus/pyramid_hybridauth',
      keywords='pyramid oauth',
      packages=find_packages(exclude=[
        "*.tests", "*.tests.*", "tests.*", "tests"
        ]),
      include_package_data=True,
      zip_safe=False,
      test_suite='pyramid_hybridauth.tests',
      install_requires=install_requires,
      tests_require=tests_require,
      )
