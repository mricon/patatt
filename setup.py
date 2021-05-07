#!/usr/bin/env python3

import os
import re
from setuptools import setup

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


def find_version(source):
    version_file = read(source)
    version_match = re.search(r"^__VERSION__ = ['\"]([^'\"]*)['\"]", version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


NAME = 'patatt'

setup(
    version=find_version('patatt/__init__.py'),
    url='https://git.kernel.org/pub/scm/utils/patatt/patatt.git/about/',
    name=NAME,
    description='A simple library to add cryptographic attestation to patches sent via email',
    author='Konstantin Ryabitsev',
    author_email='mricon@kernel.org',
    packages=['patatt'],
    license='MIT-0',
    long_description=read('README.rst'),
    long_description_content_type='text/x-rst',
    data_files = [('share/man/man5', ['man/patatt.5'])],
    keywords=['git', 'patches', 'attestation'],
    install_requires=[
        'pynacl',
    ],
    python_requires='>=3.6',
    entry_points={
        'console_scripts': [
            'patatt=patatt:command'
        ],
    },
)
