import codecs
import os
import sys
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

version_tuple = (1, 1, 7)
version = version_string = __version__ = '%d.%d.%d' % version_tuple
__author__ = 'tradeface'


if len(sys.argv) <= 1:
    print("""
Suggested setup.py parameters:
    * build
    * install
    * sdist  --formats=zip
    * sdist  # NOTE requires tar/gzip commands
PyPi:
    twine upload dist/*
""")

here = os.path.abspath(os.path.dirname(__file__))

readme_filename = os.path.join(here, 'readme.md')
if os.path.exists(readme_filename):
    with codecs.open(readme_filename, encoding='utf-8') as f:
        long_description = f.read()
else:
    long_description = None


setup(
    name='tuyaface',
    author=__author__,
    version=__version__,
    description='Python interface to Tuya WiFi smart devices.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/TradeFace/tuya/',
    author_email='',
    license='Unlicense',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Home Automation',
        'License :: Public Domain',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Topic :: Home Automation',
    ],
    keywords='home automation, tuya',
    packages=['tuyaface'],
    platforms='any',
    install_requires=[      
          'pycryptodomex',
          'bitstring',
    ],
)