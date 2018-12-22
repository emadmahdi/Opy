import os
import sys

sys.path.append ('opy')
import opy.opy as opy

from setuptools import setup
import codecs

def read (*paths):
	with codecs.open (os.path.join (*paths), 'r', encoding = 'utf-8') as aFile:
		return aFile.read()

setup (
	name = 'opy_distbuilder',
	version = opy.programVersion,
	description = 'Python obfuscator for the "Distribution Builder" library.' +
				  ' An officially endorsed forked from the Opy master.',
	long_description = (
		read ('README.md') + '\n\n' +
		read ('LICENSE')
	),
	long_description_content_type = "text/markdown",
	keywords = ['opy', 'obfuscator', 'obfuscation', 'obfuscate', 'distbuilder'],
	url = 'https://github.com/QQuick/Opy/tree/opy_distbuilder',
	license = 'Apache 2',
	author = 'Jacques de Hooge, BuvinJ',
	author_email = 'buvintech@gmail.com',
	packages = ['opy'],	
	include_package_data = True,
	install_requires = ['six'],
	classifiers = [
		'Programming Language :: Python :: 2.7',
		'Programming Language :: Python :: 3',
		'Operating System :: OS Independent',		
		'License :: Other/Proprietary License',
		'Intended Audience :: Developers',
		'Topic :: Software Development :: Libraries :: Python Modules',
		'Natural Language :: English',
		'Development Status :: 4 - Beta'		
	],
)
