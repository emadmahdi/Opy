#! /usr/bin/python
license = (  # @ReservedAssignment
'''_opy_Copyright 2014, 2015, 2016, 2017 Jacques de Hooge, GEATEC engineering, www.geatec.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
==============================================
OPY2
Version:  OPY2.2024.03.12
Modified, Enhanced, Fixed and Extended by:
EMAD MAHDI

Please feel free to report any errors or suggest new features:
	http://github.com/emadmahdi/opy2
==============================================
''')

# OPY2
allClearWords = {}
allObfuscatedWords = {}
import time,ast
timeStart = time.time()

import re
import os
import sys
import errno
import keyword
import importlib  # @UnusedImport
import random
import codecs
import shutil

isPython2 = sys.version_info [0] == 2
if isPython2 : 
	import __builtin__
else:
	import builtins
	
try: 
	from . import settings 
	isLibraryInvoked = settings.isLibraryInvoked
except:
	isLibraryInvoked=False

try: 
	from . import opy_parser                # @UnusedImport
	#from . _version import __version__  # @UnusedImport
except: 
	import opy_parser                   # @Reimport
	#from _version import __version__    # @Reimport

programName = 'opy'
__version__ = "OPY2.2024.03.12"

if (__name__ == '__main__') or isLibraryInvoked:
	print('\n---------------------------------------------')
	print ('{} (TM) Configurable Multi Module Python Obfuscator'.format (programName.capitalize (), __version__))
	print ('Copyright (C) Geatec Engineering. License: Apache 2.0 at  http://www.apache.org/licenses/LICENSE-2.0')
	print('''---------------------------------------------
OPY2     Version:  {0}     by: EMAD MAHDI
To report errors/suggestions/issues/requests use:  http://github.com/emadmahdi/opy2
---------------------------------------------\n'''.format(__version__))

	random.seed ()

	charBase = 2048         # Choose high to prevent string recoding from generating special chars like ', " and \
	stringNr = charBase
	charModulus = 7

	# =========== Utilities   

	def createFilePath (filePath, open = False):  # @ReservedAssignment
		try:
			os.makedirs (filePath.rsplit ('/', 1) [0])
		except OSError as exception:
			if exception.errno != errno.EEXIST:
				raise
				
		if open:
			return codecs.open (filePath, encoding = 'utf-8', mode = 'w')
			
	# OPY2
	# Obfuscate randomly any name and save it
	def getObfuscatedName(name,isFilename=False):
		if name in skipWordSet:
			obfuscatedWord = name
			allObfuscatedWords[name] = name
		elif name in list(allObfuscatedWords.keys()):
			obfuscatedWord = allObfuscatedWords[name]
		else:
			while True:
				random.shuffle(obfuscationLettersEnlargedList)
				if isFilename: obfuscationSize = obfuscateSize_FoldersFiiles
				else: obfuscationSize = random.randint(obfuscationMinimumSize_Words,obfuscationMaximumSize_Words)
				firstLetter = filter(str.isalpha,str(obfuscationLettersEnlargedList))[0]
				obfStart = '__' if name.startswith ('__') else '_' if name.startswith ('_') else firstLetter
				newWord = ''.join(obfuscationLettersEnlargedList)[1:obfuscationSize]
				obfuscatedWord = obfStart+newWord+obfuscatedNameTail
				if obfuscatedWord not in list(allObfuscatedWords.values()) and obfuscatedWord not in skipWordSet:
					allObfuscatedWords[name] = obfuscatedWord
					break
		return obfuscatedWord
		
	def scramble (stringLiteral):
		global stringNr
		
		if isPython2:
			recodedStringLiteral = unicode () .join ([unichr (charBase + ord (char) + (charIndex + stringNr) % charModulus) for charIndex, char in enumerate (stringLiteral)])
			stringKey = unichr (stringNr)
		else:
			recodedStringLiteral = str () .join ([chr (charBase + ord (char) + (charIndex + stringNr) % charModulus) for charIndex, char in enumerate (stringLiteral)])
			stringKey = chr (stringNr)
			
		rotationDistance = stringNr % len (stringLiteral)
		rotatedStringLiteral = recodedStringLiteral [:-rotationDistance] + recodedStringLiteral [-rotationDistance:]
		keyedStringLiteral = rotatedStringLiteral + stringKey
		
		stringNr += 1
		return 'u"' + keyedStringLiteral + '"'      
		
	def getUnScrambler (stringBase):
		return '''
from sys import version_info as __opyVerInfo

isPython2 = __opyVerInfo[0{0}] == 2{0}
charBase = {1}{0}
charModulus = {2}{0}

def unScramble (keyedStringLiteral):
	global stringNr
	
	stringNr = ord (keyedStringLiteral [-1{0}])
	rotatedStringLiteral = keyedStringLiteral [:-1{0}]
	
	rotationDistance = stringNr % len (rotatedStringLiteral)
	recodedStringLiteral = rotatedStringLiteral [:rotationDistance] + rotatedStringLiteral [rotationDistance:]
		
	if isPython2:
		stringLiteral = unicode () .join ([unichr (ord (char) - charBase - (charIndex + stringNr) % charModulus) for charIndex, char in enumerate (recodedStringLiteral)])
	else:
		stringLiteral = str () .join ([chr (ord (char) - charBase - (charIndex + stringNr) % charModulus) for charIndex, char in enumerate (recodedStringLiteral)])
		
	return eval (stringLiteral)

# OPY2
unScramble0,unScramble1,unScramble2=unScramble,unScramble,unScramble
unScramble3,unScramble4,unScramble5=unScramble2,unScramble1,unScramble0
unScramble6,unScramble7,unScramble8=unScramble5,unScramble4,unScramble3
unScramble9,unScramble10,unScramble11=unScramble8,unScramble7,unScramble6
unScramble12,unScramble13,unScramble14=unScramble11,unScramble10,unScramble9
unScramble15,unScramble16,unScramble17=unScramble14,unScramble13,unScramble12
unScramble18,unScramble19,unScramble20=unScramble17,unScramble16,unScramble15
unScramble21,unScramble22,unScramble23=unScramble20,unScramble19,unScramble18
unScramble24,unScramble25,unScramble26=unScramble23,unScramble22,unScramble21
unScramble27,unScramble28,unScramble29=unScramble26,unScramble25,unScramble24
unScramble30,unScramble31,unScramble32=unScramble29,unScramble28,unScramble27
'''.format (plainMarker, charBase, charModulus) 
			
	def printHelpAndExit (errorLevel):
		print (r'''
===============================================================================
{0} will obfuscate your extensive, real world, multi module Python source code for free!
And YOU choose per project what to obfuscate and what not, by editting the config file.

- BACKUP YOUR CODE AND VALUABLE DATA TO AN OFF-LINE MEDIUM FIRST TO PREVENT ACCIDENTAL LOSS OF WORK!!!
Then copy the default config file to the source top directory <topdir> and run {0} from there.
It will generate an obfuscation directory <topdir>/../<topdir>_{1}

- At first some identifiers may be obfuscated that shouldn't be, e.g. some of those imported from external modules.
Adapt your config file to avoid this, e.g. by adding external module names that will be recursively scanned for identifiers.
You may also exclude certain words or files in your project from obfuscation explicitly.

- Source directory, obfuscation directory and config file path can also be supplied as command line parameters.
The config file path should be something like C:/config_files/opy.cnf, so including the file name and extension.
opy [<source directory> [<target directory> [<config file path>]]]

- Comments and string literals can be marked as plain, bypassing obfuscation
Be sure to take a look at the comments in the config file opy_config.txt to discover all features.

Known limitations:

- A comment after a string literal should be preceded by whitespace
- A ' or " inside a string literal should be escaped with \ rather then doubled
- If the pep8Comments option is False (the default), a {2} in a string literal can only be used at the start, so use 'p''{2}''r' rather than 'p{2}r'
- If the pep8Comments option is set to True, however, only a <blank><blank>{2}<blank> cannot be used in the middle or at the end of a string literal
- Obfuscation of string literals is unsuitable for sensitive information since it can be trivially broken
- No renaming backdoor support for methods starting with __ (non-overridable methods, also known as private methods)

Licence:
{3}
===============================================================================

		'''.format (programName.capitalize (), programName, r'#', license))
		if errorLevel is not None: exit (errorLevel)
		
	# ============ Assign directories ============

	isLibraryConfig = False
	if isLibraryInvoked:
		# Use library settings 
		if settings.printHelp: printHelpAndExit(None)                   
					
		if settings.sourceRootDirectory is not None:                    
			sourceRootDirectory = settings.sourceRootDirectory.replace ('\\', '/')
		else:
			sourceRootDirectory = os.getcwd () .replace ('\\', '/')

		if settings.targetRootDirectory is not None:
			targetRootDirectory = settings.targetRootDirectory.replace ('\\', '/')
		else:
			targetRootDirectory = '{0}/{1}_{2}'.format (* (sourceRootDirectory.rsplit ('/', 1) + [programName]))

		if settings.configFilePath==False :
			isLibraryConfig = True    
			configFilePath = ""
		elif settings.configFilePath is not None:
			configFilePath = settings.configFilePath.replace ('\\', '/')
		else:
			configFilePath = '{0}/{1}_config.txt'.format (sourceRootDirectory, programName)    
	else:
		# Use command line arguments
		if len (sys.argv) > 1:
			for switch in '?', '-h', '--help':
				if switch in sys.argv [1]:
					printHelpAndExit (0)
			sourceRootDirectory = sys.argv [1] .replace ('\\', '/')
		else:
			sourceRootDirectory = os.getcwd () .replace ('\\', '/')

		if len (sys.argv) > 2:
			targetRootDirectory = sys.argv [2] .replace ('\\', '/')
		else:
			targetRootDirectory = '{0}/{1}_{2}'.format (* (sourceRootDirectory.rsplit ('/', 1) + [programName]))

		if len (sys.argv) > 3:
			configFilePath = sys.argv [3] .replace ('\\', '/')
		else:
			configFilePath = '{0}/{1}_config.txt'.format (sourceRootDirectory, programName)
			
	# =========== Read config file

	if isLibraryConfig:
		configFile = settings.configSettings.toVirtualFile()
	else :        
		try:
			configFile = open (configFilePath)
		except Exception as exception:
			print (exception)
			printHelpAndExit (1)
		
	exec (configFile.read ())
	configFile.close ()
	
	def getConfig (parameter, default):
		try:
			return eval (parameter)
		except:
			return default
	
	obfuscateStrings = getConfig ('obfuscate_strings', True)
	obfuscatedNameTail = getConfig ('obfuscated_name_tail', '_{}_')
	plainMarker = getConfig ('plain_marker', '_{}_'.format (programName))
	pep8Comments = getConfig ('pep8_comments', False)
	sourceFileNameExtensionList = getConfig ('source_extensions.split ()', ['py', 'pyx'])
	skipFileNameExtensionList = getConfig ('skip_extensions.split ()', ['pyc'])
	skipPathFragmentList = getConfig ('skip_path_fragments.split ()', [])
	externalModuleNameList = getConfig ('external_modules.split ()', [])
	maskExternalModules = getConfig ('mask_external_modules', True)
	skipPublicIdentifiers = getConfig ('skip_public', False)
	plainFileRelPathList = getConfig ('plain_files.split ()', [])
	extraPlainWordList = getConfig ('plain_names.split ()', [])
	dryRun = getConfig ('dry_run', False)
	preppedOnly = getConfig ('prepped_only', False)
	subsetFilesList = getConfig ('subset_files.split ()', [])

	# OPY2
	skipFilesList = getConfig ('skip_files', '') .split ()
	obfuscateNumbers = getConfig ('obfuscate_numbers', True)
	obfuscationLetters = getConfig ('obfuscation_letters', '')
	stringsExceptionsFileRelPathList = getConfig ('strings_exception_files', '') .split ()
	numbersExceptionsFileRelPathList = getConfig ('numbers_exception_files', '') .split ()
	anyExternalModulesList = getConfig ('any_external_modules.split ()', [])
	obfuscateSize_FoldersFiiles = getConfig ('foldersfiles_names_obfuscate_size', 5)
	obfuscationMinimumSize_Words = getConfig ('words_obfuscation_minimum_size', 5)
	obfuscationMaximumSize_Words = getConfig ('words_obfuscation_maximum_size', 10)
	obfuscateNames_FoldersFiles = getConfig ('obfuscate_foldersfiles_names', True)
	forceObfuscateWordsList = getConfig ('force_obfuscate_words.split ()', [])

	# OPY2
	if not obfuscationLetters: obfuscationLetters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
	obfuscationLetters = ''.join(set(obfuscationLetters))         # remove duplicated characters
	obfuscationLettersCount = len(obfuscationLetters)
	lettersCount = len(filter(str.isalpha,obfuscationLetters))    # keep only letters and remove anything else
	digitsCount = len(filter(str.isdigit,obfuscationLetters))     # keep only digits and remove anything else

	# OPY2
	if obfuscationLettersCount<2 or not lettersCount or lettersCount+digitsCount<obfuscationLettersCount:
		print('\nError:  Wrong obfuscation letters !!\n\n')
		sys.exit()

	# OPY2
	if not 2<=obfuscationMinimumSize_Words<=300 or not 2<=obfuscationMaximumSize_Words<=300 or obfuscationMaximumSize_Words<obfuscationMinimumSize_Words:
		print('\nError:  Wrong obfuscation words size !!\n\n')
		sys.exit()
	if not 2<=obfuscateSize_FoldersFiiles<=60:
		print('\nError:  Wrong obfuscation filename size !!\n\n')
		sys.exit()
	if not plainMarker: plainMarker = '_{}_'.format (programName)
	
	# OPY2
	obfuscationLettersEnlarged = ''
	for iii in range(obfuscationMaximumSize_Words//obfuscationLettersCount+1):
		obfuscationLettersEnlarged += obfuscationLetters
	obfuscationLettersEnlargedList = [jjj for jjj in obfuscationLettersEnlarged]
	
	# OPY2
	# Needed by the unscrambler
	if (obfuscateNumbers or obfuscateStrings) and 'version_info' not in extraPlainWordList:
		extraPlainWordList.append('version_info')
		
	#TODO: Handle spaces between key/colon/value, e.g. 'key : value'     
	replacementModulesDict = {}
	replacementModulesPairList = getConfig ('replacement_modules.split ()', [])
	for pair in replacementModulesPairList:
		pairParts = pair.split(":") 
		try: replacementModulesDict[ pairParts[0].strip() ]= pairParts[1].strip()
		except: continue        
		
	# ============ Gather source file names

	rawSourceFilePathList = [
		'{0}/{1}'.format (directory.replace ('\\', '/'), fileName)
		for directory, subDirectories, fileNames in os.walk (sourceRootDirectory)
		for fileName in fileNames
	]
	
	def hasSkipPathFragment (sourceFilePath):
		for skipPathFragment in skipPathFragmentList:
			if skipPathFragment in sourceFilePath:
				return True
		return False
	
	sourceFilePathList = [sourceFilePath for sourceFilePath in rawSourceFilePathList if not hasSkipPathFragment (sourceFilePath)]

	if len(subsetFilesList) > 0 :        
		def inSubsetFilesList( sourceFilePath ):
			if sourceFilePath in subsetFilesList : return True
			baseName = os.path.basename( sourceFilePath )
			if baseName in subsetFilesList : return True
			return False
		sourceFilePathList = [sourceFilePath for sourceFilePath in sourceFilePathList if inSubsetFilesList (sourceFilePath)]

	# =========== Define comment swapping tools
			
	shebangCommentRegEx = re.compile (r'^{0}!'.format (r'#'))
	codingCommentRegEx = re.compile ('coding[:=]\s*([-\w.]+)')
	keepCommentRegEx = re.compile ('.*{0}.*'.format (plainMarker), re.DOTALL)
		
	def getCommentPlaceholderAndRegister (matchObject):
		comment = matchObject.group (0)
		if keepCommentRegEx.search (comment):   # Rare, so no need for speed
			replacedComments.append (comment.replace (plainMarker, ''))
			return commentPlaceholder
		else:
			return ''
		
	def getComment (matchObject):
		global commentIndex
		commentIndex += 1
		return replacedComments [commentIndex]
		
	commentRegEx = (
			re.compile (r'{0}{1}{2}.*?$'.format (
				r"(?<!')",
				r'(?<!")',
				r'  # '  # According to PEP8 an inline comment should start like this.
			), re.MULTILINE)
		if pep8Comments else  # @UndefinedVariable
			re.compile (r'{0}{1}{2}.*?$'.format (
				r"(?<!')",
				r'(?<!")',
				r'#'
			), re.MULTILINE)
	)
	commentPlaceholder = '_{0}_c_'.format (programName)
	commentPlaceholderRegEx = re.compile (r'{0}'.format (commentPlaceholder))

	# ============ Define string swapping tools

	keepStringRegEx = re.compile (r'.*{0}.*'.format (plainMarker))
		
	def getDecodedStringPlaceholderAndRegister (matchObject):
		string = matchObject.group (0)
		if obfuscateStringsOfThisFile:
			if keepStringRegEx.search (string): # Rare, so no need for speed
				replacedStrings.append (string.replace (plainMarker, ''))
				return stringPlaceholder    # Store original string minus plainMarker, no need to unscramble
			else:
				replacedStrings.append (scramble (string))

				# OPY2
				return u'unScramble{0}({1})'.format (random.randrange(33),stringPlaceholder)    # Store unScramble (<scrambledString>)
		
		else:
			replacedStrings.append (string)
			return stringPlaceholder
		
	def getString (matchObject):
		global stringIndex
		stringIndex += 1
		return replacedStrings [stringIndex]

	stringRegEx = re.compile (r'([ru]|ru|ur|[rb]|rb|br)?(({0})|({1})|({2})|({3}))'.format (
		r"'''.*?(?<![^\\]\\)(?<![^\\]\')'''",
		r'""".*?(?<![^\\]\\)(?<![^\\]\")"""',
		r"'.*?(?<![^\\]\\)'",
		r'".*?(?<![^\\]\\)"'
	), re.MULTILINE | re.DOTALL | re.VERBOSE)

	stringPlaceholder = '_{0}_s_'.format (programName)
	stringPlaceholderRegEx = re.compile (r'{0}'.format (stringPlaceholder))

	# ============ Define 'from future' moving tools

	def moveFromFuture (matchObject):
		fromFuture = matchObject.group (0)

		if fromFuture:
			global nrOfSpecialLines
			contentList [nrOfSpecialLines:nrOfSpecialLines] = [fromFuture]  # Move 'from __future__' line after other special lines
			nrOfSpecialLines += 1
		return ''
		
	fromFutureRegEx = re.compile ('from\s*__future__\s*import\s*\w+.*$', re.MULTILINE)

	# ============ Define identifier recognition tools

	identifierRegEx = re.compile (r'''
		\b          # Delimeted
		(?!{0})     # Not starting with commentPlaceholder
		(?!{1})     # Not starting with stringPlaceholder
		[^\d\W]     # De Morgan: Not (decimal or nonalphanumerical) = not decimal and alphanumerical
		\w*         # Alphanumerical
		(?<!__)     # Not ending with __
		(?<!{0})    # Not ending with commentPlaceholder
		(?<!{1})    # Not ending with stringPlaceHolder
		\b          # Delimited
	'''.format (commentPlaceholder, stringPlaceholder), re.VERBOSE) # De Morgan

	chrRegEx = re.compile (r'\bchr\b')

	# =========== Generate skip list

	skipWordSet = set (keyword.kwlist + ['__init__'] + extraPlainWordList)  # __init__ should be in, since __init__.py is special
	if not isPython2: skipWordSet.update( ['unicode', 'unichr' ] ) # not naturally kept in clear text when obfuscation is produced in Python 3

	rawPlainFilePathList = ['{0}/{1}'.format (sourceRootDirectory, plainFileRelPath.replace ('\\', '/')) for plainFileRelPath in plainFileRelPathList]
	
	# Prevent e.g. attempt to open opy_config.txt if it is in a different location but still listed under plain_files
	
	plainFilePathList = [plainFilePath for plainFilePath in rawPlainFilePathList if os.path.exists (plainFilePath)]
	
	for plainFilePath in plainFilePathList:
		plainFile = open (plainFilePath)
		content = plainFile.read ()
		plainFile.close ()
		
		# Throw away comment-like line tails
		
		content = commentRegEx.sub ('', content)
		
		# Throw away strings
		
		content = stringRegEx.sub ('', content)
		
		# Put identifiers in skip word set
		
		skipWordSet.update (re.findall (identifierRegEx, content))
		
	class ExternalModules:
		def __init__ (self):
			for externalModuleName in externalModuleNameList:
				attributeName = externalModuleName.replace ('.', plainMarker)   # Replace . in module name by placeholder to get attribute name
				
				try:
					exec (
						'''
import {0} as currentModule
						'''.format (externalModuleName),
						globals ()
					)
					setattr (self, attributeName, currentModule)    # @UndefinedVariable
				except Exception as exception:
					print (exception)
					setattr (self, attributeName, None) # So at least the attribute name will be available
					print ('Warning: could not inspect external module {0}'.format (externalModuleName))
				
	externalModules = ExternalModules ()
	externalObjects = set ()
				
	def addExternalNames (anObject):
		if anObject in externalObjects:
			return
		else:
			externalObjects.update ([anObject])

		try:
			attributeNameList = list (anObject.__dict__)
		except:
			attributeNameList = []
		
		try:
			if isPython2:
				parameterNameList = list (anObject.func_code.co_varnames)
			else:
				parameterNameList = list (anObject.__code__.co_varnames)
		except:     
			parameterNameList = []
			
		attributeList = [getattr (anObject, attributeName) for attributeName in attributeNameList]
		attributeSkipWordList = (plainMarker.join (attributeNameList)) .split (plainMarker) # Split module name chunks that were joined by placeholder
		
		updateSet = set ([entry for entry in (parameterNameList + attributeSkipWordList) if not (entry.startswith ('__') and entry.endswith ('__'))])
		# Entries both starting and ending with __ are skipped anyhow by the identifier regex, not including them here saves time
		
		skipWordSet.update (updateSet)
		
		for attribute in attributeList: 
			try:
				addExternalNames (attribute)
			except:
				pass


	addExternalNames (__builtin__ if isPython2 else builtins) 
	addExternalNames (externalModules)

	skipWordList = list (skipWordSet)
	skipWordList.sort (key = lambda s: s.lower ())

	# ============ Generate obfuscated files

	obfuscatedFileDict = {}
	obfuscatedWordList = []
	obfuscatedRegExList = []
	skippedPublicSet=set()

	"""
	# OPY2
	# Find components of any modules listed in "any_external_modules" in "opy_config.txt"
	# fails for some attributes
	def collect_attributes_from_source_files_re_findall(content):
		attribs1,attribs2,attribs3,attribs4,attribs5,attribs6 = [],[],[],[],[],[]
		parenthesisRegex = r"(?P<expression>\(([^()]*(?P<parenthesis>\()(?(parenthesis)[^()]*\)))*?[^()]*\))"
		# find "mod.xyz"
		for module in anyModules:
			attribs1 += re.findall(module+'[\t\s]*\.[\t\s]*(.+?)[  \s  \t  \(  \)  \[  \+  \-  \=  \:  \.  ]+',content)
		#print;print(1,attribs1)
		# find "from mod import xyz,xyz"
		for module in anyModules:
			strings = re.findall('from[\t\s]+'+module+'[\t\s]+import[\t\s]+(.+?)[\t\s]*[$\r\n]',content+'\n')
			for string in strings:
				for anImport in string.split(','):
					attrib = re.findall('[\t\s]*(.*?)[\t\s]+as',anImport)
					if not attrib: attrib = [anImport]
					attribs2 += attrib
		#print;print(2,attribs2)
		# find subcomponents strings
		for attrib in set(attribs1+attribs2):
			attrib = attrib.strip(')')
			try: attribs = re.findall(attrib+'[\t\s]*'+parenthesisRegex+'*[\t\s]*\.(.*?)[\t\s\n\r]',content)
			except:
				attribs = []
				print(attrib)
			for attrib in attribs:
				attribs3 += list(attrib)
		attribs3 += attribs1+attribs2
		#print;print(3,attribs3)
		# split strings to subcomponents
		for attribs in set(attribs3):
			attribs4 += list(attribs.split('.'))
		#print;print(4,attribs4)
		# clean subcomponents
		for attrib in set(attribs4):
			attribs = re.findall('\w+',attrib)
			if attribs: attribs5.append(attribs[0])
		#print;print(5,attribs5)
		for attrib in set(attribs5):
			attribs6 += re.findall(attrib+'[\t\s]*.*?[\(\,]+[\t\s]*(\w+)[\t\s]*\=',content)
		attribs6 += attribs5
		#print;print(6,attribs6)
		return set(attribs6)
	"""

	# OPY2
	# Find components of any modules listed in "any_external_modules" in "opy_config.txt"
	def analyze_source_file_using_ast(sourceFilePath):
		sourceFile = codecs.open (sourceFilePath, encoding = 'utf-8')
		content = sourceFile.read () 
		sourceFile.close ()
		try: content = content.encode('utf8','ignore')
		except: pass
		content = ast.parse(content)
		content = ast.dump(content)
		attribs1 = re.findall("attr='(.*?)'",content)
		attribs2 = re.findall("alias\(name='(.*?)'",content)
		attribs3 = []
		for attrib in attribs2: attribs3 += attrib.split('.')
		arguments = re.findall("arg='(.*?)'",content)
		modules = re.findall("ImportFrom\(module='(.*?)'",content)
		imports = re.findall('Import\(names=\[(.*?)\]',content)
		for imp in imports: modules += re.findall("name='(.*?)'",imp)
		identifiers = re.findall("Name\(id='(.*?)'",content)
		return set(attribs1+attribs2+attribs3),set(arguments),set(modules),set(identifiers)

	# OPY2
	lastprint = 0
	sourceFilePathListFiltered = []
	sourceFilePreNameLIST = []
	allAttribs,allArguments,allIdentifiers,allExternalModules = [],[],[],[]

	# OPY2
	# Collect external modules names, modules attributes identifiers, and functions arguments identifiers
	print('1. Analyzing all python source files')
	print
	for sourceFilePath in sourceFilePathList:
		if sourceFilePath == configFilePath: continue
		sourceDirectory, sourceFileName = sourceFilePath.rsplit ('/', 1)
		if sourceFileName in skipFilesList: continue
		sourceFilePreName, sourceFileNameExtension = (sourceFileName.rsplit ('.', 1) + ['']) [ : 2]
		if sourceFileNameExtension in sourceFileNameExtensionList and not sourceFilePath in plainFilePathList:
			attribs,arguments,modules,identifiers = analyze_source_file_using_ast(sourceFilePath)
			sourceFilePathListFiltered.append(sourceFilePath)
			sourceFilePreNameLIST.append(sourceFilePreName)
			allAttribs += attribs
			allArguments += arguments
			allIdentifiers += identifiers
			allExternalModules += modules
	allExternalModules = list(set(allExternalModules).difference(sourceFilePreNameLIST))
	skipWordSet.update(allAttribs+allArguments+allExternalModules)
	externalModuleNameList += allExternalModules
	print('{0: >24}  :  {1}'.format('Files found',len(sourceFilePreNameLIST)))
	print('{0: >24}  :  {1}'.format('External modules found',len(allExternalModules)))
	print('{0: >24}  :  {1}'.format('Attributes found',len(allAttribs)))
	print('{0: >24}  :  {1}'.format('Arguments found',len(allArguments)))
	print('{0: >24}  :  {1}'.format('Identifiers found',len(allIdentifiers)))
	print

	# OPY2
	available = (obfuscationLettersCount**obfuscationMaximumSize_Words)//2
	if available<len(allIdentifiers):
		print('Wrong settings in "opy_config.txt" file')
		print('Available obfuscation words is not enough:  '+str(available))
		print('You need to increase  "Obfuscation Letters"  and/or  "Obfuscation Words Maximum Size"')
		print
		sys.exit()

	# OPY2
	available = (obfuscationLettersCount**obfuscateSize_FoldersFiiles)//2
	if available<len(sourceFilePreNameLIST):
		print('Wrong settings in "opy_config.txt" file')
		print('Available obfuscation words is not enough:  '+str(available))
		print('You need to increase  "Obfuscation Letters"  and/or  "Obfuscation folders & files names size"')
		print
		sys.exit()

	# OPY2
	if not obfuscateNames_FoldersFiles: skipWordSet.update(sourceFilePreNameLIST)
	for sourceFilePreName in sourceFilePreNameLIST: obfname = getObfuscatedName(sourceFilePreName,True)

	# OPY2
	# Read contents of section "any_external_modules" in "opy_config.txt" file
	print('2. Collecting settings from settings file "opy_config.txt"')
	print
	anyModules,anyAttribs = [],[]
	for line in anyExternalModulesList:
		if line.strip(' ').strip('\t').startswith('#'): continue
		line = line.replace(' ','').replace('\t','')
		if ':' in line: module,attribs = line.split(':',1)
		else: module,attribs = line,''
		if ',' in attribs: attribs = attribs.split(',')
		elif attribs: attribs = [attribs]
		else: attribs = []
		anyAttribs += attribs
		anyModules.append(module)
	skipWordSet = set(list(skipWordSet)+anyAttribs+anyModules)
	externalModuleNameList = set(externalModuleNameList+anyModules)

	# OPY2
	# Force obfuscation of words listed in section "force_obfuscate_words" in "opy_config.txt" file
	skipWordSet = set(skipWordSet).difference(forceObfuscateWordsList)
	print('3. Processing all python source files')
	print

	for sourceFilePath in sourceFilePathListFiltered:
		sourceDirectory, sourceFileName = sourceFilePath.rsplit ('/', 1)
		sourceFilePreName, sourceFileNameExtension = (sourceFileName.rsplit ('.', 1) + ['']) [ : 2]
		targetRelSubDirectory = sourceFilePath [len (sourceRootDirectory) : ]
		clearRelPath = targetRelSubDirectory[1:] # remove leading /
				
		# Read plain source

		if sourceFileNameExtension in sourceFileNameExtensionList and not sourceFilePath in plainFilePathList:
			stringBase = random.randrange (64)
		
			sourceFile = codecs.open (sourceFilePath, encoding = 'utf-8')
			content = sourceFile.read () 
			sourceFile.close ()


			if skipPublicIdentifiers:
				skippedPublicSet.update( opy_parser.findPublicIdentifiers( content ) )
				skipWordSet.update( skippedPublicSet )   

			# OPY2
			# Decide if strings and/or numbers should be obfuscated in this file
			global obfuscateStringsOfThisFile
			obfuscateStringsOfThisFile = obfuscateStrings and sourceFileName not in stringsExceptionsFileRelPathList
			obfuscateNumbersOfThisFile = obfuscateNumbers and sourceFileName not in numbersExceptionsFileRelPathList
			addScrambler = obfuscateStringsOfThisFile or obfuscateNumbersOfThisFile

			replacedComments = []
			contentList = content.split ('\n', 2)
				
			nrOfSpecialLines = 0
			insertCodingComment = True
			
			if len (contentList) > 0:
				if shebangCommentRegEx.search (contentList [0]):                                # If the original code starts with a shebang line
					nrOfSpecialLines += 1                                                       #   Account for that
					if len (contentList) > 1 and codingCommentRegEx.search (contentList [1]):   #   If after the shebang a coding comment follows
						nrOfSpecialLines += 1                                                   #       Account for that
						insertCodingComment = False                                             #       Don't insert, it's already there
				elif codingCommentRegEx.search (contentList [0]):                               # Else if the original code starts with a coding comment
					nrOfSpecialLines += 1                                                       #   Account for that
					insertCodingComment = False                                                 #   Don't insert, it's already there
				
			if addScrambler and insertCodingComment:                                            # Obfuscated strings are always converted to unicode
				contentList [nrOfSpecialLines:nrOfSpecialLines] = ['# coding: UTF-8']           # Insert the coding line if it wasn't there
				nrOfSpecialLines += 1                                                           # And remember it's there
																								# Nothing has to happen with an eventual shebang line
			if addScrambler:
				normalContent = '\n'.join ([getUnScrambler (stringBase)] + contentList [nrOfSpecialLines:])
			else:
				normalContent = '\n'.join (contentList [nrOfSpecialLines:])
				
			# At this point normalContent does not contain the special lines
			# They are in contentList
			
			normalContent = commentRegEx.sub (getCommentPlaceholderAndRegister, normalContent)
			 
			# Replace strings by string placeholders
			
			replacedStrings = []
			normalContent = stringRegEx.sub (getDecodedStringPlaceholderAndRegister, normalContent)
			
			# Take eventual out 'from __future__ import ... ' line and add it to contentlist
			# Content list is prepended to normalContent later
			
			normalContent = fromFutureRegEx.sub (moveFromFuture, normalContent)

			# Replace any imported modules per the old/new (key/value) pairs provided
			if len(replacementModulesDict) > 0 : 
				normalContent = opy_parser.replaceImports( normalContent, replacementModulesDict )
								
			# Parse content to find imports and optionally provide aliases for those in clear text,
			# so that they will become "masked" upon obfuscation.
			if maskExternalModules : 
				normalContent = opy_parser.injectAliases( normalContent, externalModuleNameList )
			else:  
				opy_parser.analyzeImports( normalContent, externalModuleNameList )

			# OPY2
			# Obfuscate numbers
			if obfuscateNumbersOfThisFile:
				skipWordSet.update('u')
				numbersPlaceholder = '_{0}_n_'.format(programName)
				normalContent = re.sub(r'\b(\d+\.*\d*)\b',r'{0}(\1)'.format(numbersPlaceholder),normalContent)
				lines = []
				for line in normalContent.splitlines():
					comment = re.findall('^[\t\s]*(\#.*?)$',line)
					plainNumbers = re.findall(numbersPlaceholder+'\((\d+\.*\d*)\)'+plainMarker,line)
					lineNumbers = re.findall(numbersPlaceholder+'\((\d+\.*\d*)\)',line)
					for number in lineNumbers:
						marker = ''
						if 0 and number in plainNumbers: replacement,marker = number,plainMarker
						elif comment: replacement = getObfuscatedName(str(number))
						else: replacement = u'unScramble{0}({1})'.format(random.randrange(33),scramble(number))
						line = line.replace(numbersPlaceholder+'('+number+')'+marker,replacement)
					lines.append(line)
				normalContent = '\n'.join(lines)
			normalContent = re.sub(r'\b(\d+\.*\d*)'+plainMarker+r'\b',r'\1',normalContent)

			if not preppedOnly :
				# Obfuscate content without strings
				
				# All source words and module name
				sourceWordSet = set (re.findall (identifierRegEx, normalContent) + [sourceFilePreName])
				
				# Add source words that are not yet obfuscated and shouldn't be skipped to global list of obfuscated words, preserve order of what's already there
				strippedSourceWordSet = sourceWordSet.difference (obfuscatedWordList).difference (skipWordSet)  # Leave out what is already or shouldn't be obfuscated
				strippedSourceWordList = list (strippedSourceWordSet)
				strippedSourceRegExList = [re.compile (r'\b{0}\b'.format (sourceWord)) for sourceWord in strippedSourceWordList]    # Regex used to replace obfuscated words
				obfuscatedWordList += strippedSourceWordList            
				obfuscatedRegExList += strippedSourceRegExList

				# Replace words to be obfuscated by obfuscated ones
				for obfuscationIndex, obfuscatedRegEx in enumerate (obfuscatedRegExList):
					normalContent = obfuscatedRegEx.sub (
						getObfuscatedName ( obfuscatedWordList [obfuscationIndex]),    # OPY2
						normalContent
					)   # Use regex to prevent replacing word parts

			# Replace string placeholders by strings
			
			stringIndex = -1
			normalContent = stringPlaceholderRegEx.sub (getString, normalContent)
		
			# Replace nonempty comment placeholders by comments
			
			commentIndex = -1
			normalContent = commentPlaceholderRegEx.sub (getComment, normalContent)
			
			content = '\n'.join (contentList [:nrOfSpecialLines] + [normalContent])
			
			# Remove empty lines
			
			content = '\n'.join ([line for line in [line.rstrip () for line in content.split ('\n')] if line])
			
			if not obfuscateNames_FoldersFiles or preppedOnly:
				targetFilePreName = sourceFilePreName
				targetSubDirectory = '{0}{1}'.format (targetRootDirectory, targetRelSubDirectory) .rsplit ('/', 1) [0]
			else :                     
				# Obfuscate module name

				# OPY2
				targetFilePreName = sourceFilePreName
				if obfuscateNames_FoldersFiles:
					try: targetFilePreName = getObfuscatedName(sourceFilePreName,True)
					except: pass
				
				# Obfuscate module subdir names, but only above the project root!
				targetChunks = targetRelSubDirectory.split ('/')
				for index in range (len (targetChunks)):
					
					# OPY2
					if not index: targetChunks[index] = ''
					else:
						try:
							targetChunks [index] = getObfuscatedName(str(index),True)
						except: # Not in list
							pass

				targetRelSubDirectory = '/'.join (targetChunks)
				targetSubDirectory = '{0}{1}'.format (targetRootDirectory, targetRelSubDirectory) .rsplit ('/', 1) [0]

			# Create target path and track it against clear text relative source                       
			obfusPath = '{0}/{1}.{2}'.format (targetSubDirectory, targetFilePreName, sourceFileNameExtension)
			obfuscatedFileDict[clearRelPath] = obfusPath

			# OPY2
			timeElapsed = time.time()-timeStart+1
			print('  {2:3}.  {0:5.1f}  sec  :  {1}'.format(timeElapsed-lastprint,clearRelPath,len(obfuscatedFileDict)))
			lastprint = timeElapsed

			# Bail before the actual path / file creation on a dry run 
			if dryRun : continue

			# Create target path and write file                        
			targetFile = createFilePath (obfusPath, open = True)
			targetFile.write (content)
			targetFile.close ()
		elif (not dryRun) and (not sourceFileNameExtension in skipFileNameExtensionList):
			targetSubDirectory = '{0}{1}'.format (targetRootDirectory, targetRelSubDirectory) .rsplit ('/', 1) [0]
			
			# Create target path and copy file
			targetFilePath = '{0}/{1}'.format (targetSubDirectory, sourceFileName)
			createFilePath (targetFilePath)
			shutil.copyfile (sourceFilePath, targetFilePath)

	if 0:
		print
		print ('Obfuscated files:  {0}'.format ( (obfuscatedFileDict)))
		print
		print
		print ('Obfuscated words:  {0}'.format ( (obfuscatedWordList)))
		print
		print
		print ('Obfuscated module imports:  {0}'.format ( (opy_parser.obfuscatedModImports)))
		print
		print
		print ('Masked identifier imports:  {0}'.format ( (opy_parser.maskedIdentifiers)))
		print
		print
		print ('Skipped public identifiers:  {0}'.format ( (skippedPublicSet)))
		print
		print
		print ('Time Elapsed:  {0} sec'.format ( int (timeFinish-timeStart) ))
	else:
		print
		print('{0: >28}  :  {1}'.format('Obfuscated files',len(obfuscatedFileDict)))
		print('{0: >28}  :  {1}'.format('Obfuscated words',len(obfuscatedWordList)))
		print('{0: >28}  :  {1}'.format('Obfuscated module imports',len(opy_parser.obfuscatedModImports)))
		print('{0: >28}  :  {1}'.format('Masked identifier imports',len(opy_parser.maskedIdentifiers)))
		print('{0: >28}  :  {1}'.format('Skipped public identifiers',len(skippedPublicSet)))
		print('{0: >28}  :  {1} sec'.format('Time Elapsed',int(timeElapsed)))
	print



	# Opyfying something twice can and is allowed to fail.
	# The obfuscation for e.g. variable 1 in round 1 can be the same as the obfuscation for e.g. variable 2 in round 2.
	# If in round 2 variable 2 is replaced first, the obfuscation from round 1 for variable 1 will be replaced by the same thing.
	
