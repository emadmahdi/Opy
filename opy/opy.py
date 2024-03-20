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
Version:  OPY2.2024.03.19
EMAD MAHDI

Please feel free to report any errors or suggest new features:
	http://github.com/emadmahdi/opy2
==============================================
''')

# OPY2
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
__version__ = "OPY2.2024.03.19"

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

		# OPY2
		# To allow scrambling of more strings/numbers/booleans
		# And allow bigger projects to be scrambled properly
		if stringNr==8192: stringNr = charBase
		
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
import sys
isPython2{0} = sys.version_info [0{0}] == 2{0}
charBase{0} = {1}{0}
charModulus{0} = {2}{0}

def unScramble{0} (keyedStringLiteral):
	global stringNr{0}
	
	stringNr = ord (keyedStringLiteral [-1{0}])
	rotatedStringLiteral = keyedStringLiteral [:-1{0}]
	
	rotationDistance = stringNr % len (rotatedStringLiteral)
	recodedStringLiteral = rotatedStringLiteral [:rotationDistance] + rotatedStringLiteral [rotationDistance:]
		
	if isPython2{0}:
		stringLiteral = unicode () .join ([unichr (ord (char) - charBase{0} - (charIndex + stringNr) % charModulus{0}) for charIndex, char in enumerate (recodedStringLiteral)])
	else:
		stringLiteral = str () .join ([chr (ord (char) - charBase{0} - (charIndex + stringNr) % charModulus{0}) for charIndex, char in enumerate (recodedStringLiteral)])

	return eval (stringLiteral)

unScramble0{0},unScramble1{0},unScramble2{0}=unScramble{0},unScramble{0},unScramble{0}
unScramble3{0},unScramble4{0},unScramble5{0}=unScramble2{0},unScramble1{0},unScramble0{0}
unScramble6{0},unScramble7{0},unScramble8{0}=unScramble5{0},unScramble4{0},unScramble3{0}
unScramble9{0},unScramble10{0},unScramble11{0}=unScramble8{0},unScramble7{0},unScramble6{0}
unScramble12{0},unScramble13{0},unScramble14{0}=unScramble11{0},unScramble10{0},unScramble9{0}
unScramble15{0},unScramble16{0},unScramble17{0}=unScramble14{0},unScramble13{0},unScramble12{0}
unScramble18{0},unScramble19{0},unScramble20{0}=unScramble17{0},unScramble16{0},unScramble15{0}
unScramble21{0},unScramble22{0},unScramble23{0}=unScramble20{0},unScramble19{0},unScramble18{0}
unScramble24{0},unScramble25{0},unScramble26{0}=unScramble23{0},unScramble22{0},unScramble21{0}
unScramble27{0},unScramble28{0},unScramble29{0}=unScramble26{0},unScramble25{0},unScramble24{0}
unScramble30{0},unScramble31{0},unScramble32{0}=unScramble29{0},unScramble28{0},unScramble27{0}
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
	obfuscateBooleans = getConfig ('obfuscate_booleans', True)
	obfuscationLetters = getConfig ('obfuscation_letters', '')
	stringsExceptionsFileRelPathList = getConfig ('strings_exception_files', '') .split ()
	numbersExceptionsFileRelPathList = getConfig ('numbers_exception_files', '') .split ()
	booleansExceptionsFileRelPathList = getConfig ('booleans_exception_files', '') .split ()
	anyExternalModulesList = getConfig ('any_external_modules.split ()', [])
	obfuscateSize_FoldersFiiles = getConfig ('filesfolders_names_obfuscate_size', 5)
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
				return 'unScramble{0}{1}({2})'.format(random.randrange(33),plainMarker,stringPlaceholder)    # Store unScramble (<scrambledString>)

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

	# OPY2
	# Find components of any modules listed in "any_external_modules" in "opy_config.txt"
	def analyze_all_source_files_using_ast(sourceFilePathListFiltered):
		allAttribs,allArguments,allIdentifiers,allExternalModules,allFunctions = [],[],[],[],[]
		for sourceFilePath in sourceFilePathListFiltered:
			sourceFile = codecs.open (sourceFilePath, encoding = 'utf-8')
			contents = sourceFile.read () 
			sourceFile.close ()
			try: contents = contents.encode('utf8','ignore')
			except: pass
			contents = ast.parse(contents)
			#open('s:\\'+sourceFilePath.rsplit('/',1)[1]+'.txt','w').write(ast.dump(contents))
			block = ast.dump(contents)
			froms = re.findall("ImportFrom\(module='(.*?)', names=\[(.*?)\]",block)
			for module,attribs in froms:
				if module.split('.')[0] in sourceFilePreNameLIST: continue
				allExternalModules += [module]+module.split('.')
				allAttribs += re.findall("alias\(name='(.*?)'",attribs)
			imports = re.findall("Import\(names=\[(.*?)\]",block)
			for imp in imports:
				modules = re.findall("alias\(name='(.*?)'",imp)
				for module in modules:
					if module.split('.')[0] in sourceFilePreNameLIST: continue
					allExternalModules += [module]+module.split('.')
			allAttribs += re.findall("attr='(.*?)'",block)
			allFunctions += re.findall("FunctionDef\(name='(.*?)'",block)
			allArguments += re.findall("arg='(.*?)'",block)
			allIdentifiers += re.findall("Name\(id='(.*?)'",block)
		allAttribs = list(set(allAttribs).difference(allFunctions))
		#if 'urllib_parse' in allAttribs: print('allAttribs: ',set(allAttribs))
		#if 'urllib_parse' in allArguments: print('allArguments: ',set(allArguments))
		#if 'urllib_parse' in allIdentifiers: print('allIdentifiers: ',set(allIdentifiers))
		#if 'urllib_parse' in allExternalModules: print('allExternalModules: ',set(allExternalModules))
		return allAttribs,allArguments,allIdentifiers,allExternalModules

	# OPY2
	lastprint = 0
	sourceFilePathListFiltered = []
	sourceFilePreNameLIST = []

	# OPY2
	print('1. Filtering python source files')
	print
	for sourceFilePath in sourceFilePathList:
		sourceDirectory, sourceFileName = sourceFilePath.rsplit ('/', 1)
		if sourceFileName in skipFilesList: continue
		sourceFilePreName, sourceFileNameExtension = (sourceFileName.rsplit ('.', 1) + ['']) [ : 2]
		if sourceFileNameExtension in sourceFileNameExtensionList and sourceFilePath not in plainFilePathList:
			sourceFilePathListFiltered.append(sourceFilePath)
			sourceFilePreNameLIST.append(sourceFilePreName)

	# OPY2
	# Collect external modules names, modules attributes identifiers, and functions arguments identifiers
	print('2. Analyzing python source files')
	print
	allAttribs,allArguments,allIdentifiers,allExternalModules = analyze_all_source_files_using_ast(sourceFilePathListFiltered)
	allExternalModules = list(set(allExternalModules).difference(sourceFilePreNameLIST))
	skipWordSet.update(allAttribs+allArguments+allExternalModules)
	skipWordSet = skipWordSet.difference(sourceFilePreNameLIST)
	if '__init__' in sourceFilePreNameLIST: skipWordSet.update(['__init__'])
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
		print('Available files/folders names is not enough:  '+str(available))
		print('You need to increase  "Obfuscation Letters"  and/or  "Obfuscation files/folders names size"')
		print
		sys.exit()

	# OPY2
	# Read contents of section "any_external_modules" in "opy_config.txt" file
	print('3. Collecting settings from settings file "opy_config.txt"')
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
	print('4. Processing python source files')
	print

	# OPY2
	if not obfuscateNames_FoldersFiles: skipWordSet.update(sourceFilePreNameLIST)
	for sourceFilePreName in sourceFilePreNameLIST: obfname = getObfuscatedName(sourceFilePreName,True)
	skipWordSet.update('u')   # needed for u""

	for sourceFilePath in sourceFilePathList:
		if sourceFilePath == configFilePath:    # Don't copy the config file to the target directory
			continue

		sourceDirectory, sourceFileName = sourceFilePath.rsplit ('/', 1)
		sourceFilePreName, sourceFileNameExtension = (sourceFileName.rsplit ('.', 1) + ['']) [ : 2]
		targetRelSubDirectory = sourceFilePath [len (sourceRootDirectory) : ]
		clearRelPath = targetRelSubDirectory[1:] # remove leading /
				
		# OPY2
		if sourceFileName in skipFilesList: continue

		# Read plain source

		if sourceFileNameExtension in sourceFileNameExtensionList and sourceFilePath not in plainFilePathList:
			stringBase = random.randrange (64)
		
			sourceFile = codecs.open (sourceFilePath, encoding = 'utf-8')
			content = sourceFile.read () 
			sourceFile.close ()

			if skipPublicIdentifiers:
				skippedPublicSet.update( opy_parser.findPublicIdentifiers( content ) )
				skipWordSet.update( skippedPublicSet )   

			# OPY2
			# Decide if strings and/or numbers and/or booleans should be obfuscated in this file
			global obfuscateStringsOfThisFile
			obfuscateStringsOfThisFile = (obfuscateStrings and sourceFileName not in stringsExceptionsFileRelPathList) or (not obfuscateStrings and sourceFileName in stringsExceptionsFileRelPathList)
			obfuscateNumbersOfThisFile = (obfuscateNumbers and sourceFileName not in numbersExceptionsFileRelPathList) or (not obfuscateNumbers and sourceFileName in numbersExceptionsFileRelPathList)
			obfuscateBooleansOfThisFile = (obfuscateBooleans and sourceFileName not in booleansExceptionsFileRelPathList) or (not obfuscateBooleans and sourceFileName in booleansExceptionsFileRelPathList)

			addScrambler = obfuscateStringsOfThisFile or obfuscateNumbersOfThisFile or obfuscateBooleansOfThisFile

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
				numbersPlaceholder = '_{0}_n_'.format(programName)
				normalContent = re.sub(r'\b(\d+\.*\d*)\b',r'{0}(\1)'.format(numbersPlaceholder),normalContent)
				lines = []
				for line in normalContent.splitlines():
					comment = re.findall('^[\t\s]*(\#.*?)$',line)
					#plainNumbers = re.findall(numbersPlaceholder+'\((\d+\.*\d*)\)'+plainMarker,line)
					lineNumbers = re.findall(numbersPlaceholder+'\((\d+\.*\d*)\)',line)
					for number in set(lineNumbers):
						marker = ''
						if 0 and number in plainNumbers: replacement,marker = number,plainMarker
						elif comment: replacement = getObfuscatedName(number)
						else: replacement = u'unScramble{0}{1}({2})'.format(random.randrange(33),plainMarker,scramble(number))
						line = line.replace(numbersPlaceholder+'('+number+')'+marker,replacement)
					lines.append(line)
				normalContent = '\n'.join(lines)
			normalContent = re.sub(r'\b(\d+\.*\d*)'+plainMarker+r'\b',r'\1',normalContent)

			# OPY2
			# Obfuscate booleans True/False
			if obfuscateBooleansOfThisFile:
				booleansPlaceholder = '_{0}_b_'.format(programName)
				normalContent = re.sub(r'\b(True|False)\b',r'{0}(\1)'.format(booleansPlaceholder),normalContent)
				lines = []
				for line in normalContent.splitlines():
					comment = re.findall('^[\t\s]*(\#.*?)$',line)
					#plainBooleans = re.findall(booleansPlaceholder+'\((True|False)\)'+plainMarker,line)
					lineBooleans = re.findall(booleansPlaceholder+'\((True|False)\)',line)
					for boolean in set(lineBooleans):
						marker = ''
						if 0 and boolean in plainBooleans: replacement,marker = boolean,plainMarker
						elif comment: replacement = getObfuscatedName(boolean)
						else: replacement = u'unScramble{0}{1}({2})'.format(random.randrange(33),plainMarker,scramble(boolean))
						line = line.replace(booleansPlaceholder+'('+boolean+')'+marker,replacement)
					lines.append(line)
				normalContent = '\n'.join(lines)
			normalContent = re.sub(r'\b(True|False)'+plainMarker+r'\b',r'\1',normalContent)

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
						try: targetChunks [index] = getObfuscatedName(str(index),True)
						except: pass   # Not in list

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
		elif not dryRun and sourceFileNameExtension not in skipFileNameExtensionList:
			targetSubDirectory = '{0}{1}'.format (targetRootDirectory, targetRelSubDirectory) .rsplit ('/', 1) [0]
			
			# Create target path and copy file
			targetFilePath = '{0}/{1}'.format (targetSubDirectory, sourceFileName)
			createFilePath (targetFilePath)
			shutil.copyfile (sourceFilePath, targetFilePath)

	if 0:
		print
		print ('Obfuscated files:  {0}'.format ( (obfuscatedFileDict)))
		print;print;print;print ('Obfuscated words:  {0}'.format ( (allObfuscatedWords)))
		print;print;print;print ('Obfuscated module imports:  {0}'.format ( (opy_parser.obfuscatedModImports)))
		print;print;print;print ('Masked identifier imports:  {0}'.format ( (opy_parser.maskedIdentifiers)))
		print;print;print;print ('Skipped words:  {0}'.format ( (skipWordSet)))
		print;print;print;print ('Skipped public identifiers:  {0}'.format ( (skippedPublicSet)))
		print;print;print;print ('Time Elapsed:  {0} sec'.format ( int(timeElapsed) ))
		print
	else:
		print
		print('{0: >28}  :  {1}'.format('Obfuscated files',len(obfuscatedFileDict)))
		print('{0: >28}  :  {1}'.format('Obfuscated words',len(allObfuscatedWords)))
		print('{0: >28}  :  {1}'.format('Obfuscated module imports',len(opy_parser.obfuscatedModImports)))
		print('{0: >28}  :  {1}'.format('Masked identifier imports',len(opy_parser.maskedIdentifiers)))
		print('{0: >28}  :  {1}'.format('Skipped words',len(skipWordSet)))
		print('{0: >28}  :  {1}'.format('Skipped public identifiers',len(skippedPublicSet)))
		print('{0: >28}  :  {1} sec'.format('Time Elapsed',int(timeElapsed)))
	print

	# Opyfying something twice can and is allowed to fail.
	# The obfuscation for e.g. variable 1 in round 1 can be the same as the obfuscation for e.g. variable 2 in round 2.
	# If in round 2 variable 2 is replaced first, the obfuscation from round 1 for variable 1 will be replaced by the same thing.
	
