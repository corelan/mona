#!/usr/bin/env python2.7
"""
 
U{Corelan<https://www.corelan.be>}

Copyright (c) 2011-2020, Peter Van Eeckhoutte - Corelan Consulting bv
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of Corelan nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL PETER VAN EECKHOUTTE OR CORELAN CONSULTING BVBA 
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, 
OR CONSEQUENTIAL DAMAGES(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE 
GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY 
WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 
$Revision: 613 $
$Id: mona.py 613 2020-07-13 14:33:00Z corelanc0d3r $ 
"""

__VERSION__ = '2.0'
__REV__ = filter(str.isdigit, '$Revision: 613 $')
__IMM__ = '1.8'
__DEBUGGERAPP__ = ''
arch = 32
win7mode = False

# try:
# 	import debugger
# except:
# 	pass
try:
	import immlib as dbglib
	from immlib import LogBpHook
	__DEBUGGERAPP__ = "Immunity Debugger"
except:		
	try:
		import pykd
		import windbglib as dbglib
		from windbglib import LogBpHook
		dbglib.checkVersion()
		arch = dbglib.getArchitecture()
		__DEBUGGERAPP__ = "WinDBG"
	except SystemExit:
		print("-Exit.")
		import sys
		sys.exit(1)
	except Exception:
		#import traceback
		print("Do not run this script outside of a debugger !")
		#print traceback.format_exc()
		import sys
		sys.exit(1)

import getopt

try:
	#import debugtypes
	#import libdatatype
	from immutils import *
except:
	pass

		
import os
import re
import sys
import types
import random
import shutil
import struct
import string
import types
import urllib
import inspect
import datetime
import binascii
import itertools
import traceback
import pickle
import json

from operator import itemgetter
from collections import defaultdict, namedtuple

import cProfile
import pstats

import copy

DESC = "Corelan Team exploit development swiss army knife"

#---------------------------------------#
#  Global stuff                         #
#---------------------------------------#	

TOP_USERLAND = 0x7fffffff
g_modules={}
MemoryPageACL={}
global CritCache
global vtableCache
global stacklistCache
global segmentlistCache
global VACache
global IATCache
global NtGlobalFlag
global FreeListBitmap
global memProtConstants
global currentArgs
global disasmUpperChecked
global disasmIsUpper
global configFileCache
global configwarningshown

NtGlobalFlag = -1
FreeListBitmap = {}
memProtConstants = {}
CritCache={}
IATCache={}
vtableCache={}
stacklistCache={}
segmentlistCache={}
configFileCache={}
VACache={}
ptr_counter = 0
ptr_to_get = -1
silent = False
ignoremodules = False
noheader = False
dbg = dbglib.Debugger()
disasmUpperChecked = False
disasmIsUpper = False
configwarningshown = False

if __DEBUGGERAPP__ == "WinDBG":
	if pykd.getSymbolPath().replace(" ","") == "":
		dbg.log("")
		dbg.log("** Warning, no symbol path set ! ** ",highlight=1)
		sympath = "srv*c:\symbols*http://msdl.microsoft.com/download/symbols"
		dbg.log("   I'll set the symbol path to %s" % sympath)
		pykd.setSymbolPath(sympath)
		dbg.log("   Symbol path set, now reloading symbols...")
		dbg.nativeCommand(".reload")
		dbg.log("   All set. Please restart WinDBG.")
		dbg.log("")

osver = dbg.getOsVersion()
if osver in ["6", "7", "8", "vista", "win7", "2008server", "win8", "win8.1", "win10"]:
	win7mode = True

heapgranularity = 8
if arch == 64:
	heapgranularity = 16

offset_categories = ["xp", "vista", "win7", "win8", "win10"]

# offset = [x86,x64]
offsets = {
	"FrontEndHeap" : {
		"xp" : [0x580,0xad8],
		"vista" : [0x0d4,0x178],
		"win8" : [0x0d0,0x170],
		"win10" : {
			14393 : [0x0d4,0x178]
		}
	},
	"FrontEndHeapType" : {
		"xp" : [0x586,0xae2],
		"vista" : [0x0da,0x182],
		"win8" : [0x0d6,0x17a],
		"win10" : {
			14393 : [0x0da,0x182]
		}
	},
	"VirtualAllocdBlocks" : {
		"xp" : [0x050,0x090],
		"vista" : [0x0a0,0x118],
		"win8" : [0x09c,0x110]
	},
	"SegmentList" : {
		"vista" : [0x0a8,0x128],
		"win8" : [0x0a4,0x120]
	}
}

#---------------------------------------#
#  Populate constants                   #
#---------------------------------------#	
memProtConstants["X"] = ["PAGE_EXECUTE",0x10]
memProtConstants["RX"] = ["PAGE_EXECUTE_READ",0x20]
memProtConstants["RWX"] = ["PAGE_EXECUTE_READWRITE",0x40]
memProtConstants["N"] = ["PAGE_NOACCESS",0x1]
memProtConstants["R"] = ["PAGE_READONLY",0x2]
memProtConstants["RW"] = ["PAGE_READWRITE",0x4]
memProtConstants["GUARD"] = ["PAGE_GUARD",0x100]
memProtConstants["NOCACHE"] = ["PAGE_NOCACHE",0x200]
memProtConstants["WC"] = ["PAGE_WRITECOMBINE",0x400]

#---------------------------------------#
#  Utility functions                    #
#---------------------------------------#	

def resetGlobals():
	"""
	Clears all global variables
	"""
	global CritCache
	global vtableCache
	global stacklistCache
	global segmentlistCache
	global VACache
	global NtGlobalFlag
	global FreeListBitmap
	global memProtConstants
	global currentArgs

	CritCache = None
	vtableCache = None
	stacklistCache = None
	segmentlistCache = None
	VACache = None
	NtGlobalFlag = None
	FreeListBitmap = None
	memProtConstants = None
	currentArgs = None
	disasmUpperChecked = False

	return


def getPythonVersion():
	versioninfo = sys.version
	versioninfolines = versioninfo.split('\n')
	return versioninfolines[0]


def toHex(n):
	"""
	Converts a numeric value to hex (pointer to hex)

	Arguments:
	n - the value to convert

	Return:
	A string, representing the value in hex (8 characters long)
	"""
	if arch == 32:
		return "%08x" % n
	if arch == 64:
		return "%016x" % n

def sanitize_module_name(modname):
	"""
	Sanitizes a module name so it can be used as a variable
	"""
	return modname.replace(".", "_")


def DwordToBits(srcDword):
	"""
	Converts a dword into an array of 32 bits
	"""

	bit_array = []
	h_str = "%08x" % srcDword
	h_size = len(h_str) * 4
	bits = (bin(int(h_str,16))[2:]).zfill(h_size)[::-1]
	for bit in bits:
		bit_array.append(int(bit))
	return bit_array


def getDisasmInstruction(disasmentry):
	""" returns instruction string, checks if ASM is uppercase and converts to upper if needed """
	instrline = disasmentry.getDisasm()
	global disasmUpperChecked
	global disasmIsUpper
	if disasmUpperChecked:
		if not disasmIsUpper:
			instrline = instrline.upper()
	else:
		disasmUpperChecked = True
		interim_instr = instrline.upper()
		if interim_instr == instrline:
			disasmIsUpper = True
		else:
			disasmIsUpper = False
			dbg.log("** It looks like you've configured the debugger to produce lowercase disassembly. Got it, all good **", highlight=1)
			instrline = instrline.upper()
	return instrline
	

def multiSplit(thisarg,delimchars):
	""" splits a string into an array, based on provided delimeters"""
	splitparts = []
	thispart = ""
	for c in str(thisarg):
		if c in delimchars:
			thispart = thispart.replace(" ","")
			if thispart != "":
				splitparts.append(thispart)
			splitparts.append(c)
			thispart = ""
		else:
			thispart += c
	if thispart != "":
		splitparts.append(thispart)
	return splitparts


def getAddyArg(argaddy):
	"""
	Tries to extract an address from a specified argument
	addresses and values will be considered hex
	(unless you specify 0n before a value)
	registers are allowed too
	"""
	findaddy = 0
	addyok = True
	addyparts = []
	addypartsint = []
	delimchars = ["-","+","*","/","(",")","&","|",">","<"]
	regs = dbg.getRegs()
	thispart = ""
	for c in str(argaddy):
		if c in delimchars:
			thispart = thispart.replace(" ","")
			if thispart != "":
				addyparts.append(thispart)
			addyparts.append(c)
			thispart = ""
		else:
			thispart += c
	if thispart != "":
		addyparts.append(thispart)

	partok = False
	for part in addyparts:
		cleaned = part
		if not part in delimchars:
			for x in delimchars:
				cleaned = cleaned.replace(x,"")	
			if cleaned.startswith("[") and cleaned.endswith("]"):
				partval,partok = getIntForPart(cleaned.replace("[","").replace("]",""))
				if partok:
					try:
						partval = struct.unpack('<L',dbg.readMemory(partval,4))[0]
					except:
						partval = 0
						partok = False
						break
			else:	
				partval,partok = getIntForPart(cleaned)
				if not partok:
					break
			addypartsint.append(partval)
		else:
			addypartsint.append(part)
		if not partok:
			break

	if not partok:
		addyok = False
		findval = 0
	else:
		calcstr = "".join(str(x) for x in addypartsint)
		try:
			findval = eval(calcstr)
			addyok = True
		except:
			findval = 0
			addyok = False

	return findval, addyok
	


def getIntForPart(part):
	"""
	Returns the int value associated with an input string
	The input string can be a hex value, decimal value, register, modulename, or modulee!functionname
	"""
	partclean = part
	partclean = partclean.upper()
	addyok = True
	partval = 0
	regs = dbg.getRegs()
	if partclean in regs:
		partval = regs[partclean]
	elif partclean.lower() == "heap" or partclean.lower() == "processheap":
		partval = getDefaultProcessHeap()
	else:
		if partclean.lower().startswith("0n"):
			partclean = partclean.lower().replace("0n","")
			try:
				partval = int(partclean)
			except:
				addyok = False
				partval = 0
		else:
			try:
				if not "0x" in partclean.lower():
					partclean = "0x" + partclean
				partval = int(partclean,16)
			except:
				addyok = False
				partval = 0
	if not addyok:
		if not "!" in part:
			m = getModuleObj(part)
			if not m == None:
				partval = m.moduleBase
				addyok = True
		else:
			modparts = part.split("!")
			modname = modparts[0]
			funcname = modparts[1]
			m = getFunctionAddress(modname,funcname)
			if m > 0:
				partval = m
				addyok = True
	return partval,addyok


def getHeapAllocSize(requested_size, granularity = 8):
	"""
	Returns the expected allocated size for a request of X bytes of heap memory
	taking a certain granularity into account
	"""
	
	requested_size_int = to_int(requested_size)
	interimval = (requested_size_int / granularity) * granularity
	interimtimes = (requested_size_int / granularity)
	if (interimval < requested_size_int):
		interimtimes += 1
	allocated_size = granularity * interimtimes
	
	return allocated_size
	


def getFunctionAddress(modname,funcname):
	"""
	Returns the addres of the function inside a given module
	Relies on EAT data
	Returns 0 if nothing found
	"""
	funcaddy = 0
	m = getModuleObj(modname)
	if not m == None:
		eatlist = m.getEAT()
		for f in eatlist:
			if funcname == eatlist[f]:
				return f
		for f in eatlist:
			if funcname.lower() == eatlist[f].lower():
				return f
	return funcaddy

def getFunctionName(addy):
	"""
	Returns symbol name closest to the specified address
	Only works in WinDBG
	Returns function name and optional offset
	"""
	fname = ""
	foffset = ""
	cmd2run = "ln 0x%08x" % addy
	output = dbg.nativeCommand(cmd2run)
	for line in output.split("\n"):
		if "|" in line:
			lineparts = line.split(" ")
			partcnt = 0
			for p in lineparts:
				if not p == "":
					if partcnt == 1:
						fname = p
						break
					partcnt += 1
	if "+" in fname:
		fnameparts = fname.split("+")
		if len(fnameparts) > 1:
			return fnameparts[0],fnameparts[1]
	return fname,foffset


def printDataArray(data,charsperline=16,prefix=""):
	maxlen = len(data)
	charcnt = 0
	charlinecnt = 0
	linecnt = 0
	thisline = prefix
	lineprefix = "%04d - %04d " % (charcnt,charcnt+charsperline-1)
	thisline += lineprefix
	while charcnt < maxlen:
		thisline += data[charcnt:charcnt+1]
		charlinecnt += 1
		charcnt += 1
		if charlinecnt == charsperline or charlinecnt == maxlen:
			dbg.log(thisline)
			thisline = prefix
			lineprefix = "%04d - %04d " % (charcnt,charcnt+charsperline-1)
			thisline += lineprefix
			charlinecnt = 0
	return None


def find_all_copies(tofind,data):
	"""
	Finds all occurences of a string in a longer string

	Arguments:
	tofind - the string to find
	data - contains the data to look for all occurences of 'tofind'

	Return:
	An array with all locations
	"""
	position = 0
	positions = []
	searchstringlen = len(tofind)
	maxlen = len(data)
	while position < maxlen:
		position = data.find(tofind,position)
		if position == -1:
			break
		positions.append(position)
		position += searchstringlen
	return positions

def getAllStringOffsets(data,minlen,offsetstart = 0):
	asciistrings = {}
	for match in re.finditer("(([\x20-\x7e]){%d,})" % minlen,data): 
		thisloc = match.start() + offsetstart
		thisend = match.end() + offsetstart
		asciistrings[thisloc] = thisend
	return asciistrings

def getAllUnicodeStringOffsets(data,minlen,offsetstart = 0):
	unicodestrings = {}
	for match in re.finditer("((\x00[\x20-\x7e]){%d,})" % (minlen*2),data):
		unicodestrings[offsetstart + match.start()] = (offsetstart + match.end())
	return unicodestrings


def stripExtension(fullname):
	"""
	Removes extension from a filename
	(will only remove the last extension)

	Arguments :
	fullname - the original string

	Return:
	A string, containing the original string without the last extension
	"""
	nameparts = str(fullname).split(".")
	if len(nameparts) > 1:
		cnt = 0
		modname = ""
		while cnt < len(nameparts)-1:
			modname = modname + nameparts[cnt] + "."
			cnt += 1
		return modname.strip(".")
	return fullname


def toHexByte(n):
	"""
	Converts a numeric value to a hex byte

	Arguments:
	n - the vale to convert (max 255)

	Return:
	A string, representing the value in hex (1 byte)
	"""
	return "%02X" % n

def toAsciiOnly(inputstr):
	return "".join(i for i in inputstr if ord(i)<128 and ord(i) > 31)

def toAscii(n):
	"""
	Converts a byte to its ascii equivalent. Null byte = space

	Arguments:
	n - A string (2 chars) representing the byte to convert to ascii

	Return:
	A string (one character), representing the ascii equivalent
	"""
	asciiequival = " "
	if n.__class__.__name__ == "int":
		n = "%02x" % n
	try:
		if n != "00":
			asciiequival=binascii.a2b_hex(n)
		else:
			asciiequival = " "
	except TypeError:
		asciiequival=" "
	return asciiequival

def hex2bin(pattern):
	"""
	Converts a hex string (\\x??\\x??\\x??\\x??) to real hex bytes

	Arguments:
	pattern - A string representing the bytes to convert 

	Return:
	the bytes
	"""
	pattern = pattern.replace("\\x", "")
	pattern = pattern.replace("\"", "")
	pattern = pattern.replace("\'", "")
	
	return ''.join([binascii.a2b_hex(i+j) for i,j in zip(pattern[0::2],pattern[1::2])])

def cleanHex(hex):
	hex = hex.replace("'","")
	hex = hex.replace('"',"")
	hex = hex.replace("\\x","")
	hex = hex.replace("0x","")
	return hex

def hex2int(hex):
	return int(hex,16)

def getVariantType(typenr):
	varianttypes = {}
	varianttypes[0x0] = "VT_EMPTY"
	varianttypes[0x1] = "VT_NULL"
	varianttypes[0x2] = "VT_I2"
	varianttypes[0x3] = "VT_I4"
	varianttypes[0x4] = "VT_R4"
	varianttypes[0x5] = "VT_R8"
	varianttypes[0x6] = "VT_CY"
	varianttypes[0x7] = "VT_DATE"
	varianttypes[0x8] = "VT_BSTR"
	varianttypes[0x9] = "VT_DISPATCH"
	varianttypes[0xA] = "VT_ERROR"
	varianttypes[0xB] = "VT_BOOL"
	varianttypes[0xC] = "VT_VARIANT"
	varianttypes[0xD] = "VT_UNKNOWN"
	varianttypes[0xE] = "VT_DECIMAL"
	varianttypes[0x10] = "VT_I1"
	varianttypes[0x11] = "VT_UI1"
	varianttypes[0x12] = "VT_UI2"
	varianttypes[0x13] = "VT_UI4"
	varianttypes[0x14] = "VT_I8"
	varianttypes[0x15] = "VT_UI8"
	varianttypes[0x16] = "VT_INT"
	varianttypes[0x17] = "VT_UINT"
	varianttypes[0x18] = "VT_VOID"
	varianttypes[0x19] = "VT_HRESULT"
	varianttypes[0x1A] = "VT_PTR"
	varianttypes[0x1B] = "VT_SAFEARRAY"
	varianttypes[0x1C] = "VT_CARRAY"
	varianttypes[0x1D] = "VT_USERDEFINED"
	varianttypes[0x1E] = "VT_LPSTR"
	varianttypes[0x1F] = "VT_LPWSTR"
	varianttypes[0x24] = "VT_RECORD"
	varianttypes[0x25] = "VT_INT_PTR"
	varianttypes[0x26] = "VT_UINT_PTR"
	varianttypes[0x2000] = "VT_ARRAY"
	varianttypes[0x4000] = "VT_BYREF"

	if typenr in varianttypes:
		return varianttypes[typenr]
	else:
		return ""



def bin2hex(binbytes):
	"""
	Converts a binary string to a string of space-separated hexadecimal bytes.
	"""
	return ' '.join('%02x' % ord(c) for c in binbytes)

def bin2hexstr(binbytes):
	"""
	Converts bytes to a string with hex
	
	Arguments:
	binbytes - the input to convert to hex
	
	Return :
	string with hex
	"""
	return ''.join('\\x%02x' % ord(c) for c in binbytes)

def str2js(inputstring):
	"""
	Converts a string to a javascript string
	
	Arguments:
	inputstring - the input string to convert 

	Return :
	string in javascript format
	"""
	length = len(inputstring)
	if length % 2 == 1:
		jsmsg = "Warning : odd size given, js pattern will be truncated to " + str(length - 1) + " bytes, it's better use an even size\n"
		if not silent:
			dbg.logLines(jsmsg,highlight=1)
	toreturn=""
	for thismatch in re.compile("..").findall(inputstring):
		thisunibyte = ""
		for thisbyte in thismatch:
			thisunibyte = "%02x" % ord(thisbyte) + thisunibyte
		toreturn += "%u" + thisunibyte
	return toreturn		


def readJSONDict(filename):
	"""
	Retrieve stored dict from JSON file
	"""
	jsondict = {}
	with open(filename, 'rb') as infile:
		jsondata = infile.read()
		jsondict = json.loads(jsondata)
	return jsondict


def writeJSONDict(filename, dicttosave):
	"""
	Write dict as JSON to file
	"""
	with open(filename, 'wb') as outfile:
		json.dump(dicttosave, outfile)
	return


def readPickleDict(filename):
	"""
	Retrieve stored dict from file (pickle load)
	"""
	pdict = {}
	pdict = pickle.load( open(filename,"rb"))
	return pdict

def writePickleDict(filename, dicttosave):
	"""
	Write a dict to file as a pickle
	"""
	pickle.dump(dicttosave, open(filename, "wb"))
	return

	
def opcodesToHex(opcodes):
	"""
	Converts pairs of chars (opcode bytes) to hex string notation

	Arguments :
	opcodes : pairs of chars
	
	Return :
	string with hex
	"""
	toreturn = []
	opcodes = opcodes.replace(" ","")
	
	for cnt in range(0, len(opcodes), 2):
		thisbyte = opcodes[cnt:cnt+2]
		toreturn.append("\\x" + thisbyte)
	toreturn = ''.join(toreturn)
	return toreturn
	
	
def rmLeading(input,toremove,toignore=""):
	"""
	Removes leading characters from an input string
	
	Arguments:
	input - the input string
	toremove - the character to remove from the begin of the string
	toignore - ignore this character
	
	Return:
	the input string without the leading character(s)
	"""
	newstring = ""
	cnt = 0
	while cnt < len(input):
		if input[cnt] != toremove and input[cnt] != toignore:
			break
		cnt += 1
	newstring = input[cnt:]
	return newstring

	
def getVersionInfo(filename):
	"""Retrieves version and revision numbers from a mona file
	
	Arguments : filename
	
	Return :
	version - string with version (or empty if not found)
	revision - string with revision (or empty if not found)
	"""

	file = open(filename,"rb")
	content = file.readlines()
	file.close()

	
	revision = ""
	version = ""
	for line in content:
		if line.startswith("$Revision"):
			parts = line.split(" ")
			if len(parts) > 1:
				revision = parts[1].replace("$","")
		if line.startswith("__VERSION__"):
			parts = line.split("=")
			if len(parts) > 1:
				version = parts[1].strip()
	return version,revision

	
def toniceHex(data,size):
	"""
	Converts a series of bytes into a hex string, 
	newline after 'size' nr of bytes
	
	Arguments :
	data - the bytes to convert
	size - the number of bytes to show per linecache
	
	Return :
	a multiline string
	"""
	flip = 1
	thisline = "\""
	block = ""

	try:
   		 # Python 2
		xrange
	except NameError:
		# Python 3, xrange is now named range
		xrange = range
	
	for cnt in xrange(len(data)):
		thisline += "\\x%s" % toHexByte(ord(data[cnt]))				
		if (flip == size) or (cnt == len(data)-1):				
			thisline += "\""
			flip = 0
			block += thisline 
			block += "\n"
			thisline = "\""
		cnt += 1
		flip += 1
	return block.lower()
	
def hexStrToInt(inputstr):
	"""
	Converts a string with hex bytes to a numeric value
	Arguments:
	inputstr - A string representing the bytes to convert. Example : 41414141

	Return:
	the numeric value
	"""
	valtoreturn = 0
	try:
		valtoreturn = int(inputstr, 16)
	except:
		valtoreturn = 0
	return valtoreturn

def to_int(inputstr):
	"""
	Converts a string to int, whether it's hex or decimal
	Arguments:
	    inputstr - A string representation of a number. Example: 0xFFFF, 2345

	Return:
	    the numeric value
	"""
	if str(inputstr).lower().startswith("0x"):
		return hexStrToInt(inputstr)
	else:
		return int(inputstr)
	
def toSize(toPad,size):
	"""
	Adds spaces to a string until the string reaches a certain length

	Arguments:
	input - A string
	size - the destination size of the string 

	Return:
	the expanded string of length <size>
	"""
	padded = toPad + " " * (size - len(toPad))
	return padded.ljust(size," ")

	
def toUnicode(input):
	"""
	Converts a series of bytes to unicode (UTF-16) bytes
	
	Arguments :
	input - the source bytes
	
	Return:
	the unicode expanded version of the input
	"""
	unicodebytes = ""
	# try/except, just in case .encode bails out
	try:
		unicodebytes = input.encode('UTF-16LE')
	except:
		inputlst = list(input)
		for inputchar in inputlst:
			unicodebytes += inputchar + '\x00'
	return unicodebytes
	
def toJavaScript(input):
	"""
	Extracts pointers from lines of text
	and returns a javascript friendly version
	"""
	alllines = input.split("\n")
	javascriptversion = ""
	allbytes = ""
	for eachline in alllines:
		thisline = eachline.replace("\t","").lower().strip()
		if not(thisline.startswith("#")):
			if thisline.startswith("0x"):
				theptr = thisline.split(",")[0].replace("0x","")
				# change order to unescape format
				if arch == 32:
					ptrstr = ""
					byte1 = theptr[0] + theptr[1]
					ptrstr = "\\x" + byte1
					byte2 = theptr[2] + theptr[3]
					ptrstr = "\\x" + byte2 + ptrstr
					try:
						byte3 = theptr[4] + theptr[5]
						ptrstr = "\\x" + byte3 + ptrstr
					except:
						pass
					try:
						byte4 = theptr[6] + theptr[7]
						ptrstr = "\\x" + byte4 + ptrstr
					except:
						pass
					allbytes += hex2bin(ptrstr)
				if arch == 64:
					byte1 = theptr[0] + theptr[1]
					byte2 = theptr[2] + theptr[3]
					byte3 = theptr[4] + theptr[5]
					byte4 = theptr[6] + theptr[7]
					byte5 = theptr[8] + theptr[9]
					byte6 = theptr[10] + theptr[11]
					byte7 = theptr[12] + theptr[13]
					byte8 = theptr[14] + theptr[15]
					allbytes += hex2bin("\\x" + byte8 + "\\x" + byte7 + "\\x" + byte6 + "\\x" + byte5)
					allbytes += hex2bin("\\x" + byte4 + "\\x" + byte3 + "\\x" + byte2 + "\\x" + byte1)
	javascriptversion = str2js(allbytes)			
	return javascriptversion
	

def getSourceDest(instruction):
	"""
	Determines source and destination register for a given instruction
	"""
	src = []
	dst = []
	srcp = []
	dstp = []
	srco = []
	dsto = []
	instr = []
	haveboth = False
	seensep = False
	seeninstr = False

	regs = getAllRegs()

	instructionparts = multiSplit(instruction,[" ",","])
	
	if "," in instructionparts:
		haveboth = True

	delkeys = ["DWORD","PTR","BYTE"]

	for d in delkeys:
		if d in instructionparts:
			instructionparts.remove(d)


	for p in instructionparts:

		regfound = False
		for r in regs:
			if r.upper() in p.upper() and not "!" in p and not len(instr) == 0:
				regfound = True
				seeninstr = True
				break

		if not regfound:
			if not seeninstr and not seensep:
				instr.append(p) 
		
			if "," in p:
				seensep = True
		else:
			for r in regs:
				if r.upper() in p.upper():
					if not seensep or not haveboth:
						dstp.append(p)
						if not r in dsto:
							dsto.append(r)
							break
					else:
						srcp.append(p)
						if not r in srco:
							srco.append(r)
							break

	#dbg.log("dst: %s" % dsto)
	#dbg.log("src: %s" % srco)
	src = srcp
	dst = dstp
	return src,dst

	

def getAllRegs():
	"""
	Return an array with all 32bit, 16bit and 8bit registers
	"""
	regs = ["EAX","EBX","ECX","EDX","ESP","EBP","ESI","EDI","EIP"]
	regs.append("AX")
	regs.append("BX")
	regs.append("CX")
	regs.append("DX")
	regs.append("BP")
	regs.append("SP")
	regs.append("SI")
	regs.append("DI")
	regs.append("AL")
	regs.append("AH")
	regs.append("BL")
	regs.append("BH")
	regs.append("CL")
	regs.append("CH")
	regs.append("DL")
	regs.append("DH")
	return regs

def getSmallerRegs(reg):
	if reg == "EAX":
		return ["AX","AL","AH"]
	if reg == "AX":
		return ["AL","AH"]
	if reg == "EBX":
		return ["BX","BL","BH"]
	if reg == "BX":
		return ["BL","BH"]
	if reg == "ECX":
		return ["CX","CL","CH"]
	if reg == "CX":
		return ["CL","CH"]
	if reg == "EDX":
		return ["DX","DL","DH"]
	if reg == "DX":
		return ["DL","DH"]
	if reg == "ESP":
		return ["SP"]
	if reg == "EBP":
		return ["BP"]
	if reg == "ESI":
		return ["SI"]
	if reg == "EDI":
		return ["DI"]

	return []


def isReg(reg):
	"""
	Checks if a given string is a valid reg
	Argument :
	reg  - the register to check
	
	Return:
	Boolean
	"""
	regs = []
	if arch == 32:
		regs=["eax","ebx","ecx","edx","esi","edi","ebp","esp"]
	if arch == 64:
		regs=["rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
	return str(reg).lower() in regs
	

def isAddress(string):
	"""
	Check if a string is an address / consists of hex chars only

	Arguments:
	string - the string to check

	Return:
	Boolean - True if the address string only contains hex bytes
	"""
	string = string.replace("\\x","")
	if len(string) > 16:
		return False
	for char in string:
		if char.upper() not in ["A","B","C","D","E","F","1","2","3","4","5","6","7","8","9","0"]:
			return False
	return True
	
def isHexValue(string):
	"""
	Check if a string is a hex value / consists of hex chars only (and - )

	Arguments:
	string - the string to check

	Return:
	Boolean - True if the address string only contains hex bytes or - sign
	"""
	string = string.replace("\\x","")
	string = string.replace("0x","")
	if len(string) > 16:
		return False
	for char in string:
		if char.upper() not in ["A","B","C","D","E","F","1","2","3","4","5","6","7","8","9","0","-"]:
			return False
	return True	

def Poly_ReturnDW(value):
	I = random.randint(1, 3)
	if I == 1:
		if random.randint(1, 2) == 1:
			return dbg.assemble( "SUB EAX, EAX\n ADD EAX, 0x%08x" % value )
		else:
			return dbg.assemble( "SUB EAX, EAX\n ADD EAX, -0x%08x" % value )
	if I == 2:
		return dbg.assemble( "PUSH 0x%08x\n POP EAX\n" % value )
	if I == 3:
		if random.randint(1, 2) == 1:
			return dbg.assemble( "XCHG EAX, EDI\n DB 0xBF\n DD 0x%08x\n XCHG EAX, EDI" % value )
		else:
			return dbg.assemble( "XCHG EAX, EDI\n MOV EDI, 0x%08x\n XCHG EAX, EDI" % value )
	return

def Poly_Return0():
	I = random.randint(1, 4)
	if I == 1:
		return dbg.assemble( "SUB EAX, EAX" )
	if I == 2:
		if random.randint(1, 2) == 1:
			return dbg.assemble( "PUSH 0\n POP EAX" )
		else:
			return dbg.assemble( "DB 0x6A, 0x00\n POP EAX" )
	if I == 3:
		return dbg.assemble( "XCHG EAX, EDI\n SUB EDI, EDI\n XCHG EAX, EDI" )
	if I == 4:
		return Poly_ReturnDW(0)
	return


def addrToInt(string):
	"""
	Convert a textual address to an integer

	Arguments:
	string - the address

	Return:
	int - the address value
	"""
	
	string = string.replace("\\x","")
	return hexStrToInt(string)
	
def splitAddress(address):
	"""
	Splits aa dword/qdword into individual bytes (4 or 8 bytes)

	Arguments:
	address - The string to split

	Return:
	4 or 8 bytes
	"""
	if arch == 32:
		byte1 = address >> 24 & 0xFF
		byte2 = address >> 16 & 0xFF
		byte3 = address >>  8 & 0xFF
		byte4 = address & 0xFF
		return byte1,byte2,byte3,byte4

	if arch == 64:
		byte1 = address >> 56 & 0xFF
		byte2 = address >> 48 & 0xFF
		byte3 = address >> 40 & 0xFF
		byte4 = address >> 32 & 0xFF
		byte5 = address >> 24 & 0xFF
		byte6 = address >> 16 & 0xFF
		byte7 = address >>  8 & 0xFF
		byte8 = address & 0xFF
		return byte1,byte2,byte3,byte4,byte5,byte6,byte7,byte8


def bytesInRange(address, range):
	"""
	Checks if all bytes of an address are in a range

	Arguments:
	address - the address to check
	range - a range object containing the values all bytes need to comply with

	Return:
	a boolean
	"""
	if arch == 32:
		byte1,byte2,byte3,byte4 = splitAddress(address)
		
		# if the first is a null we keep the address anyway
		if not (byte1 == 0 or byte1 in range):
			return False
		elif not byte2 in range:
			return False
		elif not byte3 in range:
			return False
		elif not byte4 in range:
			return False

	if arch == 64:
		byte1,byte2,byte3,byte4,byte5,byte6,byte7,byte8 = splitAddress(address)
		
		# if the first is a null we keep the address anyway
		if not (byte1 == 0 or byte1 in range):
			return False
		elif not byte2 in range:
			return False
		elif not byte3 in range:
			return False
		elif not byte4 in range:
			return False
		elif not byte5 in range:
			return False
		elif not byte6 in range:
			return False
		elif not byte7 in range:
			return False
		elif not byte8 in range:
			return False
	
	return True

def readString(address):
	"""
	Reads a string from the given address until it reaches a null bytes

	Arguments:
	address - the base address (integer value)

	Return:
	the string
	"""
	toreturn = dbg.readString(address)
	return toreturn

def getSegmentEnd(segmentstart):
	os = dbg.getOsVersion()
	offset = 0x24
	if win7mode:
		offset = 0x28
	segmentend = struct.unpack('<L',dbg.readMemory(segmentstart + offset,4))[0]
	return segmentend


def getHeapFlag(flag):
	flags = {
	0x0 : "Free",
	0x1 : "Busy",
	0x2 : "Extra present",
	0x4 : "Fill pattern",
	0x8 : "Virtallocd",
	0x10 : "Last",
	0x20 : "FFU-1",
	0x40 : "FFU-2",
	0x80 : "No Coalesce"
	}
	#if win7mode:
	#	flags[0x8] = "Internal"
	if flag in flags:
		return flags[flag]
	else:
		# maybe it's a combination of flags
		values = [0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1]
		flagtext = []
		for val in values:
			if (flag - val) >= 0:
				flagtext.append(flags[val])
				flag -= val
		if len(flagtext) == 0:
			flagtext = "Unknown"
		else:
			flagtext = ','.join(flagtext)
		return flagtext

def decodeHeapHeader(headeraddress,headersize,key):
	# get header and decode first 4 bytes
	blockcnt = 0
	fullheaderbytes = ""
	decodedheader = ""
	fullheaderbytes = ""
	while blockcnt < headersize:
		header = struct.unpack('<L',dbg.readMemory(headeraddress+blockcnt,4))[0]
		if blockcnt == 0:
			decodedheader = header ^ key
		else:
			decodedheader = header
		headerbytes = "%08x" % decodedheader
		bytecnt = 7
		while bytecnt >= 0:
			fullheaderbytes = fullheaderbytes + headerbytes[bytecnt-1] + headerbytes[bytecnt]
			bytecnt -= 2
		blockcnt += 4
	return hex2bin(fullheaderbytes)

def walkSegment(FirstEntry,LastValidEntry,heapbase):
	"""
	Finds all chunks in a given segment

	Arguments : Start and End of segment, and heapbase
	

	Returns a dictionary of MnChunk objects
	Key : chunk pointer

	"""
	mHeap = MnHeap(heapbase)
	mSegment = MnSegment(heapbase,FirstEntry,LastValidEntry)
	return mSegment.getChunks()

	
def getStacks():
	"""
	Retrieves all stacks from all threads in the current application

	Arguments:
	None

	Return:
	a dictionary, with key = threadID. Each entry contains an array with base and top of the stack
	"""
	stacks = {}
	global stacklistCache
	if len(stacklistCache) > 0:
		return stacklistCache
	else:
		threads = dbg.getAllThreads() 
		for thread in threads:
			teb = thread.getTEB()
			tid = thread.getId()
			topStack = 0
			baseStack = 0
			if arch == 32:
				topStack = struct.unpack('<L',dbg.readMemory(teb+4,4))[0]
				baseStack = struct.unpack('<L',dbg.readMemory(teb+8,4))[0]
			if arch == 64:
				topStack = struct.unpack('<Q',dbg.readMemory(teb+8,8))[0]
				baseStack = struct.unpack('<Q',dbg.readMemory(teb+16,8))[0]
			stacks[tid] = [baseStack,topStack]
		stacklistCache = stacks
		return stacks

def meetsAccessLevel(page,accessLevel):
	"""
	Checks if a given page meets a given access level

	Arguments:
	page - a page object
	accesslevel - a string containing one of the following access levels :
	R,W,X,RW,RX,WR,WX,RWX or *

	Return:
	a boolean
	"""
	if "*" in accessLevel:
		return True
	
	pageAccess = page.getAccess(human=True)
	
	if "-R" in accessLevel:
		if "READ" in pageAccess:
			return False
	if "-W" in accessLevel:
		if "WRITE" in pageAccess:
			return False
	if "-X" in accessLevel:
		if "EXECUTE" in pageAccess:
			return False
	if "R" in accessLevel:
		if not "READ" in pageAccess:
			return False
	if "W" in accessLevel:
		if not "WRITE" in pageAccess:
			return False
	if "X" in accessLevel:
		if not "EXECUTE" in pageAccess:
			return False
			
	return True

def splitToPtrInstr(input):
	"""
	Splits a line (retrieved from a mona output file) into a pointer and a string with the instructions in the file

	Arguments:
	input : the line containing pointer and instruction

	Return:
	a pointer - (integer value)
	a string - instruction
	if the input does not contain a valid line, pointer will be set to -1 and string will be empty
	"""	
	
	thispointer = -1
	thisinstruction = ""
	split1 = re.compile(" ")
	split2 = re.compile(":")
	split3 = re.compile("\*\*")
	
	thisline = input.lower()
	if thisline.startswith("0x"):
		#get the pointer
		parts = split1.split(input)
		part1 = parts[0].replace("\n","").replace("\r","")
		if len(part1) != 10:
			return thispointer,thisinstruction
		else:
			thispointer = hexStrToInt(part1)
			if len(parts) > 1:
				subparts = split2.split(input)
				subpartsall = ""
				if len(subparts) > 1:
					cnt = 1
					while cnt < len(subparts):
						subpartsall += subparts[cnt] + ":"
						cnt +=1
					subsubparts = split3.split(subpartsall)
					thisinstruction = subsubparts[0].strip()
			return thispointer,thisinstruction
	else:
		return thispointer,thisinstruction
		
		
def getNrOfDictElements(thisdict):
	"""
	Will get the total number of entries in a given dictionary
	Argument: the source dictionary
	Output : an integer
	"""
	total = 0
	for dicttype in thisdict:
		for dictval in thisdict[dicttype]:
			total += 1
	return total
	
def getModuleObj(modname):
	"""
	Will return a module object if the provided module name exists
	Will perform a case sensitive search first,
	and then a case insensitive search in case nothing was found
	"""
	# Method 1
	mod = dbg.getModule(modname)
	if mod is not None:
		return MnModule(modname)
	# Method 2

	suffixes = ["",".exe",".dll"]
	allmod = dbg.getAllModules()
	for suf in suffixes:
		modname_search = modname + suf	
		
		#WinDBG optimized
		if __DEBUGGERAPP__ == "WinDBG":	
			for tmod_s in allmod:
				tmod = dbg.getModule(tmod_s)
				if not tmod == None:
					if tmod.getName() == modname_search:
						return MnModule(tmod_s)
					imname = dbg.getImageNameForModule(tmod.getName())
					if not imname == None:
						if imname == modname_search:
							return MnModule(tmod)
			for tmod_s in allmod:
				tmod = dbg.getModule(tmod_s)
				if not tmod == None:
					if tmod.getName().lower() == modname_search.lower():
						return MnModule(tmod_s)
					imname = dbg.getImageNameForModule(tmod.getName().lower())
					if not imname == None:
						if imname.lower() == modname_search.lower():
							return MnModule(tmod)
			for tmod_s in allmod:
				tmod = dbg.getModule(tmod_s)
				if not tmod == None:
					if tmod_s.lower() == modname_search.lower():
						return MnModule(tmod_s)
		else:
			# Immunity
			for tmod_s in allmod:
				if not tmod_s == None:
					mname = tmod_s.getName()
					if mname == modname_search:
						return MnModule(mname)
			for tmod_s in allmod:
				if not tmod_s == None:
					mname = tmod_s.getName()
					if mname.lower() == modname_search.lower():
						return MnModule(mname)
		
	return None
	
		
		
def getPatternLength(startptr,type="normal",args={}):
	"""
	Gets length of a cyclic pattern, starting from a given pointer
	
	Arguments:
	startptr - the start pointer (integer value)
	type - optional string, indicating type of pattern :
		"normal" : normal pattern
		"unicode" : unicode pattern
		"upper" : uppercase pattern
		"lower" : lowercase pattern
	"""
	patternsize = 0
	endofpattern = False
	global silent
	oldsilent=silent
	silent=True
	fullpattern = createPattern(200000,args)
	silent=oldsilent
	if type == "upper":
		fullpattern = fullpattern.upper()
	if type == "lower":
		fullpattern = fullpattern.lower()
	#if type == "unicode":
	#	fullpattern = toUnicode(fullpattern)
	
	if type in ["normal","upper","lower","unicode"]:
		previousloc = -1
		while not endofpattern and patternsize <= len(fullpattern):
			sizemeter=dbg.readMemory(startptr+patternsize,4)
			if type == "unicode":
				sizemeter=dbg.readMemory(startptr+patternsize,8)
				sizemeter = sizemeter.replace('\x00','')
			else:
				sizemeter=dbg.readMemory(startptr+patternsize,4)
			if len(sizemeter) == 4:
				thisloc = fullpattern.find(sizemeter)
				if thisloc < 0 or thisloc <= previousloc:
					endofpattern = True
				else:
					patternsize += 4
					previousloc = thisloc
			else:
				return patternsize
		#maybe this is not the end yet
		patternsize -= 8
		endofpattern = False
		while not endofpattern and patternsize <= len(fullpattern):
			sizemeter=dbg.readMemory(startptr+patternsize,4)
			if type == "unicode":
				sizemeter=dbg.readMemory(startptr+patternsize,8)
				sizemeter = sizemeter.replace('\x00','')
			else:
				sizemeter=dbg.readMemory(startptr+patternsize,4)
			if fullpattern.find(sizemeter) < 0:
				patternsize += 3
				endofpattern = True
			else:		
				patternsize += 1
	if type == "unicode":
		patternsize = (patternsize / 2) + 1
	return patternsize
	
def getAPointer(modules,criteria,accesslevel):
	"""
	Gets the first pointer from one of the supplied module that meets a set of criteria
	
	Arguments:
	modules - array with module names
	criteria - dictionary describing the criteria the pointer needs to comply with
	accesslevel - the required access level
	
	Return:
	a pointer (integer value) or 0 if nothing was found
	"""
	pointer = 0
	dbg.getMemoryPages()
	for a in dbg.MemoryPages.keys():
			page_start = a
			page_size  = dbg.MemoryPages[a].getSize()
			page_end   = a + page_size
			#page in one of the modules ?
			if meetsAccessLevel(dbg.MemoryPages[a],accesslevel):
				pageptr = MnPointer(a)
				thismodulename = pageptr.belongsTo()
				if thismodulename != "" and thismodulename in modules:
					thismod = MnModule(thismodulename)
					start = thismod.moduleBase
					end = thismod.moduleTop
					random.seed()
					for cnt in xrange(page_size+1):
						#randomize the value
						theoffset = random.randint(0,page_size)
						thispointer = MnPointer(page_start + theoffset)
						if meetsCriteria(thispointer,criteria):
							return page_start + theoffset
	return pointer
	
	
def haveRepetition(string, pos):
	first =  string[pos]
	MIN_REPETITION = 3		
	if len(string) - pos > MIN_REPETITION:
		count = 1
		while ( count < MIN_REPETITION and string[pos+count] ==  first):
			count += 1
		if count >= MIN_REPETITION:
			return True
	return False


def findAllPaths(graph,start_vertex,end_vertex,path=[]):
	path = path + [start_vertex]
	if start_vertex == end_vertex:
		return [path]
	if start_vertex not in graph:
		return []
	paths = []
	for vertex in graph[start_vertex]:
		if vertex not in path:
			extended_paths = findAllPaths(graph,vertex,end_vertex,path)
			for p in extended_paths:
				paths.append(p)
	return paths



def isAsciiString(data):
	"""
	Check if a given string only contains ascii characters
	"""
	return all((ord(c) >= 32 and ord(c) <= 127) for c in data)
	
def isAscii(b):
	"""
	Check if a given hex byte is ascii or not
	
	Argument : the byte
	Returns : Boolean
	"""
	return b == 0x0a or b == 0x0d or (b >= 0x20 and b <= 0x7e)
	
def isAscii2(b):
	"""
	Check if a given hex byte is ascii or not, will not flag newline or carriage return as ascii
	
	Argument : the byte
	Returns : Boolean
	"""
	return b >= 0x20 and b <= 0x7e	
	
def isHexString(input):
	"""
	Checks if all characters in a string are hex (0->9, a->f, A->F)
	Alias for isAddress()
	"""
	return isAddress(input)

def extract_chunks(iterable, size):
	""" Retrieves chunks of the given :size from the :iterable """
	fill = object()
	gen = itertools.izip_longest(fillvalue=fill, *([iter(iterable)] * size))
	return (tuple(x for x in chunk if x != fill) for chunk in gen)

def rrange(x, y = 0):
	""" Creates a reversed range (from x - 1 down to y).
	
	Example:
	>>> rrange(10, 0) # => [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
	"""
	return range(x - 1, y - 1, -1)

def getSkeletonHeader(exploittype,portnr,extension,url,badchars='\x00\x0a\x0d'):

	originalauthor = "insert_name_of_person_who_discovered_the_vulnerability"
	name = "insert name for the exploit"
	cve = "insert CVE number here"
	
	if url == "":
		url = "<insert another link to the exploit/advisory here>"
	else:
		try:
			# connect to url & get author + app description
			u = urllib.urlretrieve(url)
			# extract title
			fh = open(u[0],'r')
			contents = fh.readlines()
			fh.close()
			for line in contents:
				if line.find('<h1') > -1:
					titleline = line.split('>')
					if len(titleline) > 1:
						name = titleline[1].split('<')[0].replace("\"","").replace("'","").strip()
					break
			for line in contents:
				if line.find('Author:') > -1 and line.find('td style') > -1:
					authorline = line.split("Author:")
					if len(authorline) > 1:
						originalauthor = authorline[1].split('<')[0].replace("\"","").replace("'","").strip()
					break
			for line in contents:
				if line.find('CVE:') > -1 and line.find('td style') > -1:
					cveline = line.split("CVE:")
					if len(cveline) > 1:
						tcveparts = cveline[1].split('>')
						if len(tcveparts) > 1:
							tcve = tcveparts[1].split('<')[0].replace("\"","").replace("'","").strip()
							if tcve.upper().strip() != "N//A":
								cve = tcve
					break					
		except:
			dbg.log(" ** Unable to download %s" % url,highlight=1)
			url = "<insert another link to the exploit/advisory here>"
	
	monaConfig = MnConfig()
	thisauthor = monaConfig.get("author")
	if thisauthor == "":
		thisauthor = "<insert your name here>"

	skeletonheader = "##\n"
	skeletonheader += "# This module requires Metasploit: http://metasploit.com/download\n"
	skeletonheader += "# Current source: https://github.com/rapid7/metasploit-framework\n"
	skeletonheader += "##\n\n"
	skeletonheader += "require 'msf/core'\n\n"
	skeletonheader += "class MetasploitModule < Msf::Exploit::Remote\n"
	skeletonheader += "  #Rank definition: https://github.com/rapid7/metasploit-framework/wiki/Exploit-Ranking\n"
	skeletonheader += "  #ManualRanking/LowRanking/AverageRanking/NormalRanking/GoodRanking/GreatRanking/ExcellentRanking\n"
	skeletonheader += "  Rank = NormalRanking\n\n"
	
	if exploittype == "fileformat":
		skeletonheader += "  include Msf::Exploit::FILEFORMAT\n"
	if exploittype == "network client (tcp)":
		skeletonheader += "  include Msf::Exploit::Remote::Tcp\n"
	if exploittype == "network client (udp)":
		skeletonheader += "  include Msf::Exploit::Remote::Udp\n"
		
	if cve.strip() == "":
		cve = "<insert CVE number here>"
		
	skeletoninit = "  def initialize(info = {})\n"
	skeletoninit += "    super(update_info(info,\n"
	skeletoninit += "      'Name'    => '" + name + "',\n"
	skeletoninit += "      'Description'  => %q{\n"
	skeletoninit += "          Provide information about the vulnerability / explain as good as you can\n"
	skeletoninit += "          Make sure to keep each line less than 100 columns wide\n"
	skeletoninit += "      },\n"
	skeletoninit += "      'License'    => MSF_LICENSE,\n"
	skeletoninit += "      'Author'    =>\n"
	skeletoninit += "        [\n"
	skeletoninit += "          '" + originalauthor + "<user[at]domain.com>',  # Original discovery\n"
	skeletoninit += "          '" + thisauthor + "',  # MSF Module\n"		
	skeletoninit += "        ],\n"
	skeletoninit += "      'References'  =>\n"
	skeletoninit += "        [\n"
	skeletoninit += "          [ 'OSVDB', '<insert OSVDB number here>' ],\n"
	skeletoninit += "          [ 'CVE', '" + cve + "' ],\n"
	skeletoninit += "          [ 'URL', '" + url + "' ]\n"
	skeletoninit += "        ],\n"
	skeletoninit += "      'DefaultOptions' =>\n"
	skeletoninit += "        {\n"
	skeletoninit += "          'ExitFunction' => 'process', #none/process/thread/seh\n"
	skeletoninit += "          #'InitialAutoRunScript' => 'migrate -f',\n"	
	skeletoninit += "        },\n"
	skeletoninit += "      'Platform'  => 'win',\n"
	skeletoninit += "      'Payload'  =>\n"
	skeletoninit += "        {\n"
	skeletoninit += "          'BadChars' => \"" + bin2hexstr(badchars) + "\", # <change if needed>\n"
	skeletoninit += "          'DisableNops' => true,\n"
	skeletoninit += "        },\n"
	
	skeletoninit2 = "      'Privileged'  => false,\n"
	skeletoninit2 += "      #Correct Date Format: \"M D Y\"\n"
	skeletoninit2 += "      #Month format: Jan,Feb,Mar,Apr,May,Jun,Jul,Aug,Sep,Oct,Nov,Dec\n"
	skeletoninit2 += "      'DisclosureDate'  => 'MONTH DAY YEAR',\n"
	skeletoninit2 += "      'DefaultTarget'  => 0))\n"
	
	if exploittype.find("network") > -1:
		skeletoninit2 += "\n    register_options([Opt::RPORT(" + str(portnr) + ")], self.class)\n"
	if exploittype.find("fileformat") > -1:
		skeletoninit2 += "\n    register_options([OptString.new('FILENAME', [ false, 'The file name.', 'msf" + extension + "']),], self.class)\n"
	skeletoninit2 += "\n  end\n\n"
	
	return skeletonheader,skeletoninit,skeletoninit2

def shortJump(sizeofinst, offset):
	"""
	Calculate the parameter for a short relative jump from the size of instruction (which can be JMP, JNZ etc...) and the desired offset
	Arguments:
	sizeofinst - the size of the instruction used to achieve the jump
	offset - the desired offset from the address of the instruction
	Return:
	A binary value which can be used along with the jump instruction
	"""
	if (offset - sizeofinst) < -128 or (offset - sizeofinst) > 127:
		dbg.log(" ** short jump too long",highlight=1)
	return struct.pack("b", offset - sizeofinst)

def archValue(x86, x64):
	if arch == 32:
		return x86
	elif arch == 64:
		return x64

def readPtrSizeBytes(ptr):
	if arch == 32:
		return struct.unpack('<L',dbg.readMemory(ptr,4))[0]
	elif arch == 64:
		return struct.unpack('<Q',dbg.readMemory(ptr,8))[0]

def getOsOffset(name):
	osrelease = dbg.getOsRelease()
	osreleaseparts = osrelease.split(".")
	major = int(osreleaseparts[0])
	minor = int(osreleaseparts[1])
	build = int(osreleaseparts[2])

	offset_category = "xp"
	if major == 6 and minor == 0:
		offset_category = "vista"
	elif major == 6 and minor == 1:
		offset_category = "win7"
	elif major == 6 and minor in [2, 3]:
		offset_category = "win8"
	elif major == 10 and minor == 0:
		offset_category = "win10"

	offset_category_index = offset_categories.index(offset_category)

	offset = 0
	curr_category = "xp"
	for c in offset_categories:
		if not c in offsets[name]:
			continue
		if offset_categories.index(c) > offset_category_index:
			break
		curr_category = c
		if curr_category != "win10":
			offset = offsets[name][c]
		else:
			win10offsets = offsets[name][c]
			for o in sorted(win10offsets):
				if o > build:
					break
				curr_build = o
				offset = win10offsets[o]

	return archValue(offset[0], offset[1])

#---------------------------------------#
#   Class to call commands & parse args #
#---------------------------------------#

class MnCommand:
	"""
	Class to call commands, show usage and parse arguments
	"""
	def __init__(self, name, description, usage, parseProc, alias=""):
		self.name = name
		self.description = description
		self.usage = usage
		self.parseProc = parseProc
		self.alias = alias


#---------------------------------------#
#   Class to encode bytes               #
#---------------------------------------#

class MnEncoder:
	""" 
	Class to encode bytes
	"""

	def __init__(self,bytestoencode):
		self.origbytestoencode = bytestoencode
		self.bytestoencode = bytestoencode

	def encodeAlphaNum(self,badchars = []):
		encodedbytes = {}
		if not silent:
			dbg.log("[+] Using alphanum encoder")
			dbg.log("[+] Received %d bytes to encode" % len(self.origbytestoencode))
			dbg.log("[+] Nr of bad chars: %d" % len(badchars))
		# first, check if there are no bad char conflicts
		nobadchars = "\x25\x2a\x2d\x31\x32\x35\x4a\x4d\x4e\x50\x55"
		badbadchars = False
		for b in badchars:
			if b in nobadchars:
				dbg.log("*** Error: byte \\x%s cannot be a bad char with this encoder" % bin2hex(b))
				badbadchars = True

		if badbadchars:
			return {}				

		# if all is well, explode the input to a multiple of 4
		while True:
			moduloresult = len(self.bytestoencode) % 4
			if moduloresult == 0:
				break
			else:
				self.bytestoencode += '\x90'
		if not len(self.bytestoencode) == len(self.origbytestoencode):
			if not silent:
				dbg.log("[+] Added %d nops to make length of input a multiple of 4" % (len(self.bytestoencode) - len(self.origbytestoencode)))

		# break it down into chunks of 4 bytes
		toencodearray = []
		toencodearray = [self.bytestoencode[max(i-4,0):i] for i in range(len(self.bytestoencode), 0, -4)][::-1]
		blockcnt = 1
		encodedline = 0
		# we have to push the blocks in reverse order
		blockcnt = len(toencodearray)
		nrblocks = len(toencodearray)
		while blockcnt > 0:
			if not silent:
				dbg.log("[+] Processing block %d/%d" % (blockcnt,nrblocks))
			encodedbytes[encodedline] = ["\x25\x4a\x4d\x4e\x55","AND EAX,0x554E4D4A"]
			encodedline += 1
			encodedbytes[encodedline] = ["\x25\x35\x32\x31\x2A","AND EAX,0x2A313235"]
			encodedline += 1
	
			opcodes=[]
			startpos=7
			source = "".join(bin2hex(a) for a in toencodearray[blockcnt-1])
			
			origbytes=source[startpos-7]+source[startpos-6]+source[startpos-5]+source[startpos-4]+source[startpos-3]+source[startpos-2]+source[startpos-1]+source[startpos]
			reversebytes=origbytes[6]+origbytes[7]+origbytes[4]+origbytes[5]+origbytes[2]+origbytes[3]+origbytes[0]+origbytes[1]
			revval=hexStrToInt(reversebytes)			   
			twoval=4294967296-revval
			twobytes=toHex(twoval)
			if not silent:	
				dbg.log("Opcode to produce : %s%s %s%s %s%s %s%s" % (origbytes[0],origbytes[1],origbytes[2],origbytes[3],origbytes[4],origbytes[5],origbytes[6],origbytes[7]))
				dbg.log("         reversed : %s%s %s%s %s%s %s%s" % (reversebytes[0],reversebytes[1],reversebytes[2],reversebytes[3],reversebytes[4],reversebytes[5],reversebytes[6],reversebytes[7]))
				dbg.log("                    -----------")				   
				dbg.log("   2's complement : %s%s %s%s %s%s %s%s" % (twobytes[0],twobytes[1],twobytes[2],twobytes[3],twobytes[4],twobytes[5],twobytes[6],twobytes[7]))
		
			#for each byte, start with last one first
			bcnt=3
			overflow=0		
			while bcnt >= 0:
				currbyte=twobytes[(bcnt*2)]+twobytes[(bcnt*2)+1]
				currval=hexStrToInt(currbyte)-overflow
				testval=currval/3

				if testval < 32:
					#put 1 in front of byte
					currbyte="1"+currbyte
					currval=hexStrToInt(currbyte)-overflow
					overflow=1
				else:
					overflow=0

				val1=currval/3
				val2=currval/3
				val3=currval/3
				sumval=val1+val2+val3
				
				if sumval < currval:
					val3 = val3 + (currval-sumval)

				#validate / fix badchars
				
				fixvals=self.validatebadchars_enc(val1,val2,val3,badchars)
				val1="%02x" % fixvals[0]
				val2="%02x" % fixvals[1]
				val3="%02x" % fixvals[2]			
				opcodes.append(val1)
				opcodes.append(val2)
				opcodes.append(val3)
				bcnt=bcnt-1

			# we should now have 12 bytes in opcodes
			if not silent:
				dbg.log("                    -----------")
				dbg.log("                    %s %s %s %s" % (opcodes[9],opcodes[6],opcodes[3],opcodes[0]))
				dbg.log("                    %s %s %s %s" % (opcodes[10],opcodes[7],opcodes[4],opcodes[1]))
				dbg.log("                    %s %s %s %s" % (opcodes[11],opcodes[8],opcodes[5],opcodes[2]))
				dbg.log("")
			thisencodedbyte = "\x2D"
			thisencodedbyte += hex2bin("\\x%s" % opcodes[0])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[3])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[6])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[9])
			encodedbytes[encodedline] = [thisencodedbyte,"SUB EAX,0x%s%s%s%s" % (opcodes[9],opcodes[6],opcodes[3],opcodes[0])]
			encodedline += 1

			thisencodedbyte = "\x2D"
			thisencodedbyte += hex2bin("\\x%s" % opcodes[1])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[4])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[7])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[10])
			encodedbytes[encodedline] = [thisencodedbyte,"SUB EAX,0x%s%s%s%s" % (opcodes[10],opcodes[7],opcodes[4],opcodes[1])]
			encodedline += 1

			thisencodedbyte = "\x2D"
			thisencodedbyte += hex2bin("\\x%s" % opcodes[2])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[5])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[8])
			thisencodedbyte += hex2bin("\\x%s" % opcodes[11])
			encodedbytes[encodedline] = [thisencodedbyte,"SUB EAX,0x%s%s%s%s" % (opcodes[11],opcodes[8],opcodes[5],opcodes[2])]
			encodedline += 1

			encodedbytes[encodedline] = ["\x50","PUSH EAX"]
			encodedline += 1
			
			blockcnt -= 1
	

		return encodedbytes



	def validatebadchars_enc(self,val1,val2,val3,badchars):
		newvals=[]
		allok=0
		giveup=0
		type=0
		origval1=val1
		origval2=val2
		origval3=val3
		d1=0
		d2=0
		d3=0
		lastd1=0
		lastd2=0
		lastd3=0	
		while allok==0 and giveup==0:
			#check if there are bad chars left
			charcnt=0
			val1ok=1
			val2ok=1
			val3ok=1
			while charcnt < len(badchars):
				if (hex2bin("%02x" % val1) in badchars):
					val1ok=0
				if (hex2bin("%02x" % val2) in badchars):
					val2ok=0
				if (hex2bin("%02x" % val3) in badchars):
					val3ok=0
				charcnt=charcnt+1		
			if (val1ok==0) or (val2ok==0) or (val3ok==0):
				allok=0
			else:
				allok=1
			if allok==0:
				#try first by sub 1 from val1 and val2, and add more to val3
				if type==0:
					val1=val1-1
					val2=val2-1
					val3=val3+2
					if (val1<1) or (val2==0) or (val3 > 126):
						val1=origval1
						val2=origval2
						val3=origval3
						type=1
				if type==1:			  
				#then try by add 1 to val1 and val2, and sub more from val3
					val1=val1+1
					val2=val2+1
					val3=val3-2
					if (val1>126) or (val2>126) or (val3 < 1):
						val1=origval1
						val2=origval2
						val3=origval3
						type=2	
				if type==2:
					#try by sub 2 from val1, and add 1 to val2 and val3
					val1=val1-2
					val2=val2+1
					val3=val3+1
					if (val1<1) or (val2>126) or (val3 > 126):
						val1=origval1
						val2=origval2
						val3=origval3
						type=3
				if type==3:
					#try by add 2 to val1, and sub 1 from val2 and val3
					val1=val1+2
					val2=val2-1
					val3=val3-1
					if (val1 > 126) or (val2 < 1) or (val3 < 1):
						val1=origval1
						val2=origval2
						val3=origval3
						type=4
				if type==4:
					if (val1ok==0):
						val1=val1-1
						d1=d1+1
					else:
						#now spread delta over other 2 values
						if (d1 > 0):
							val2=val2+1
							val3=origval3+d1-1
							d1=d1-1
						else:
							val1=0					
					if (val1 < 1) or (val2 > 126) or (val3 > 126):
						val1=origval1
						val2=origval2
						val3=origval3
						d1=0					
						type=5
				if type==5:
					if (val1ok==0):
						val1=val1+1
						d1=d1+1
					else:
						#now spread delta over other 2 values
						if (d1 > 0):
							val2=val2-1
							val3=origval3-d1+1
							d1=d1-1
						else:
							val1=255					
					if (val1>126) or (val2 < 1) or (val3 < 1):
						val1=origval1
						val2=origval2
						val3=origval3
						val1ok=0
						val2ok=0
						val3ok=0					
						d1=0
						d2=0
						d3=0					
						type=6
				if type==6:
					if (val1ok==0):
						val1=val1-1
						#d1=d1+1
					if (val2ok==0):
						val2=val2+1
						#d2=d2+1
					d3=origval1-val1+origval2-val2
					val3=origval3+d3
					if (lastd3==d3) and (d3 > 0):
						val1=origval1
						val2=origval2
						val3=origval3				
						giveup=1
					else:
						lastd3=d3			
					if (val1<1) or (val2 < 1) or (val3 > 126):
						val1=origval1
						val2=origval2
						val3=origval3
						giveup=1
		#check results
		charcnt=0
		val1ok=1
		val2ok=1
		val3ok=1	
		val1text="OK"	
		val2text="OK"
		val3text="OK"	
		while charcnt < len(badchars):
			if (val1 == badchars[charcnt]):
				val1ok=0
				val1text="NOK"			
			if (val2 == badchars[charcnt]):
				val2ok=0
				val2text="NOK"						
			if (val3 == badchars[charcnt]):
				val3ok=0
				val3text="NOK"						
			charcnt=charcnt+1	
			
		if (val1ok==0) or (val2ok==0) or (val3ok==0):
			dbg.log("  ** Unable to fix bad char issue !",highlight=1)
			dbg.log("	  -> Values to check : %s(%s) %s(%s) %s(%s) " % (bin2hex(origval1),val1text,bin2hex(origval2),val2text,bin2hex(origval3),val3text),highlight=1)	
			val1=origval1
			val2=origval2
			val3=origval3		
		newvals.append(val1)
		newvals.append(val2)
		newvals.append(val3)
		return newvals		
		
		
#---------------------------------------#
#   Class to perform call tracing       #
#---------------------------------------#

class MnCallTraceHook(LogBpHook):
	def __init__(self, callptr, showargs, instruction, logfile):
		LogBpHook.__init__(self)
		self.callptr = callptr
		self.showargs = showargs
		self.logfile = logfile
		self.instruction = instruction
	
	def run(self,regs):
		# get instruction at this address
		thisaddress = regs["EIP"]
		thisinstruction = self.instruction
		allargs = []
		argstr = ""
		if thisinstruction.startswith("CALL "):
			if self.showargs > 0:
				for cnt in xrange(self.showargs):
					thisarg = 0
					try:
						thisarg = struct.unpack('<L',dbg.readMemory(regs["ESP"]+(cnt*4),4))[0]
					except:
						thisarg = 0
					allargs.append(thisarg)
					argstr += "0x%08x, " % thisarg
				argstr = argstr.strip(" ")
				argstr = argstr.strip(",")
				#dbg.log("CallTrace : 0x%08x : %s (%s)" % (thisaddress,thisinstruction,argstr),address = thisaddress)
			#else:
				#dbg.log("CallTrace : 0x%08x : %s" % (thisaddress,thisinstruction), address = thisaddress)
			# save to file
			try:
				FILE=open(self.logfile,"a")
				textra = ""
				for treg in dbglib.Registers32BitsOrder:
					if thisinstruction.lower().find(treg.lower()) > -1:
						textra += "%s = 0x%08x, " % (treg,regs[treg])
				if textra != "":
					textra = textra.strip(" ")
					textra = textra.strip(",")
					textra = "(" + textra + ")"
				FILE.write("0x%08x : %s %s\n" % (thisaddress, thisinstruction, textra))
				if self.showargs > 0:
					cnt = 0
					while cnt < len(allargs):
						content = ""
						try:
							bytecontent = dbg.readMemory(allargs[cnt],16)
							content = bin2hex(bytecontent)
						except:
							content = ""
						FILE.write("            Arg%d at 0x%08x : 0x%08x : %s\n" % (cnt,regs["ESP"]+(cnt*4),allargs[cnt],content))
						cnt += 1
				FILE.close()
			except:
				#dbg.log("OOPS", highlight=1)
				pass
		if thisinstruction.startswith("RETN"):
			returnto = 0
			try:
				returnto = struct.unpack('<L',dbg.readMemory(regs["ESP"],4))[0]
			except:
				returnto = 0
			#dbg.log("ReturnTrace : 0x%08x : %s - Return To 0x%08x" % (thisaddress,thisinstruction,returnto), address = thisaddress)
			try:
				FILE=open(self.logfile,"a")
				FILE.write("0x%08x : %s \n" % (thisaddress, thisinstruction))
				FILE.write("            ReturnTo at 0x%08x : 0x%08x\n" % (regs["ESP"],returnto))
				FILE.write("            EAX : 0x%08x\n" % regs["EAX"])
				FILE.close()
			except:
				pass
				
#---------------------------------------#
#   Class to set deferred BP Hooks      #
#---------------------------------------#

class MnDeferredHook(LogBpHook):
	def __init__(self, loadlibraryptr, targetptr):
		LogBpHook.__init__(self)
		self.targetptr = targetptr
		self.loadlibraryptr = loadlibraryptr
		
	def run(self,regs):
		#dbg.log("0x%08x - DLL Loaded, checking for %s" % (self.loadlibraryptr,self.targetptr), highlight=1)
		dbg.pause()
		if self.targetptr.find(".") > -1:
			# function name, try to resolve
			functionaddress = dbg.getAddress(self.targetptr)
			if functionaddress > 0:
				dbg.log("Deferred Breakpoint set at %s (0x%08x)" % (self.targetptr,functionaddress),highlight=1)
				dbg.setBreakpoint(functionaddress)
				self.UnHook()
				dbg.log("Hook removed")
				dbg.run()
				return
		if self.targetptr.find("+") > -1:
			ptrparts = self.targetptr.split("+")
			modname = ptrparts[0]
			if not modname.lower().endswith(".dll"):
				modname += ".dll" 
			themodule = getModuleObj(modname)
			if themodule != None and len(ptrparts) > 1:
				address = themodule.getBase() + int(ptrparts[1],16)
				if address > 0:
					dbg.log("Deferred Breakpoint set at %s (0x%08x)" % (self.targetptr,address),highlight=1)
					dbg.setBreakpoint(address)
					self.UnHook()
					dbg.log("Hook removed")
					dbg.run()
					return
		if self.targetptr.find("+") == -1 and self.targetptr.find(".") == -1:
			address = int(self.targetptr,16)
			thispage = dbg.getMemoryPageByAddress(address)
			if thispage != None:
				dbg.setBreakpoint(address)
				dbg.log("Deferred Breakpoint set at 0x%08x" % address, highlight=1)
				self.UnHook()
				dbg.log("Hook removed")
		dbg.run()

#---------------------------------------#
#   Class to access config file         #
#---------------------------------------#
class MnConfig:
	"""
	Class to perform config file operations
	"""
	def __init__(self):
	
		global configwarningshown
		self.configfile = "mona.ini"
		self.currpath = os.path.dirname(os.path.realpath(self.configfile))
		# first check if we will be saving the file into Immunity folder
		if __DEBUGGERAPP__ == "Immunity Debugger":
			if not os.path.exists(os.path.join(self.currpath,"immunitydebugger.exe")):
				if not configwarningshown:
					dbg.log(" ** Warning: using mona.ini file from %s" % self.currpath, highlight=True)
					configwarningshown = True
	
	def get(self,parameter):
		"""
		Retrieves the contents of a given parameter from the config file
		or from memory if the config file has been read already
		(configFileCache)
		Arguments:
		parameter - the name of the parameter 

		Return:
		A string, containing the contents of that parameter
		"""	
		#read config file
		#format :  parameter=value
		toreturn = ""
		curparam=[]
		global configFileCache
		#first check if parameter already exists in global cache
		if parameter.strip().lower() in configFileCache:
			toreturn = configFileCache[parameter.strip().lower()]
			#dbg.log("Found parameter %s in cache: %s" % (parameter, toreturn))
		else:
			if os.path.exists(self.configfile):
				try:
					configfileobj = open(self.configfile,"rb")
					content = configfileobj.readlines()
					configfileobj.close()
					for thisLine in content:
						if not thisLine[0] == "#":
							currparam = thisLine.split('=')
							if currparam[0].strip().lower() == parameter.strip().lower() and len(currparam) > 1:
								#get value
								currvalue = ""
								i=1
								while i < len(currparam):
									currvalue = currvalue + currparam[i] + "="
									i += 1
								toreturn = currvalue.rstrip("=").replace('\n','').replace('\r','')
								# drop into global cache for next time
								configFileCache[parameter.strip().lower()] = toreturn
								#dbg.log("Read parameter %s from file: %s" % (parameter, toreturn))
				except:
					toreturn=""
		
		return toreturn
	
	def set(self,parameter,paramvalue):
		"""
		Sets/Overwrites the contents of a given parameter in the config file

		Arguments:
		parameter - the name of the parameter 
		paramvalue - the new value of the parameter

		Return:
		nothing
		"""
		global configFileCache
		configFileCache[parameter.strip().lower()] = paramvalue
		if os.path.exists(self.configfile):
			#modify file
			try:
				configfileobj = open(self.configfile,"r")
				content = configfileobj.readlines()
				configfileobj.close()
				newcontent = []
				paramfound = False
				for thisLine in content:
					thisLine = thisLine.replace('\n','').replace('\r','')
					if not thisLine[0] == "#":
						currparam = thisLine.split('=')
						if currparam[0].strip().lower() == parameter.strip().lower():
							newcontent.append(parameter+"="+paramvalue+"\n")
							paramfound = True
						else:
							newcontent.append(thisLine+"\n")
					else:
						newcontent.append(thisLine+"\n")
				if not paramfound:
					newcontent.append(parameter+"="+paramvalue+"\n")
				#save new config file (rewrite)
				dbg.log("[+] Saving config file, modified parameter %s" % parameter)
				FILE=open(self.configfile,"w")
				FILE.writelines(newcontent)
				FILE.close()
				dbg.log("     mona.ini saved under %s" % self.currpath)
			except:
				dbg.log("Error writing config file : %s : %s" % (sys.exc_type,sys.exc_value),highlight=1)
				return ""
		else:
			#create new file
			try:
				dbg.log("[+] Creating config file, setting parameter %s" % parameter)
				FILE=open(self.configfile,"w")
				FILE.write("# -----------------------------------------------#\n")
				FILE.write("# !mona.py configuration file                    #\n")
				FILE.write("# Corelan Team - https://www.corelan.be          #\n") 
				FILE.write("# -----------------------------------------------#\n")
				FILE.write(parameter+"="+paramvalue+"\n")
				FILE.close()
			except:
				dbg.log(" ** Error writing config file", highlight=1)
				return ""
		return ""
	
	
#---------------------------------------#
#   Class to log entries to file        #
#---------------------------------------#
class MnLog:
	"""
	Class to perform logfile operations
	"""
	def __init__(self, filename):
		
		self.filename = filename
		
			
	def reset(self,clear=True,showheader=True):
		"""
		Optionally clears a log file, write a header to the log file and return filename

		Optional :
		clear = Boolean. When set to false, the logfile won't be cleared. This method can be
		used to retrieve the full path to the logfile name of the current MnLog class object
		Logfiles are written to the debugger program folder, unless a config value 'workingfolder' is set.

		Return:
		full path to the logfile name.
		"""	
		global noheader
		if clear:
			if not silent:
				dbg.log("[+] Preparing output file '" + self.filename +"'")
		if not showheader:
			noheader = True
		debuggedname = dbg.getDebuggedName()
		thispid = dbg.getDebuggedPid()
		if thispid == 0:
			debuggedname = "_no_name_"
		thisconfig = MnConfig()
		workingfolder = thisconfig.get("workingfolder").rstrip("\\").strip()
		#strip extension from debuggedname
		parts = debuggedname.split(".")
		extlen = len(parts[len(parts)-1])+1
		debuggedname = debuggedname[0:len(debuggedname)-extlen]
		debuggedname = debuggedname.replace(" ","_")
		workingfolder = workingfolder.replace('%p', debuggedname)
		workingfolder = workingfolder.replace('%i', str(thispid))		
		logfile = workingfolder + "\\" + self.filename
		#does working folder exist ?
		if workingfolder != "":
			if not os.path.exists(workingfolder):
				try:
					dbg.log("    - Creating working folder %s" % workingfolder)
					#recursively create folders
					os.makedirs(workingfolder)
					dbg.log("    - Folder created")
				except:
					dbg.log("   ** Unable to create working folder %s, the debugger program folder will be used instead" % workingfolder,highlight=1)
					logfile = self.filename
		else:
			logfile = self.filename
		if clear:
			if not silent:
				dbg.log("    - (Re)setting logfile %s" % logfile)
			try:
				if os.path.exists(logfile):
					try:
						os.delete(logfile+".old")
					except:
						pass
					try:
						os.rename(logfile,logfile+".old")
					except:
						try:
							os.rename(logfile,logfile+".old2")
						except:
							pass
			except:
				pass
			#write header
			if not noheader:
				try:
					with open(logfile,"w") as fh:
						fh.write("=" * 80 + '\n')
						thisversion,thisrevision = getVersionInfo(inspect.stack()[0][1])
						thisversion = thisversion.replace("'","")
						fh.write("  Output generated by mona.py v"+thisversion+", rev "+thisrevision+" - " + __DEBUGGERAPP__ + "\n")
						fh.write("  Corelan Team - https://www.corelan.be\n")
						fh.write("=" * 80 + '\n')
						osver=dbg.getOsVersion()
						osrel=dbg.getOsRelease()
						fh.write("  OS : " + osver + ", release " + osrel + "\n")
						fh.write("  Process being debugged : " + debuggedname +" (pid " + str(thispid) + ")\n")
						currmonaargs = " ".join(x for x in currentArgs)
						fh.write("  Current mona arguments: %s\n" % currmonaargs)
						fh.write("=" * 80 + '\n')
						fh.write("  " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n")
						fh.write("=" * 80 + '\n')
				except:
					pass
			else:
				try:
					with open(logfile,"w") as fh:
						fh.write("")
				except:
					pass
			#write module table
			try:
				if not ignoremodules:
					showModuleTable(logfile)
			except:
				pass
		return logfile
		
	def write(self,entry,logfile):
		"""
		Write an entry (can be multiline) to a given logfile

		Arguments:
		entry - the data to write to the logfile
		logfile - the full path to the logfile

		Return:
		nothing
		"""		
		towrite = ""
		#check if entry is int 
		if type(entry) == int:
			if entry > 0:
				ptrx = MnPointer(entry)
				modname = ptrx.belongsTo()
				modinfo = MnModule(modname)
				towrite = "0x" + toHex(entry) + " : " + ptrx.__str__() + " " + modinfo.__str__()
			else:
				towrite = entry
		else:
			towrite = entry
		# if this fails, we got an unprintable character
		try:
			towrite = str(towrite)
		except:
			# one at a time
			towrite2 = ""
			for c in towrite:
				try:
					towrite2 += str(c)
				except:
					towrite2 += "\\x" + str(hex(ord(c))).replace("0x","")
			towrite = towrite2
		try:
			with open(logfile,"a") as fh:
				if towrite.find('\n') > -1:
					fh.writelines(towrite)
				else:
					fh.write(towrite+"\n")
		except:
			pass
		return True
	

#---------------------------------------#
#  Simple Queue class                   #
#---------------------------------------#
class MnQueue:
	"""
	Simple queue class
	"""
	def __init__(self):
		self.holder = []
		
	def enqueue(self,val):
		self.holder.append(val)
		
	def dequeue(self):
		val = None
		try:
			val = self.holder[0]
			if len(self.holder) == 1:
				self.holder = []
			else:
				self.holder = self.holder[1:]	
		except:
			pass
			
		return val	
		
	def IsEmpty(self):
		result = False
		if len(self.holder) == 0:
			result = True
		return result	


#---------------------------------------#
#  Class to access module properties    #
#---------------------------------------#
	
class MnModule:
	"""
	Class to access module properties
	"""
	def __init__(self, modulename):
		#dbg.log("MnModule(%s)" % modulename)
		modisaslr = True
		modissafeseh = True
		modrebased = True
		modisnx = True
		modisos = True
		self.IAT = {}
		self.EAT = {}
		path = ""
		mzbase = 0
		mzsize = 0
		mztop = 0
		mcodebase = 0
		mcodesize = 0
		mcodetop = 0
		mentry = 0
		mversion = ""
		self.internalname = modulename
		if modulename != "":
			# if info is cached, retrieve from cache
			if ModInfoCached(modulename):
				modisaslr = getModuleProperty(modulename,"aslr")
				modissafeseh = getModuleProperty(modulename,"safeseh")
				modrebased = getModuleProperty(modulename,"rebase")
				modisnx = getModuleProperty(modulename,"nx")
				modisos = getModuleProperty(modulename,"os")
				path = getModuleProperty(modulename,"path")
				mzbase = getModuleProperty(modulename,"base")
				mzsize = getModuleProperty(modulename,"size")
				mztop = getModuleProperty(modulename,"top")
				mversion = getModuleProperty(modulename,"version")
				mentry = getModuleProperty(modulename,"entry")
				mcodebase = getModuleProperty(modulename,"codebase")
				mcodesize = getModuleProperty(modulename,"codesize")
				mcodetop = getModuleProperty(modulename,"codetop")
			else:
				#gather info manually - this code should only get called from populateModuleInfo()
				self.moduleobj = dbg.getModule(modulename)
				modissafeseh = True
				modisaslr = True
				modisnx = True
				modrebased = False
				modisos = False
				#if self.moduleobj == None:
				#	dbg.log("*** Error - self.moduleobj is None, key %s" % modulename, highlight=1)
				mod       = self.moduleobj
				mzbase    = mod.getBaseAddress()
				mzrebase  = mod.getFixupbase()
				mzsize    = mod.getSize()
				mversion  = mod.getVersion()
				mentry    = mod.getEntry() 
				mcodebase = mod.getCodebase()
				mcodesize = mod.getCodesize()
				mcodetop  = mcodebase + mcodesize
				
				mversion=mversion.replace(", ",".")
				mversionfields=mversion.split('(')
				mversion=mversionfields[0].replace(" ","")
								
				if mversion=="":
					mversion="-1.0-"
				path=mod.getPath()
				if mod.getIssystemdll() == 0:
					modisos = "WINDOWS" in path.upper()
				else:
					modisos = True
				mztop = mzbase + mzsize
				if mzbase > 0:
					peoffset=struct.unpack('<L',dbg.readMemory(mzbase+0x3c,4))[0]
					pebase=mzbase+peoffset
					osver=dbg.getOsVersion()
					safeseh_offset = [0x5f, 0x5f, 0x5e]
					safeseh_flag = [0x4, 0x4, 0x400]
					os_index = 0
					# Vista / Win7 / Win8
					if win7mode:
						os_index = 2
					flags=struct.unpack('<H',dbg.readMemory(pebase+safeseh_offset[os_index],2))[0]
					numberofentries=struct.unpack('<L',dbg.readMemory(pebase+0x74,4))[0]
					#safeseh ?
					if (flags&safeseh_flag[os_index])!=0:
						modissafeseh=True
					else:
						if numberofentries>10:
							sectionaddress,sectionsize=struct.unpack('<LL',dbg.readMemory(pebase+0x78+8*10,8))
							sectionaddress+=mzbase
							data=struct.unpack('<L',dbg.readMemory(sectionaddress,4))[0]
							condition = False
							if os_index < 2:
								condition=(sectionsize!=0) and ((sectionsize==0x40) or (sectionsize==data))
							else:
								condition=(sectionsize!=0) and ((sectionsize==0x40))
							if condition==False:
								modissafeseh=False
							else:
								sehlistaddress,sehlistsize=struct.unpack('<LL',dbg.readMemory(sectionaddress+0x40,8))
								if sehlistaddress!=0 and sehlistsize!=0:
									modissafeseh=True
								else:
									modissafeseh=False
				
					#aslr
					if (flags&0x0040)==0:  # 'IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE
						modisaslr=False
					#nx
					if (flags&0x0100)==0:
						modisnx=False
					#rebase
					if mzrebase != mzbase:
						modrebased=True
		else:
			# should never be hit
			#print "No module specified !!!"
			#print "stacktrace : "
			#print traceback.format_exc()
			return None

		#check if module is excluded
		thisconfig = MnConfig()
		allexcluded = []
		excludedlist = thisconfig.get("excluded_modules")
		modfound = False
		if excludedlist:
			allexcluded = excludedlist.split(',')
			for exclentry in allexcluded:
				if exclentry.lower().strip() == modulename.lower().strip():
					modfound = True
		self.isExcluded = modfound
		
		#done - populate variables
		self.isAslr = modisaslr
		
		self.isSafeSEH = modissafeseh
		
		self.isRebase = modrebased
		
		self.isNX = modisnx
		
		self.isOS = modisos
		
		self.moduleKey = modulename
	
		self.modulePath = path
		
		self.moduleBase = mzbase
		
		self.moduleSize = mzsize
		
		self.moduleTop = mztop
		
		self.moduleVersion = mversion
		
		self.moduleEntry = mentry
		
		self.moduleCodesize = mcodesize
		
		self.moduleCodetop = mcodetop
		
		self.moduleCodebase = mcodebase
		
			
	
	def __str__(self):
		#return general info about the module
		#modulename + info
		"""
		Get information about a module (human readable format)

		Arguments:
		None

		Return:
		String with various properties about a module
		"""			
		outstring = ""
		if self.moduleKey != "":
			outstring = "[" + self.moduleKey + "] ASLR: " + str(self.isAslr) + ", Rebase: " + str(self.isRebase) + ", SafeSEH: " + str(self.isSafeSEH) + ", OS: " + str(self.isOS) + ", v" + self.moduleVersion + " (" + self.modulePath + ")"
		else:
			outstring = "[None]"
		return outstring
		
	def isAslr(self):
		return self.isAslr
		
	def isSafeSEH(self):
		return self.isSafeSEH
		
	def isRebase(self):
		return self.isRebase
		
	def isOS(self):
		return self.isOS
	
	def isNX(self):
		return self.isNX
		
	def moduleKey(self):
		return self.moduleKey
		
	def modulePath(self):
		return self.modulePath
	
	def moduleBase(self):
		return self.moduleBase
	
	def moduleSize(self):
		return self.moduleSize
	
	def moduleTop(self):
		return self.moduleTop
	
	def moduleEntry(self):
		return self.moduleEntry
		
	def moduleCodebase(self):
		return self.moduleCodebase
	
	def moduleCodesize(self):
		return self.moduleCodesize
		
	def moduleCodetop(self):
		return self.moduleCodetop
		
	def moduleVersion(self):
		return self.moduleVersion
		
	def isExcluded(self):
		return self.isExcluded
	
	def getFunctionCalls(self,criteria={}):
		funccalls = {}
		sequences = []
		sequences.append(["call","\xff\x15"])
		funccalls = searchInRange(sequences, self.moduleBase, self.moduleTop,criteria)
		return funccalls
		
	def getIAT(self):
		IAT = {}
		global IATCache
		dbg.logLines("    Getting IAT for %s." % (self.moduleKey))
		try:
			if not self.moduleKey in IATCache:  # if len(self.IAT) == 0:
				dbg.log("    Enumerating IAT")          
				try:
					themod = dbg.getModule(self.moduleKey)
					syms = themod.getSymbols()
					thename = ""
					for sym in syms:
						if syms[sym].getType().startswith("Import"):
							thename = syms[sym].getName()
							theaddress = syms[sym].getAddress()
							if not theaddress in IAT:
								IAT[theaddress] = thename
				except:
					import traceback
					dbg.logLines(traceback.format_exc())
					pass
				# merge
				
				# find optional header
				PEHeader_ref = self.moduleBase + 0x3c
				PEHeader_location = self.moduleBase + struct.unpack('<L',dbg.readMemory(PEHeader_ref,4))[0]
				# do we have an optional header ?
				bsizeOfOptionalHeader = dbg.readMemory(PEHeader_location+0x14,2)
				sizeOfOptionalHeader = struct.unpack('<L',bsizeOfOptionalHeader+"\x00\x00")[0]
				OptionalHeader_location = PEHeader_location + 0x18
				if sizeOfOptionalHeader > 0:
					# get address of DataDirectory
					DataDirectory_location = OptionalHeader_location + 0x60
					# get size of Import Table
					importtable_size = struct.unpack('<L',dbg.readMemory(DataDirectory_location+0x64,4) )[0]
					importtable_rva = struct.unpack('<L',dbg.readMemory(DataDirectory_location+0x60,4) )[0]
					iatAddr = self.moduleBase + importtable_rva
					max_nr_entries = importtable_size / 4
					iatcnt = 0
					while iatcnt < max_nr_entries:
						thisloc = iatAddr + (4*iatcnt)
						iatEntry = struct.unpack('<L',dbg.readMemory(thisloc,4) )[0]
						if iatEntry > 0:
							ptr = iatEntry
							ptrx = MnPointer(iatEntry)
							modname = ptrx.belongsTo()
							tmod = MnModule(modname)
							thisfunc = dbglib.Function(dbg,ptr)
							thisfuncfullname = thisfunc.getName().lower()
							if thisfuncfullname.endswith(".unknown") or thisfuncfullname.endswith(".%08x" % ptr):
								if not tmod is None:
									imagename = tmod.getShortName()
									eatlist = tmod.getEAT()
									if iatEntry in eatlist:
										thisfuncfullname =  "." + imagename + "!" + eatlist[iatEntry]	
										thisfuncname = thisfuncfullname.split('.')
										IAT[thisloc] = thisfuncname[1].strip(">")
									else:
										IAT[thisloc] = imagename + "!0x%08x" % iatEntry
							else:	
								IAT[thisloc] = thisfuncfullname.replace(".","!")
						iatcnt += 1
				
				if len(IAT) == 0:
					#search method nr 2, not accurate, but will find *something*
					funccalls = self.getFunctionCalls()
					for functype in funccalls:
						for fptr in funccalls[functype]:
							ptr=struct.unpack('<L',dbg.readMemory(fptr+2,4))[0]
							if ptr >= self.moduleBase and ptr <= self.moduleTop:
								if not ptr in IAT:
									thisfunc = dbglib.Function(dbg,ptr)
									thisfuncfullname = thisfunc.getName().lower()
									thisfuncname = []
									if thisfuncfullname.endswith(".unknown") or thisfuncfullname.endswith(".%08x" % ptr):
										iatptr = struct.unpack('<L',dbg.readMemory(ptr,4))[0]
										# see if we can find the original function name using the EAT
										tptr = MnPointer(ptr)
										modname = tptr.belongsTo()
										tmod = MnModule(modname)
										ofullname = thisfuncfullname
										
										if not tmod is None:
											imagename = tmod.getShortName()
											eatlist = tmod.getEAT()
											if iatptr in eatlist:
												thisfuncfullname =  "." + imagename + "!" + eatlist[iatptr]
										if thisfuncfullname == ofullname:
											tparts = thisfuncfullname.split('.')
											thisfuncfullname = tparts[0] + (".%08x" % iatptr)
									thisfuncname = thisfuncfullname.split('.')
									IAT[ptr] = thisfuncname[1].strip(">")
									
				self.IAT = IAT
				IATCache[self.moduleKey] = IAT
			else:
				dbg.log("    Retrieving IAT from cache")             
				IAT = IATCache[self.moduleKey] #IAT = self.IAT
		except:
			import traceback
			dbg.logLines(traceback.format_exc())
			return IAT
		return IAT
		
		
	def getEAT(self):
		eatlist = {}
		if len(self.EAT) == 0:
			try:
				# avoid major suckage, let's do it ourselves
				# find optional header
				PEHeader_ref = self.moduleBase + 0x3c
				PEHeader_location = self.moduleBase + struct.unpack('<L',dbg.readMemory(PEHeader_ref,4))[0]
				# do we have an optional header ?
				bsizeOfOptionalHeader = dbg.readMemory(PEHeader_location+0x14,2)
				sizeOfOptionalHeader = struct.unpack('<L',bsizeOfOptionalHeader+"\x00\x00")[0]
				OptionalHeader_location = PEHeader_location + 0x18
				if sizeOfOptionalHeader > 0:
					# get address of DataDirectory
					DataDirectory_location = OptionalHeader_location + 0x60
					# get size of Export Table
					exporttable_size = struct.unpack('<L',dbg.readMemory(DataDirectory_location+4,4) )[0]
					exporttable_rva = struct.unpack('<L',dbg.readMemory(DataDirectory_location,4) )[0]
					if exporttable_size > 0:
						# get start of export table
						eatAddr = self.moduleBase + exporttable_rva
						nr_of_names = struct.unpack('<L',dbg.readMemory(eatAddr + 0x18,4))[0]
						rva_of_names = self.moduleBase + struct.unpack('<L',dbg.readMemory(eatAddr + 0x20,4))[0]
						address_of_functions =  self.moduleBase + struct.unpack('<L',dbg.readMemory(eatAddr + 0x1c,4))[0]
						for i in range(0, nr_of_names):
							eatName = dbg.readString(self.moduleBase + struct.unpack('<L',dbg.readMemory(rva_of_names + (4 * i),4))[0])
							eatAddress = self.moduleBase + struct.unpack('<L',dbg.readMemory(address_of_functions + (4 * i),4))[0]
							eatlist[eatAddress] = eatName
				self.EAT = eatlist
			except:
				return eatlist
		else:
			eatlist = self.EAT
		return eatlist
	
	
	def getShortName(self):
		return stripExtension(self.moduleKey)


def getNtGlobalFlag():
	pebaddress = dbg.getPEBAddress()
	global NtGlobalFlag
	if NtGlobalFlag == -1:
		try:
			NtGlobalFlag = struct.unpack('<L',dbg.readMemory(pebaddress+0x068,4))[0]
		except:
			NtGlobalFlag = 0
	return NtGlobalFlag

def getNtGlobalFlagDefinitions():
	definitions = {}
	
	definitions[0x0]		= ["","No GFlags enabled"]
	
	definitions[0x00000001]	= ["soe", "Stop On Execute"]
	definitions[0x00000002]	= ["sls", "Show Loader Snaps"]
	definitions[0x00000004]	= ["dic", "Debug Initial Command"]
	definitions[0x00000008]	= ["shg", "Stop On Hung GUI"]
	
	definitions[0x00000010]	= ["htc", "Enable Heap Tail Checking"]
	definitions[0x00000020]	= ["hfc", "Enable Heap Free Checking"]
	definitions[0x00000040]	= ["hpc", "Enable Heap Parameter Checking"]
	definitions[0x00000080]	= ["hvc", "Enable Heap Validation On Call"]
	
	definitions[0x00000100]	= ["vrf", "Enable Application Verifier"]
	definitions[0x00000200]	= ["   ", "Enable Silent Process Exit Monitoring"]
	if not win7mode:
		definitions[0x00000400]	= ["ptg", "Enable Pool Tagging"]
	definitions[0x00000800]	= ["htg", "Enable Heap Tagging"]
	
	definitions[0x00001000]	= ["ust", "Create User Mode Stack Trace"]
	definitions[0x00002000]	= ["kst", "Create Kernel Mode Stack Trace"]
	definitions[0x00004000]	= ["otl", "Maintain A List Of Objects For Each Type"]
	definitions[0x00008000]	= ["htd", "Enable Heap Tagging By DLL"]
	
	definitions[0x00010000]	= ["dse", "Disable Stack Extension"]
	definitions[0x00020000]	= ["d32", "Enable Debugging Of Win32 Subsystem"]
	definitions[0x00040000]	= ["ksl", "Enable Loading Of Kernel Debugger Symbols"]
	definitions[0x00080000]	= ["dps", "Disable Paging Of Kernel Stacks"]
	
	definitions[0x00100000]	= ["scb", "Enable System Critical Breaks"]
	definitions[0x00200000]	= ["dhc", "Disable Heap Coalesce On Free"]
	definitions[0x00400000]	= ["ece", "Enable Close Exception"]
	definitions[0x00800000]	= ["eel", "Enable Exception Logging"]
	
	definitions[0x01000000]	= ["eot", "Early Object Handle Type Tagging"]
	definitions[0x02000000]	= ["hpa", "Enable Page Heap"]
	definitions[0x04000000]	= ["dwl", "Debug WinLogon"]
	definitions[0x08000000]	= ["ddp", "Buffer DbgPrint Output"]

	definitions[0x10000000] = ["cse", "Early Critical Section Event Creation"]
	definitions[0x40000000] = ["bhd", "Disable Bad Handles Detection"]
	definitions[0x80000000]	= ["dpd", "Disable Protected DLL Verification"]
	
	return definitions



def getNtGlobalFlagValues(flag):
	allvalues = []
	for defvalue in getNtGlobalFlagDefinitions():
		if defvalue > 0:
			allvalues.append(defvalue)
	# sort list descending
	allvalues.sort(reverse=True)
	flagvalues = []
	remaining = flag
	for flagvalue in allvalues:
		if flagvalue <= remaining:
			remaining -= flagvalue
			if remaining >= 0:
				flagvalues.append(flagvalue)
	return flagvalues

def getNtGlobalFlagNames(flag):
	names = []
	allvalues = getNtGlobalFlagDefinitions()
	currentvalues = getNtGlobalFlagValues(flag)
	for defvalue in currentvalues:
		if defvalue > 0:
			names.append(allvalues[defvalue][0])
	return names

def getNtGlobalFlagValueData(flagvalue):
	toreturn = ["",""]
	if flagvalue in getNtGlobalFlagDefinitions():
		toreturn = getNtGlobalFlagDefinitions()[flagvalue]
	return toreturn


def getActiveFlagNames(flagvalue):
	currentflags = getNtGlobalFlagValues(flagvalue)
	flagdefs = getNtGlobalFlagDefinitions()
	flagnames = []
	if len(currentflags) == 0:
		currentflags = [0]
	for flag in currentflags:
		if flag in flagdefs:
			flagdata = flagdefs[flag]
			flagnames.append(flagdata[0])
	return ",".join(flagnames)


def getNtGlobalFlagValueName(flagvalue):
	data = getNtGlobalFlagValueData(flagvalue)
	toreturn = ""
	if data[0] != "":
		toreturn += "+" + data[0]
	else:
		toreturn += "    "
	toreturn += " - "
	toreturn += data[1]
	return toreturn


#---------------------------------------#
#  Class for heap structures            #
#---------------------------------------#		
class MnHeap:
	"""
	Class for heap structures
	"""
	heapbase = 0
	EncodeFlagMask = 0
	Encoding = 0

	# _HEAP
	# Windows XP
	# ----------
	# +0x000 Entry            : _HEAP_ENTRY
	# +0x008 Signature        : Uint4B
	# +0x00c Flags            : Uint4B
	# +0x010 ForceFlags       : Uint4B
	# +0x014 VirtualMemoryThreshold : Uint4B
	# +0x018 SegmentReserve   : Uint4B
	# +0x01c SegmentCommit    : Uint4B
	# +0x020 DeCommitFreeBlockThreshold : Uint4B
	# +0x024 DeCommitTotalFreeThreshold : Uint4B
	# +0x028 TotalFreeSize    : Uint4B
	# +0x02c MaximumAllocationSize : Uint4B
	# +0x030 ProcessHeapsListIndex : Uint2B
	# +0x032 HeaderValidateLength : Uint2B
	# +0x034 HeaderValidateCopy : Ptr32 Void
	# +0x038 NextAvailableTagIndex : Uint2B
	# +0x03a MaximumTagIndex  : Uint2B
	# +0x03c TagEntries       : Ptr32 _HEAP_TAG_ENTRY
	# +0x040 UCRSegments      : Ptr32 _HEAP_UCR_SEGMENT
	# +0x044 UnusedUnCommittedRanges : Ptr32 _HEAP_UNCOMMMTTED_RANGE
	# +0x048 AlignRound       : Uint4B
	# +0x04c AlignMask        : Uint4B
	# +0x050 VirtualAllocdBlocks : _LIST_ENTRY
	# +0x058 Segments         : [64] Ptr32 _HEAP_SEGMENT
	# +0x158 u                : __unnamed
	# +0x168 u2               : __unnamed
	# +0x16a AllocatorBackTraceIndex : Uint2B
	# +0x16c NonDedicatedListLength : Uint4B
	# +0x170 LargeBlocksIndex : Ptr32 Void
	# +0x174 PseudoTagEntries : Ptr32 _HEAP_PSEUDO_TAG_ENTRY
	# +0x178 FreeLists        : [128] _LIST_ENTRY
	# +0x578 LockVariable     : Ptr32 _HEAP_LOCK
	# +0x57c CommitRoutine    : Ptr32     long 
	# +0x580 FrontEndHeap     : Ptr32 Void
	# +0x584 FrontHeapLockCount : Uint2B
	# +0x586 FrontEndHeapType : UChar
	# +0x587 LastSegmentIndex : UChar

	# Windows 7
	# ---------
	# +0x000 Entry            : _HEAP_ENTRY
	# +0x008 SegmentSignature : Uint4B
	# +0x00c SegmentFlags     : Uint4B
	# +0x010 SegmentListEntry : _LIST_ENTRY
	# +0x018 Heap             : Ptr32 _HEAP
	# +0x01c BaseAddress      : Ptr32 Void
	# +0x020 NumberOfPages    : Uint4B
	# +0x024 FirstEntry       : Ptr32 _HEAP_ENTRY
	# +0x028 LastValidEntry   : Ptr32 _HEAP_ENTRY
	# +0x02c NumberOfUnCommittedPages : Uint4B
	# +0x030 NumberOfUnCommittedRanges : Uint4B
	# +0x034 SegmentAllocatorBackTraceIndex : Uint2B
	# +0x036 Reserved         : Uint2B
	# +0x038 UCRSegmentList   : _LIST_ENTRY
	# +0x040 Flags            : Uint4B
	# +0x044 ForceFlags       : Uint4B
	# +0x048 CompatibilityFlags : Uint4B
	# +0x04c EncodeFlagMask   : Uint4B
	# +0x050 Encoding         : _HEAP_ENTRY
	# +0x058 PointerKey       : Uint4B
	# +0x05c Interceptor      : Uint4B
	# +0x060 VirtualMemoryThreshold : Uint4B
	# +0x064 Signature        : Uint4B
	# +0x068 SegmentReserve   : Uint4B
	# +0x06c SegmentCommit    : Uint4B
	# +0x070 DeCommitFreeBlockThreshold : Uint4B
	# +0x074 DeCommitTotalFreeThreshold : Uint4B
	# +0x078 TotalFreeSize    : Uint4B
	# +0x07c MaximumAllocationSize : Uint4B
	# +0x080 ProcessHeapsListIndex : Uint2B
	# +0x082 HeaderValidateLength : Uint2B
	# +0x084 HeaderValidateCopy : Ptr32 Void
	# +0x088 NextAvailableTagIndex : Uint2B
	# +0x08a MaximumTagIndex  : Uint2B
	# +0x08c TagEntries       : Ptr32 _HEAP_TAG_ENTRY
	# +0x090 UCRList          : _LIST_ENTRY
	# +0x098 AlignRound       : Uint4B
	# +0x09c AlignMask        : Uint4B
	# +0x0a0 VirtualAllocdBlocks : _LIST_ENTRY
	# +0x0a8 SegmentList      : _LIST_ENTRY
	# +0x0b0 AllocatorBackTraceIndex : Uint2B
	# +0x0b4 NonDedicatedListLength : Uint4B
	# +0x0b8 BlocksIndex      : Ptr32 Void
	# +0x0bc UCRIndex         : Ptr32 Void
	# +0x0c0 PseudoTagEntries : Ptr32 _HEAP_PSEUDO_TAG_ENTRY
	# +0x0c4 FreeLists        : _LIST_ENTRY
	# +0x0cc LockVariable     : Ptr32 _HEAP_LOCK
	# +0x0d0 CommitRoutine    : Ptr32     long 
	# +0x0d4 FrontEndHeap     : Ptr32 Void
	# +0x0d8 FrontHeapLockCount : Uint2B
	# +0x0da FrontEndHeapType : UChar
	# +0x0dc Counters         : _HEAP_COUNTERS
	# +0x130 TuningParameters : _HEAP_TUNING_PARAMETERS	
	
	def __init__(self,address):
		self.heapbase = address
		self.VirtualAllocdBlocks = {}
		self.LookAsideList = {}
		self.SegmentList = {}
		self.lalheads = {}
		self.Encoding = 0
		self.FrontEndHeap = 0
		return None


	def getEncodingKey(self):
		"""
		Retrieves the Encoding key from the current heap

		Return: Int, containing the Encoding key (on Windows 7 and up)
		or zero on older Operating Systems
		"""
		self.Encoding = 0
		if win7mode:
			offset = archValue(0x4c,0x7c)
			self.EncodeFlagMask = struct.unpack('<L',dbg.readMemory(self.heapbase+offset,4))[0]
			if self.EncodeFlagMask == 0x100000:
				if arch == 32:
					self.Encoding = struct.unpack('<L',dbg.readMemory(self.heapbase+0x50,4))[0]
				elif arch == 64:
					self.Encoding = struct.unpack('<L',dbg.readMemory(self.heapbase+0x80+0x8,4))[0]
		return self.Encoding


	def getHeapChunkHeaderAtAddress(self,thischunk,headersize=8,type="chunk"):
		"""
		Will convert the bytes placed at a certain address into an MnChunk object
		"""

		key = self.getEncodingKey()
		fullheaderbin = ""
		if type == "chunk" or type == "lal" or type == "freelist":
			chunktype = "chunk"
			if key == 0 and not win7mode:
				fullheaderbin = dbg.readMemory(thischunk,headersize)
			else:
				fullheaderbin = decodeHeapHeader(thischunk,headersize,key)
			# if we have heap corruption, thischunk may not be a readable address
			# so fullheaderbin would be empty
			if len(fullheaderbin) == headersize:
				sizebytes = fullheaderbin[0:2]
				thissize = struct.unpack('<H',sizebytes)[0]
				prevsize = 0
				segmentid = 0
				flag = 0
				unused = 0
				tag = 0

				if key == 0 and not win7mode:
					prevsize = struct.unpack('<H',fullheaderbin[2:4])[0]
					segmentid = struct.unpack('<B',fullheaderbin[4:5])[0]
					flag = struct.unpack('<B',fullheaderbin[5:6])[0]
					unused = struct.unpack('<B',fullheaderbin[6:7])[0]
					tag = struct.unpack('<B',fullheaderbin[7:8])[0]		
				else:
					flag = struct.unpack('<B',fullheaderbin[2:3])[0]
					tag = struct.unpack('<B',fullheaderbin[3:4])[0]
					prevsize = struct.unpack('<H',fullheaderbin[4:6])[0]
					segmentid = struct.unpack('<B',fullheaderbin[6:7])[0]
					unused = struct.unpack('<B',fullheaderbin[7:8])[0]

				flink = 0
				blink = 0
				if type == "lal" or type == "freelist":
					flink = struct.unpack('<L',dbg.readMemory(thischunk+headersize,4))[0]
				if type == "freelist":
					blink = struct.unpack('<L',dbg.readMemory(thischunk+headersize+4,4))[0]
				return MnChunk(thischunk,chunktype,headersize,self.heapbase,0,thissize,prevsize,segmentid,flag,unused,tag,flink,blink)
			else:
				return MnChunk(thischunk,chunktype,headersize,self.heapbase,0,0,0,0,0,0,0,0,0)

		return None


	def getFrontEndHeap(self):
		"""
		Returns the value of the FrontEndHeap field in the heapbase
		"""
		return readPtrSizeBytes(self.heapbase+getOsOffset("FrontEndHeap"))


	def getFrontEndHeapType(self):
		"""
		Returns the value of the FrontEndHeapType field in the heapbase
		"""
		return struct.unpack('B',dbg.readMemory(self.heapbase+getOsOffset("FrontEndHeapType"),1))[0]

	def getLookAsideHead(self):
		"""
		Returns the LookAside List Head as a dictionary of dictionaries
		"""
		if not win7mode:
			self.FrontEndHeap = self.getFrontEndHeap()
			self.FrontEndHeapType = self.getFrontEndHeapType()
			if self.FrontEndHeap > 0 and self.FrontEndHeapType == 0x1 and len(self.lalheads) == 0:
				lalindex = 0
				startloc = self.FrontEndHeap
				while lalindex < 128:
					thisptr = self.FrontEndHeap + (0x30 * lalindex)
					lalheadfields = {}
					# read the next 0x30 bytes and break down into lal head elements
					lalheadbin = dbg.readMemory(thisptr,0x30)
					lalheadfields["Next"] = struct.unpack('<L',lalheadbin[0:4])[0]
					lalheadfields["Depth"] = struct.unpack('<H',lalheadbin[4:6])[0]
					lalheadfields["Sequence"] = struct.unpack('<H',lalheadbin[6:8])[0]
					lalheadfields["Depth2"] = struct.unpack('<H',lalheadbin[8:0xa])[0]
					lalheadfields["MaximumDepth"] = struct.unpack('<H',lalheadbin[0xa:0xc])[0]
					lalheadfields["TotalAllocates"] = struct.unpack('<L',lalheadbin[0xc:0x10])[0]
					lalheadfields["AllocateMisses"] = struct.unpack('<L',lalheadbin[0x10:0x14])[0]
					lalheadfields["AllocateHits"] = struct.unpack('<L',lalheadbin[0x10:0x14])[0] 
					lalheadfields["TotalFrees"] = struct.unpack('<L',lalheadbin[0x14:0x18])[0]
					lalheadfields["FreeMisses"] = struct.unpack('<L',lalheadbin[0x18:0x1c])[0]
					lalheadfields["FreeHits"] = struct.unpack('<L',lalheadbin[0x18:0x1c])[0]
					lalheadfields["Type"] = struct.unpack('<L',lalheadbin[0x1c:0x20])[0]
					lalheadfields["Tag"] = struct.unpack('<L',lalheadbin[0x20:0x24])[0]
					lalheadfields["Size"] = struct.unpack('<L',lalheadbin[0x24:0x28])[0]
					lalheadfields["Allocate"] = struct.unpack('<L',lalheadbin[0x28:0x2c])[0]
					lalheadfields["Free"] = struct.unpack('<L',lalheadbin[0x2c:0x30])[0]
					self.lalheads[lalindex] = lalheadfields
					lalindex += 1
		return self.lalheads

	def showLookAsideHead(self,lalindex):
		if len(self.lalheads) == 0:
			self.getLookAsideHead()
		if lalindex in self.lalheads:
			thislalhead = self.lalheads[lalindex]
			dbg.log("  Next: 0x%08x" % thislalhead["Next"])
			dbg.log("  Depth: 0x%04x" % thislalhead["Depth"])
			dbg.log("  Sequence: 0x%04x" % thislalhead["Sequence"])
			dbg.log("  Depth2: 0x%04x" % thislalhead["Depth2"])
			dbg.log("  MaximumDepth: 0x%04x" % thislalhead["MaximumDepth"])
			dbg.log("  TotalAllocates: 0x%08x" % thislalhead["TotalAllocates"])
			dbg.log("  AllocateMisses/AllocateHits: 0x%08x" % thislalhead["AllocateMisses"])
			dbg.log("  TotalFrees: 0x%08x" % thislalhead["TotalFrees"])
			dbg.log("  FreeMisses/FreeHits: 0x%08x" % thislalhead["FreeMisses"])
			dbg.log("  Type 0x%08x" % thislalhead["Type"])
			dbg.log("  Tag: 0x%08x" % thislalhead["Tag"])
			dbg.log("  Size: 0x%08x" % thislalhead["Size"])
			dbg.log("  Allocate: 0x%08x" % thislalhead["Allocate"])
			dbg.log("  Free: 0x%08x" % thislalhead["AllocateMisses"])
		return 

	def getLookAsideList(self):
		"""
		Retrieves the LookAsideList (if enabled) for the current heap
		Returns : a dictionary, key = LAL index
		Each element in the dictionary contains a dictionary, using a sequence nr as key,
		    and each element in this dictionary contains an MnChunk object
		"""
		lal = {}
		if not win7mode:
			self.FrontEndHeap = self.getFrontEndHeap()
			self.FrontEndHeapType = self.getFrontEndHeapType()
			if self.FrontEndHeap > 0 and self.FrontEndHeapType == 0x1:
				lalindex = 0
				startloc = self.FrontEndHeap
				while lalindex < 128:
					thisptr = self.FrontEndHeap + (0x30 * lalindex)
					lalhead_flink = struct.unpack('<L',dbg.readMemory(thisptr,4))[0]
					if lalhead_flink != 0:
						thissize = (lalindex * 8)
						next_flink = lalhead_flink
						seqnr = 0
						thislal = {} 
						while next_flink != 0 and next_flink != startloc:
							chunk = self.getHeapChunkHeaderAtAddress(next_flink-8,8,"lal")
							next_flink = chunk.flink
							thislal[seqnr] = chunk
							seqnr += 1
						lal[lalindex] = thislal
					lalindex += 1
		return lal

	def getFreeListInUseBitmap(self):
		global FreeListBitmap
		if not self.heapbase in FreeListBitmap:
			FreeListBitmapHeap = []
			cnt = 0
			while cnt < 4:
				fldword = dbg.readLong(self.heapbase+0x158 + (4 * cnt))
				bitmapbits = DwordToBits(fldword)
				#print "0x%08x : %s (%d)" % (fldword,bitmapbits,len(bitmapbits))
				for thisbit in bitmapbits:
					FreeListBitmapHeap.append(thisbit)
				cnt += 1
			FreeListBitmap[self.heapbase] = FreeListBitmapHeap
		return FreeListBitmap[self.heapbase]


	def getFreeList(self):
		"""
		Retrieves the FreeLists (XP/2003) for the current heap
		Returns : a dictionary, key = FreeList table index
		Each element in the dictionary contains a dictionary, using the FreeList position as key
			and each element in this dictionary contains an MnChunk object		
		"""
		freelists = {}
		if not win7mode:
			flindex = 0
			while flindex < 128:
				freelistflink = self.heapbase + 0x178 + (8 * flindex) + 4
				freelistblink = self.heapbase + 0x178 + (8 * flindex)
				endchain = False
				try:
					tblink = struct.unpack('<L',dbg.readMemory(freelistflink,4))[0]
					tflink = struct.unpack('<L',dbg.readMemory(freelistblink,4))[0]
					origblink = freelistblink
					if freelistblink != tblink:
						thisfreelist = {}
						endchain = False
						thisfreelistindex = 0
						pflink = 0
						while not endchain:
							try:
								freelistentry = self.getHeapChunkHeaderAtAddress(tflink-8,8,"freelist")
								thisfreelist[thisfreelistindex] = freelistentry
								thisfreelistindex += 1
								thisblink = struct.unpack('<L',dbg.readMemory(tflink+4,4))[0]
								thisflink = struct.unpack('<L',dbg.readMemory(tflink,4))[0]
								tflink=thisflink
								if (tflink == origblink) or (tflink == pflink):
									endchain = True
								pflink = tflink 
							except:
								endchain = True
						freelists[flindex] = thisfreelist
				except:
					continue
				flindex += 1
		return freelists	


	def getVirtualAllocdBlocks(self):
		"""
		Retrieves the VirtualAllocdBlocks list from the selected heap

		Return: A dictionary, using the start of a virtualallocdblock as key
		Each entry in the dictionary contains a MnChunk object, with chunktype set to "virtualalloc"
		"""
		global VACache
		offset = getOsOffset("VirtualAllocdBlocks")
		encodingkey = 0
		if win7mode:
			encodingkey = self.getEncodingKey()
		if not self.heapbase in VACache:
			try:
				# get virtualallocdBlocks for this heap
				vaptr = self.heapbase + offset
				valistentry = struct.unpack('<L',dbg.readMemory(vaptr,4))[0]
				while valistentry != vaptr:
					# get VA Header info
					# header:
					#            	size    size
					#               (x86)   (x64)
					#               =====   =====
					# FLINK         4       8
					# BLINK      	4       8
					# Normal header 8       16    encoded on Win7+
					# CommitSize    4       8
					# ReserveSize   4       8     = requested size
					# BusyBlock     8       16

					headersize = 0
					heoffset = 0 # HEAP_ENTRY offset (@ BusyBlock)
					vaheader = None
					flink = 0
					blink = 0
					commitsize = 0
					reservesize = 0
					size = 0

					if arch == 32:
						headersize = 32
						heoffset = 24
						vaheader = dbg.readMemory(valistentry,headersize)
						flink = struct.unpack('<L',vaheader[0:4])[0]
						blink = struct.unpack('<L',vaheader[4:8])[0]
						commitsize = struct.unpack('<L',vaheader[16:20])[0]
						reservesize = struct.unpack('<L',vaheader[20:24])[0]
					elif arch == 64:
						headersize = 64
						heoffset = 48
						vaheader = dbg.readMemory(valistentry,headersize)
						flink = struct.unpack('<Q',vaheader[0:8])[0]
						blink = struct.unpack('<Q',vaheader[8:16])[0]
						commitsize = struct.unpack('<Q',vaheader[32:40])[0]
						reservesize = struct.unpack('<Q',vaheader[40:48])[0]

					size_e = struct.unpack('<H',vaheader[heoffset:heoffset+2])[0]
					if win7mode:
						size = (size_e ^ (encodingkey & 0xFFFF))
					else:
						size = size_e

					#prevsize = struct.unpack('<H',vaheader[26:28])[0]
					prevsize = 0
					segmentid = struct.unpack('<B',vaheader[heoffset+4:heoffset+5])[0]
					flag = struct.unpack('<B',vaheader[heoffset+5:heoffset+6])[0]
					if win7mode:
						flag = struct.unpack('<B',vaheader[heoffset+2:heoffset+3])[0]
					unused = struct.unpack('<B',vaheader[heoffset+6:heoffset+7])[0]
					tag = struct.unpack('<B',vaheader[heoffset+7:])[0]

					chunkobj = MnChunk(valistentry,"virtualalloc",headersize,self.heapbase,0,size,prevsize,segmentid,flag,unused,tag,flink,blink,commitsize,reservesize)
					self.VirtualAllocdBlocks[valistentry] = chunkobj
					valistentry = struct.unpack('<L',dbg.readMemory(valistentry,4))[0]
				VACache[self.heapbase] = self.VirtualAllocdBlocks
			except:
				pass
		else:
			self.VirtualAllocdBlocks = VACache[self.heapbase]		
		return self.VirtualAllocdBlocks	

	def getHeapSegmentList(self):
		"""
		Will collect all segments for the current heap object

		Return: A dictionary, using the start of a segment as key
		Each entry in the dictionary has 4 fields :
		start of segment, end of segment, FirstEntry and LastValidEntry
		"""
		self.SegmentList = getSegmentsForHeap(self.heapbase)
		# segstart,segend,firstentry,lastentry
		return self.SegmentList

	def usesLFH(self):
		"""
		Checks if the current heap has LFH enabled

		Return: Boolean
		"""
		if win7mode:
			frontendheaptype = self.getFrontEndHeapType()
			if frontendheaptype == 0x2:
				return True
			else:
				return False
		else:
			return False
			
	def getLFHAddress(self):
		"""
		Retrieves the address of the Low Fragmentation Heap for the current heap

		Return: Int
		"""
		return readPtrSizeBytes(self.heapbase+getOsOffset("FrontEndHeap"))

	def getState(self):
		"""
		Enumerates all segments, chunks and VirtualAllocdBlocks in the current heap

		Return: array of dicts 
			0 : segments  (with segment addy as key), contains list of chunks 
			1 : vablocks 
		Key: Heap
		Contents:
			Segment -> Chunks
			VA Blocks
		"""
		statedata = {}
		segments = getSegmentsForHeap(self.heapbase)
		for seg in segments:
			segstart = segments[seg][0]
			segend = segments[seg][1]
			FirstEntry = segments[seg][2]
			LastValidEntry = segments[seg][3]
			datablocks = walkSegment(FirstEntry,LastValidEntry,self.heapbase)
			statedata[seg] = datablocks
		return statedata

"""
Low Fragmentation Heap
"""
class MnLFH():

   # +0x000 Lock             : _RTL_CRITICAL_SECTION
   # +0x018 SubSegmentZones  : _LIST_ENTRY
   # +0x020 ZoneBlockSize    : Uint4B
   # +0x024 Heap             : Ptr32 Void
   # +0x028 SegmentChange    : Uint4B
   # +0x02c SegmentCreate    : Uint4B
   # +0x030 SegmentInsertInFree : Uint4B
   # +0x034 SegmentDelete    : Uint4B
   # +0x038 CacheAllocs      : Uint4B
   # +0x03c CacheFrees       : Uint4B
   # +0x040 SizeInCache      : Uint4B
   # +0x048 RunInfo          : _HEAP_BUCKET_RUN_INFO
   # +0x050 UserBlockCache   : [12] _USER_MEMORY_CACHE_ENTRY
   # +0x110 Buckets          : [128] _HEAP_BUCKET
   # +0x310 LocalData        : [1] _HEAP_LOCAL_DATA

   # blocks : LocalData->SegmentInfos->SubSegments (Mgmt List)->SubSegs
   
	# class attributes
	Lock = None
	SubSegmentZones = None
	ZoneBlockSize = None
	Heap = None
	SegmentChange = None
	SegmentCreate = None
	SegmentInsertInFree = None
	SegmentDelete = None
	CacheAllocs = None
	CacheFrees = None
	SizeInCache = None
	RunInfo = None
	UserBlockCache = None
	Buckets = None
	LocalData = None
	
	def __init__(self,lfhbase):
		self.lfhbase = lfhbase
		self.populateLFHFields()
		return
		
	def populateLFHFields(self):
		# read 0x310 bytes and split into pieces
		FLHHeader = dbg.readMemory(self.lfhbase,0x310)
		self.Lock = FLHHeader[0:0x18]
		self.SubSegmentZones = []
		self.SubSegmentZones.append(struct.unpack('<L',FLHHeader[0x18:0x1c])[0])
		self.SubSegmentZones.append(struct.unpack('<L',FLHHeader[0x1c:0x20])[0])
		self.ZoneBlockSize = struct.unpack('<L',FLHHeader[0x20:0x24])[0]
		self.Heap = struct.unpack('<L',FLHHeader[0x24:0x28])[0]
		self.SegmentChange = struct.unpack('<L',FLHHeader[0x28:0x2c])[0]
		self.SegmentCreate = struct.unpack('<L',FLHHeader[0x2c:0x30])[0]
		self.SegmentInsertInFree = struct.unpack('<L',FLHHeader[0x30:0x34])[0]
		self.SegmentDelete = struct.unpack('<L',FLHHeader[0x34:0x38])[0]
		self.CacheAllocs = struct.unpack('<L',FLHHeader[0x38:0x3c])[0]
		self.CacheFrees = struct.unpack('<L',FLHHeader[0x3c:0x40])[0]
		self.SizeInCache = struct.unpack('<L',FLHHeader[0x40:0x44])[0]
		self.RunInfo = []
		self.RunInfo.append(struct.unpack('<L',FLHHeader[0x48:0x4c])[0])
		self.RunInfo.append(struct.unpack('<L',FLHHeader[0x4c:0x50])[0])
		self.UserBlockCache = []
		cnt = 0
		while cnt < (12*4):
			self.UserBlockCache.append(struct.unpack('<L',FLHHeader[0x50+cnt:0x54+cnt])[0])
			cnt += 4

	def getSegmentInfo(self):
		# input : self.LocalData
		# output : return SubSegment
		return

	def getSubSegmentList(self):
		# input : SubSegment
		# output : subsegment mgmt list
		return

	def getSubSegment(self):
		# input : subsegment list
		# output : subsegments/blocks
		return

"""
MnHeap Childclass
"""
class MnSegment:
	def __init__(self,heapbase,segmentstart,segmentend,firstentry=0,lastvalidentry=0):
		self.heapbase = heapbase
		self.segmentstart = segmentstart
		self.segmentend = segmentend
		self.firstentry = segmentstart
		self.lastvalidentry = segmentend
		if firstentry > 0:
			self.firstentry = firstentry
		if lastvalidentry > 0:
			self.lastvalidentry = lastvalidentry
		self.chunks = {}

	def getChunks(self):
		"""
		Enumerate all chunks in the current segment
		Output : Dictionary, key = chunkptr
		         Values : MnChunk objects
		         chunktype will be set to "chunk"
		"""
		thischunk = self.firstentry
		allchunksfound = False
		allchunks = {}
		nextchunk = thischunk
		cnt = 0
		savedprevsize = 0
		mHeap = MnHeap(self.heapbase)
		key = mHeap.getEncodingKey()
		while not allchunksfound:
			thissize = 0
			prevsize = 0
			flag = 0
			unused = 0
			segmentid = 0
			tag = 0
			headersize = 0x8
			try:
				fullheaderbin = ""
				if key == 0 and not win7mode:
					fullheaderbin = dbg.readMemory(thischunk,headersize)
				else:
					fullheaderbin = decodeHeapHeader(thischunk,headersize,key)

				sizebytes = fullheaderbin[0:2]
				thissize = struct.unpack('<H',sizebytes)[0]
				
				if key == 0 and not win7mode:
					prevsizebytes = struct.unpack('<H',fullheaderbin[2:4])[0]
					segmentid = struct.unpack('<B',fullheaderbin[4:5])[0]
					flag = struct.unpack('<B',fullheaderbin[5:6])[0]
					unused = struct.unpack('<B',fullheaderbin[6:7])[0]
					tag = struct.unpack('<B',fullheaderbin[7:8])[0]
						
				else:
					flag = struct.unpack('<B',fullheaderbin[2:3])[0]
					tag = struct.unpack('<B',fullheaderbin[3:4])[0]
					prevsizebytes = struct.unpack('<H',fullheaderbin[4:6])[0]
					segmentid = struct.unpack('<B',fullheaderbin[6:7])[0]
					unused = struct.unpack('<B',fullheaderbin[7:8])[0]

				if savedprevsize == 0:
					prevsize = 0
					savedprevsize = thissize
				else:
					prevsize = savedprevsize
					savedprevsize = thissize

				#prevsize = prevsizebytes
					
			except:
				thissize = 0
				prevsize = 0
				flag = 0
				unused = 0

			if thissize > 0:
				nextchunk = thischunk + (thissize * 8)
			else:
				nextchunk += headersize

			chunktype = "chunk"
			if "virtall" in getHeapFlag(flag).lower() or "internal" in getHeapFlag(flag).lower():
				#chunktype = "virtualalloc"
				headersize = 0x20
					
			if not thischunk in allchunks and thissize > 0:
				mChunk = MnChunk(thischunk,chunktype,headersize,self.heapbase,self.segmentstart,thissize,prevsize,segmentid,flag,unused,tag)
				allchunks[thischunk] = mChunk
			
			thischunk = nextchunk

			if nextchunk >= self.lastvalidentry:
				allchunksfound = True
			if "last" in getHeapFlag(flag).lower():
				allchunksfound = True
			
			cnt += 1
		self.chunks = allchunks
		return allchunks

"""
Chunk class
"""
class MnChunk:
	chunkptr = 0
	chunktype = ""
	headersize = 0
	extraheadersize = 0
	heapbase = 0
	segmentbase = 0
	size = 0
	prevsize = 0
	segment = 0
	flag = 0
	flags = 0
	unused = 0
	tag = 0
	flink = 0
	blink = 0
	commitsize = 0
	reservesize = 0
	remaining = 0
	hasust = False
	dph_block_information_startstamp = 0 
	dph_block_information_heap = 0
	dph_block_information_requestedsize = 0 
	dph_block_information_actualsize = 0
	dph_block_information_traceindex = 0
	dph_block_information_stacktrace = 0
	dph_block_information_endstamp = 0	

	def __init__(self,chunkptr,chunktype,headersize,heapbase,segmentbase,size,prevsize,segment,flag,unused,tag,flink=0,blink=0,commitsize=0,reservesize=0):
		self.chunkptr = chunkptr
		self.chunktype = chunktype
		self.extraheadersize = 0
		self.remaining = 0
		self.dph_block_information_startstamp = 0 
		self.dph_block_information_heap = 0
		self.dph_block_information_requestedsize = 0 
		self.dph_block_information_actualsize = 0
		self.dph_block_information_traceindex = 0
		self.dph_block_information_stacktrace = 0
		self.dph_block_information_endstamp = 0
		self.hasust = False
		# if ust/hpa is enabled, the chunk header is followed by 32bytes of DPH_BLOCK_INFORMATION header info
		currentflagnames = getNtGlobalFlagNames(getNtGlobalFlag())
		if "ust" in currentflagnames:
			self.hasust = True
		if "hpa" in currentflagnames:
			# reader header info
			if arch == 32:
				self.extraheadersize = 0x20
				try:
					raw_dph_header = dbg.readMemory(chunkptr + headersize,0x20)
					self.dph_block_information_startstamp = struct.unpack('<L',raw_dph_header[0:4])[0]
					self.dph_block_information_heap = struct.unpack('<L',raw_dph_header[4:8])[0]
					self.dph_block_information_requestedsize = struct.unpack('<L',raw_dph_header[8:12])[0]
					self.dph_block_information_actualsize = struct.unpack('<L',raw_dph_header[12:16])[0]
					self.dph_block_information_traceindex = struct.unpack('<H',raw_dph_header[16:18])[0]
					self.dph_block_information_stacktrace = struct.unpack('<L',raw_dph_header[24:28])[0]
					self.dph_block_information_endstamp = struct.unpack('<L',raw_dph_header[28:32])[0]
				except:
					pass
			elif arch == 64:
				self.extraheadersize = 0x40
				# reader header info
				try:
					raw_dph_header = dbg.readMemory(chunkptr + headersize,0x40)
					self.dph_block_information_startstamp = struct.unpack('<L',raw_dph_header[0:4])[0]
					self.dph_block_information_heap = struct.unpack('<Q',raw_dph_header[8:16])[0]
					self.dph_block_information_requestedsize = struct.unpack('<Q',raw_dph_header[16:24])[0]
					self.dph_block_information_actualsize = struct.unpack('<Q',raw_dph_header[24:32])[0]
					self.dph_block_information_traceindex = struct.unpack('<H',raw_dph_header[32:34])[0]
					self.dph_block_information_stacktrace = struct.unpack('<Q',raw_dph_header[48:56])[0]
					self.dph_block_information_endstamp = struct.unpack('<L',raw_dph_header[60:64])[0]
				except:
					pass
		self.headersize = headersize
		self.heapbase = heapbase
		self.segmentbase = segmentbase
		self.size = size
		self.prevsize = prevsize
		self.segment = segment
		self.flag = flag
		self.flags = flag
		self.unused = unused
		self.tag = tag
		self.flink = flink
		self.blink = blink
		self.commitsize = commitsize
		self.reservesize = reservesize
		self.userptr = self.chunkptr + self.headersize + self.extraheadersize
		self.usersize = (self.size * heapgranularity) - self.unused - self.extraheadersize
		self.remaining = self.unused - self.headersize - self.extraheadersize
		self.flagtxt = getHeapFlag(self.flag)


	def showChunk(self,showdata = False):
		chunkshown = False
		if self.chunktype == "chunk":
			dbg.log("    _HEAP @ %08x, Segment @ %08x" % (self.heapbase,self.segmentbase))
			if win7mode:
				iHeap = MnHeap(self.heapbase)
				if iHeap.usesLFH():
					dbg.log("    Heap has LFH enabled. LFH Heap starts at 0x%08x" % iHeap.getLFHAddress())
					if "busy" in self.flagtxt.lower() and "virtallocd" in self.flagtxt.lower():
						dbg.log("    ** This chunk may be managed by LFH")
						self.flagtxt = self.flagtxt.replace("Virtallocd","Internal")
			dbg.log("                      (         bytes        )                   (bytes)")						
			dbg.log("      HEAP_ENTRY      Size  PrevSize    Unused Flags    UserPtr  UserSize Remaining - state")
			dbg.log("        %08x  %08x  %08x  %08x  [%02x]   %08x  %08x  %08x   %s  (hex)" % (self.chunkptr,self.size*heapgranularity,self.prevsize*heapgranularity,self.unused,self.flag,self.userptr,self.usersize,self.unused-self.headersize,self.flagtxt))
			dbg.log("                  %08d  %08d  %08d                   %08d  %08d   %s  (dec)" % (self.size*heapgranularity,self.prevsize*heapgranularity,self.unused,self.usersize,self.unused-self.headersize,self.flagtxt))
			dbg.log("")
			chunkshown = True

		if self.chunktype == "virtualalloc":
			dbg.log("    _HEAP @ %08x, VirtualAllocdBlocks" % (self.heapbase))
			dbg.log("      FLINK : 0x%08x, BLINK : 0x%08x" % (self.flink,self.blink))
			dbg.log("      CommitSize : 0x%08x bytes, ReserveSize : 0x%08x bytes" % (self.commitsize*heapgranularity, self.reservesize*heapgranularity))
			dbg.log("                      (         bytes        )                   (bytes)")						
			dbg.log("      HEAP_ENTRY      Size  PrevSize    Unused Flags    UserPtr  UserSize - state")
			dbg.log("        %08x  %08x  %08x  %08x  [%02x]   %08x  %08x   %s  (hex)" % (self.chunkptr,self.size*heapgranularity,self.prevsize*heapgranularity,self.unused,self.flag,self.userptr,self.usersize,self.flagtxt))
			dbg.log("                  %08d  %08d  %08d                   %08d   %s  (dec)" % (self.size*heapgranularity,self.prevsize*heapgranularity,self.unused,self.usersize,self.flagtxt))
			dbg.log("")
			chunkshown = True

		if chunkshown:
			requestedsize = self.usersize
			dbg.log("      Chunk header size: 0x%x (%d)" % (self.headersize,self.headersize))
			if self.extraheadersize > 0:
				dbg.log("      Extra header due to GFlags: 0x%x (%d) bytes" % (self.extraheadersize,self.extraheadersize))
			if self.dph_block_information_stacktrace > 0:
				dbg.log("      DPH_BLOCK_INFORMATION Header size: 0x%x (%d)" % (self.extraheadersize,self.extraheadersize))
				dbg.log("         StartStamp    : 0x%08x" % self.dph_block_information_startstamp)
				dbg.log("         Heap          : 0x%08x" % self.dph_block_information_heap)
				dbg.log("         RequestedSize : 0x%08x" % self.dph_block_information_requestedsize)
				requestedsize = self.dph_block_information_requestedsize
				dbg.log("         ActualSize    : 0x%08x" % self.dph_block_information_actualsize)
				dbg.log("         TraceIndex    : 0x%08x" % self.dph_block_information_traceindex)
				dbg.log("         StackTrace    : 0x%08x" % self.dph_block_information_stacktrace)
				dbg.log("         EndStamp      : 0x%08x" % self.dph_block_information_endstamp)	
			dbg.log("      Size initial allocation request: 0x%x (%d)" % (requestedsize,requestedsize))
			dbg.log("      Total space for data: 0x%x (%d)" % (self.usersize + self.unused - self.headersize,self.usersize + self.unused - self.headersize))
			dbg.log("      Delta between initial size and total space for data: 0x%x (%d)" % (self.unused - self.headersize, self.unused-self.headersize))
			if showdata:
				dsize = self.usersize + self.remaining
				if dsize > 0 and dsize < 32:
					contents = bin2hex(dbg.readMemory(self.userptr,self.usersize+self.remaining))
				else:
					contents = bin2hex(dbg.readMemory(self.userptr,32)) + " ..."
				dbg.log("      Data : %s" % contents)
			dbg.log("")
		return

	def showChunkLine(self,showdata = False):
		return


#---------------------------------------#
#  Class to access pointer properties   #
#---------------------------------------#
class MnPointer:
	"""
	Class to access pointer properties
	"""
	def __init__(self,address):
	
		# check that the address is an integer
		if not type(address) == int and not type(address) == long:
			raise Exception("address should be an integer or long")
	
		self.address = address
		
		NullRange 			= [0]
		AsciiRange			= range(1,128)
		AsciiPrintRange		= range(20,127)
		AsciiUppercaseRange = range(65,91)
		AsciiLowercaseRange = range(97,123)
		AsciiAlphaRange     = AsciiUppercaseRange + AsciiLowercaseRange
		AsciiNumericRange   = range(48,58)
		AsciiSpaceRange     = [32]
		
		self.HexAddress = toHex(address)

		# define the characteristics of the pointer
		byte1,byte2,byte3,byte4,byte5,byte6,byte7,byte8 = (0,)*8

		if arch == 32:
			byte1,byte2,byte3,byte4 = splitAddress(address)
		elif arch == 64:
			byte1,byte2,byte3,byte4,byte5,byte6,byte7,byte8 = splitAddress(address)
		
		# Nulls
		self.hasNulls = (byte1 == 0) or (byte2 == 0) or (byte3 == 0) or (byte4 == 0)
		
		# Starts with null
		self.startsWithNull = (byte1 == 0)
		
		# Unicode
		self.isUnicode = ((byte1 == 0) and (byte3 == 0))
		
		# Unicode reversed
		self.isUnicodeRev = ((byte2 == 0) and (byte4 == 0))

		if arch == 64:
			self.hasNulls = self.hasNulls or (byte5 == 0) or (byte6 == 0) or (byte7 == 0) or (byte8 == 0)
			self.isUnicode = self.isUnicode and ((byte5 == 0) and (byte7 == 0))
			self.isUnicodeRev = self.isUnicodeRev and ((byte6 == 0) and (byte8 == 0))
		
		# Unicode transform
		self.unicodeTransform = UnicodeTransformInfo(self.HexAddress) 

		# Ascii
		if not self.isUnicode and not self.isUnicodeRev:			
			self.isAscii = bytesInRange(address, AsciiRange)
		else:
			self.isAscii = bytesInRange(address, NullRange + AsciiRange)
		
		# AsciiPrintable
		if not self.isUnicode and not self.isUnicodeRev:
			self.isAsciiPrintable = bytesInRange(address, AsciiPrintRange)
		else:
			self.isAsciiPrintable = bytesInRange(address, NullRange + AsciiPrintRange)
			
		# Uppercase
		if not self.isUnicode and not self.isUnicodeRev:
			self.isUppercase = bytesInRange(address, AsciiUppercaseRange)
		else:
			self.isUppercase = bytesInRange(address, NullRange + AsciiUppercaseRange)
		
		# Lowercase
		if not self.isUnicode and not self.isUnicodeRev:
			self.isLowercase = bytesInRange(address, AsciiLowercaseRange)
		else:
			self.isLowercase = bytesInRange(address, NullRange + AsciiLowercaseRange)
			
		# Numeric
		if not self.isUnicode and not self.isUnicodeRev:
			self.isNumeric = bytesInRange(address, AsciiNumericRange)
		else:
			self.isNumeric = bytesInRange(address, NullRange + AsciiNumericRange)
			
		# Alpha numeric
		if not self.isUnicode and not self.isUnicodeRev:
			self.isAlphaNumeric = bytesInRange(address, AsciiAlphaRange + AsciiNumericRange + AsciiSpaceRange)
		else:
			self.isAlphaNumeric = bytesInRange(address, NullRange + AsciiAlphaRange + AsciiNumericRange + AsciiSpaceRange)
		
		# Uppercase + Numbers
		if not self.isUnicode and not self.isUnicodeRev:
			self.isUpperNum = bytesInRange(address, AsciiUppercaseRange + AsciiNumericRange)
		else:
			self.isUpperNum = bytesInRange(address, NullRange + AsciiUppercaseRange + AsciiNumericRange)
		
		# Lowercase + Numbers
		if not self.isUnicode and not self.isUnicodeRev:
			self.isLowerNum = bytesInRange(address, AsciiLowercaseRange + AsciiNumericRange)
		else:
			self.isLowerNum = bytesInRange(address, NullRange + AsciiLowercaseRange + AsciiNumericRange)
		
	
	def __str__(self):
		"""
		Get pointer properties (human readable format)

		Arguments:
		None

		Return:
		String with various properties about the pointer
		"""	

		outstring = ""
		if self.startsWithNull:
			outstring += "startnull,"
			
		elif self.hasNulls:
			outstring += "null,"
		
		#check if this pointer is unicode transform
		hexaddr = self.HexAddress
		outstring += UnicodeTransformInfo(hexaddr)

		if self.isUnicode:
			outstring += "unicode,"
		if self.isUnicodeRev:
			outstring += "unicodereverse,"			
		if self.isAsciiPrintable:
			outstring += "asciiprint,"
		if self.isAscii:
			outstring += "ascii,"
		if self.isUppercase:
			outstring == "upper,"
		if self.isLowercase:
			outstring += "lower,"
		if self.isNumeric:
			outstring+= "num,"
			
		if self.isAlphaNumeric and not (self.isUppercase or self.isLowercase or self.isNumeric):
			outstring += "alphanum,"
		
		if self.isUpperNum and not (self.isUppercase or self.isNumeric):
			outstring += "uppernum,"
		
		if self.isLowerNum and not (self.isLowercase or self.isNumeric):
			outstring += "lowernum,"
			
		outstring = outstring.rstrip(",")
		outstring += " {" + getPointerAccess(self.address)+"}"
		return outstring

	def getAddress(self):
		return self.address
	
	def isUnicode(self):
		return self.isUnicode
		
	def isUnicodeRev(self):
		return self.isUnicodeRev		
	
	def isUnicodeTransform(self):
		return self.unicodeTransform != ""
	
	def isAscii(self):
		return self.isAscii
	
	def isAsciiPrintable(self):
		return self.isAsciiPrintable
	
	def isUppercase(self):
		return self.isUppercase
	
	def isLowercase(self):
		return self.isLowercase
		
	def isUpperNum(self):
		return self.isUpperNum
		
	def isLowerNum(self):
		return self.isLowerNum
		
	def isNumeric(self):
		return self.isNumeric
		
	def isAlphaNumeric(self):
		return self.alphaNumeric
	
	def hasNulls(self):
		return self.hasNulls
	
	def startsWithNull(self):
		return self.startsWithNull
		
	def belongsTo(self):
		"""
		Retrieves the module a given pointer belongs to

		Arguments:
		None

		Return:
		String with the name of the module a pointer belongs to,
		or empty if pointer does not belong to a module
		"""		
		if len(g_modules)==0:
			populateModuleInfo()
		for thismodule,modproperties in g_modules.iteritems():
				thisbase = getModuleProperty(thismodule,"base")
				thistop = getModuleProperty(thismodule,"top")
				if (self.address >= thisbase) and (self.address <= thistop):
					return thismodule
		return ""
	
	def isOnStack(self):
		"""
		Checks if the pointer is on one of the stacks of one of the threads in the process

		Arguments:
		None

		Return:
		Boolean - True if pointer is on stack
		"""	
		stacks = getStacks()
		for stack in stacks:
			if (stacks[stack][0] <= self.address) and (self.address < stacks[stack][1]):
				return True
		return False
	
	def isInHeap(self):
		"""
		Checks if the pointer is part of one of the pages associated with process heaps/segments

		Arguments:
		None

		Return:
		Boolean - True if pointer is in heap
		"""	
		segmentcnt = 0

		for heap in dbg.getHeapsAddress():
				# part of a segment ?
				segments = getSegmentsForHeap(heap)
				for segment in segments:
					if segmentcnt == 0:
						# in heap data structure
						if self.address >= heap and self.address <= segment:
							return True
						segmentcnt += 1
					if self.address >= segment:
						last = segments[segment][3]
						if self.address >= segment and self.address <= last:
							return True
		# maybe it's in a VA List ?
		for heap in dbg.getHeapsAddress():
			mHeap = MnHeap(heap)
			valist = mHeap.getVirtualAllocdBlocks()
			if len(valist) > 0:
				for vachunk in valist:
					thischunk = valist[vachunk]
					#dbg.log("self: 0x%08x, vachunk: 0x%08x, commitsize: 0x%08x, vachunk+(thischunk.commitsize)*8: 0x%08x" % (self.address,vachunk,thischunk.commitsize,vachunk+(thischunk.commitsize*8)))
					if self.address >= vachunk and self.address <= (vachunk+(thischunk.commitsize*heapgranularity)):
						return True
		return False
		

	def getHeapInfo(self):
		global silent
		oldsilent = silent
		silent = True
		foundinheap, foundinsegment, foundinva, foundinchunk = self.showHeapBlockInfo()
		silent = oldsilent
		return [foundinheap, foundinsegment, foundinva, foundinchunk]

	def getHeapInfo_old(self):
		"""
		Returns heap related information about a given pointer
		"""
		heapinfo = {}
		heapinfo["heap"] = 0
		heapinfo["segment"] = 0
		heapinfo["chunk"] = 0
		heapinfo["size"] = 0
		allheaps = dbg.getHeapsAddress()
		for heap in allheaps:
			dbg.log("checking heap 0x%08x for 0x%08x" % (heap,self.address))
			theap = dbg.getHeap(heap)
			heapchunks = theap.getChunks(heap)
			if len(heapchunks) > 0 and not silent:
				dbg.log("Querying segment(s) for heap 0x%s" % toHex(heap))
			for hchunk in heapchunks:
				chunkbase = hchunk.get("address")
				chunksize = hchunk.get("size")
				if self.address >= chunkbase and self.address <= (chunkbase+chunksize):
					heapinfo["heap"] = heap
					heapinfo["segment"] = 0
					heapinfo["chunk"] = chunkbase
					heapinfo["size"] = chunksize
					return heapinfo
		return heapinfo


	def showObjectInfo(self):
		# check if chunk is a DOM object
		if __DEBUGGERAPP__ == "WinDBG":
			cmdtorun = "dds 0x%08x L 1" % self.address
			output = dbg.nativeCommand(cmdtorun)
			outputlower = output.lower()
			outputlines = output.split("\n")
			if "vftable" in outputlower:
				# is this Internet Explorer ?
				ieversion = 0
				if isModuleLoadedInProcess('iexplore.exe') and isModuleLoadedInProcess('mshtml.dll'):
					ieversionstr = getModuleProperty('iexplore.exe','version')
					dbg.log("      Internet Explorer v%s detected" % ieversionstr)
					ieversion = 0
					if ieversionstr.startswith("8."):
						ieversion = 8
					if ieversionstr.startswith("9."):
						ieversion = 9
					if ieversionstr.startswith("10."):
						ieversion = 10
				dbg.log("      0x%08x may be the start of an object, vtable pointer: %s" % (self.address,outputlines[0]))
				vtableptr_s = outputlines[0][10:18]
				try:
					vtableptr = hexStrToInt(vtableptr_s)
					dbg.log("      Start of vtable at 0x%08x: (showing first 4 entries only)" % vtableptr)
					cmdtorun = "dds 0x%08x L 4" % vtableptr
					output = dbg.nativeCommand(cmdtorun)
					outputlines = output.split("\n")
					cnt = 0
					for line in outputlines:
						if line.replace(" ","") != "":
							dbg.log("       +0x%x -> %s" % (cnt,line))
						cnt += 4
					if "mshtml!" in outputlower and ieversion > 7:
						# see if we can find the object type, refcounter, attribute count, parent, etc
						refcounter = None
						attributeptr = None
						try:
							refcounter = dbg.readLong(self.address + 4)
						except:
							pass
						try:
							if ieversion == 8:
								attributeptr = dbg.readLong(self.address + 0xc)
							if ieversion == 9:
								attributeptr = dbg.readLong(self.address + 0x10)
						except:
							pass
						if not refcounter is None and not attributeptr is None:
							dbg.log("      Refcounter: 0x%x (%d)" % (refcounter,refcounter))
							if refcounter > 0x20000:
								dbg.log("      Note: a huge refcounter value may indicate this is not a real DOM object")
							if attributeptr == 0:
								dbg.log("      No attributes found")
							else:
								ptrx = MnPointer(attributeptr)
								if ptrx.isInHeap():
									dbg.log("      Attribute info structure stored at 0x%08x" % attributeptr)
									offset_nr = 0x4
									nr_multiplier = 4
									offset_tableptr = 0xc
									offset_tabledata = 0
									variant_offset = 4
									attname_offset = 8
									attvalue_offset = 0xc
									if ieversion == 9:
										nr_multiplier = 1
										offset_nr = 0x4
										offset_tableptr = 0x8
										offset_tabledata = 4
										variant_offset = 1
										attname_offset = 4
										attvalue_offset = 8

									nr_attributes = dbg.readLong(attributeptr + offset_nr) / nr_multiplier
									attributetableptr = dbg.readLong(attributeptr + offset_tableptr)
									dbg.log("        +0x%02x : Nr of attributes: %d" % (offset_nr,nr_attributes))
									dbg.log("        +0x%02x : Attribute table at 0x%08x" % (offset_tableptr,attributetableptr))
									
									attcnt = 0
									while attcnt < nr_attributes:
										
										try:
											dbg.log("                Attribute %d (at 0x%08x) :" % (attcnt+1,attributetableptr))
											sec_dword = "%08x" % struct.unpack('<L',dbg.readMemory(attributetableptr+4,4))[0]
											variant_type = int(sec_dword[0:2][:-1],16)
											dbg.log("                  Variant Type : 0x%02x (%s)" % (variant_type,getVariantType(variant_type)))
											if variant_type > 0x1:
												att_name = "<n.a.>"
												try:
													att_name_ptr = dbg.readLong(attributetableptr+attname_offset)
													att_name_ptr_value = dbg.readLong(att_name_ptr+4)
													att_name = dbg.readWString(att_name_ptr_value)
												except:
													att_name = "<n.a.>"
												dbg.log("                  0x%08x + 0x%02x (0x%08x): 0x%08x : &Attribute name : '%s'" % (attributetableptr,attname_offset,attributetableptr+attname_offset,att_name_ptr,att_name))
												att_value_ptr = dbg.readLong(attributetableptr+attvalue_offset)
												ptrx = MnPointer(att_value_ptr)
												if ptrx.isInHeap():
													att_value = ""
													if variant_type == 0x8:
														att_value = dbg.readWString(att_value_ptr)
													if variant_type == 0x16:
														attv = dbg.readLong(att_value_ptr)
														att_value = "0x%08x (%s)" % (attv,int("0x%08x" % attv,16))
													if variant_type == 0x1e:
														att_from = dbg.readLong(att_value_ptr)
														att_value = dbg.readString(att_from)
													if variant_type == 0x1f:
														att_from = dbg.readLong(att_value_ptr)
														att_value = dbg.readWString(att_from)
												else:
													att_value = "0x%08x (%s)" % (att_value_ptr,int("0x%08x" % att_value_ptr,16))
												dbg.log("                  0x%08x + 0x%02x (0x%08x): 0x%08x : &Value : %s" % (attributetableptr,attvalue_offset,attributetableptr+attvalue_offset,att_value_ptr,att_value))
										except:
											dbg.logLines(traceback.format_exc(),highlight=True)
											break
										attributetableptr += 0x10 											
										attcnt += 1
								else:
									dbg.log("      Invalid attribute ptr found (0x%08x). This may not be a real DOM object." % attributeptr)


						offset_domtree = 0x14
						if ieversion == 9:
							offset_domtree = 0x1C
						domtreeptr = dbg.readLong(self.address + offset_domtree)
						if not domtreeptr is None:
							dptrx = MnPointer(domtreeptr)
							if dptrx.isInHeap():
								currobj = self.address
								moreparents = True
								parentcnt = 0
								dbg.log("      Object +0x%02x : Ptr to DOM Tree info: 0x%08x" % (offset_domtree,domtreeptr))								
								while moreparents:
									# walk tree, get parents
									parentspaces = " " * parentcnt
									cmdtorun = "dds poi(poi(poi(0x%08x+0x%02x)+4)) L 1" % (currobj,offset_domtree)
									output = dbg.nativeCommand(cmdtorun)
									outputlower = output.lower()
									outputlines = output.split("\n")
									if "vftable" in outputlines[0]:
										dbg.log("      %s Parent : %s" % (parentspaces,outputlines[0]))
										parts = outputlines[0].split(" ")
										try:
											currobj = int(parts[0],16)
										except:
											currobj = 0
									else:
										moreparents = False
									parentcnt += 3
									if currobj == 0:
										moreparents = False

				except:
					dbg.logLines(traceback.format_exc(),highlight=True)
					pass

		return



	def showHeapBlockInfo(self):
		"""
		Find address in heap and print out info about heap, segment, chunk it belongs to
		"""
		allheaps = []
		heapkey = 0
		
		foundinheap = None
		foundinsegment = None
		foundinva = None
		foundinchunk = None
		dumpsize = 0
		dodump = False

		try:
			allheaps = dbg.getHeapsAddress()
		except:
			allheaps = []
		for heapbase in allheaps:
			mHeap = MnHeap(heapbase)
			heapbase_extra = ""
			frontendinfo = []
			frontendheapptr = 0
			frontendheaptype = 0
			if win7mode:
				heapkey = mHeap.getEncodingKey()
				if mHeap.usesLFH():
					frontendheaptype = 0x2
					heapbase_extra = " [LFH] "
					frontendheapptr = mHeap.getLFHAddress()
			frontendinfo = [frontendheaptype,frontendheapptr]

			segments = mHeap.getHeapSegmentList()

			#segments
			for seg in segments:
				segstart = segments[seg][0]
				segend = segments[seg][1]
				FirstEntry = segments[seg][2]
				LastValidEntry = segments[seg][3]								
				allchunks = walkSegment(FirstEntry,LastValidEntry,heapbase)
				for chunkptr in allchunks:
					thischunk = allchunks[chunkptr]
					thissize = thischunk.size*8 
					headersize = thischunk.headersize
					if self.address >= chunkptr and self.address < (chunkptr + thissize):
						# found it !
						if not silent:
							dbg.log("")
							dbg.log("Address 0x%08x found in " % self.address)
							thischunk.showChunk(showdata = True)
							self.showObjectInfo()
							self.showHeapStackTrace(thischunk)
							dodump = True
							dumpsize = thissize
						foundinchunk = thischunk
						foundinsegment = seg
						foundinheap = heapbase
						break
				if not foundinchunk == None:
					break

			# VA
			if foundinchunk == None:
				# maybe it's in VirtualAllocdBlocks
				vachunks = mHeap.getVirtualAllocdBlocks()
				for vaptr in vachunks:
					thischunk = vachunks[vaptr]
					if self.address >= vaptr and self.address <= vaptr + (thischunk.commitsize*8):
						if not silent:
							dbg.log("")
							dbg.log("Address 0x%08x found in VirtualAllocdBlocks of heap 0x%08x" % (self.address,heapbase))
							thischunk.showChunk(showdata = True)
							self.showObjectInfo()
							self.showHeapStackTrace(thischunk)
							thissize = thischunk.usersize
							dumpsize = thissize
							dodump = True					
						foundinchunk = thischunk
						foundinva = vaptr
						foundinheap = heapbase
						break

			# perhaps chunk is in FEA
			# if it is, it won't be a VA chunk
			if foundinva == None:
				if not win7mode:
					foundinlal = False
					foundinfreelist = False
					FrontEndHeap = mHeap.getFrontEndHeap()
					if FrontEndHeap > 0:
						fea_lal = mHeap.getLookAsideList()
						for lal_table_entry in sorted(fea_lal.keys()):
							nr_of_chunks = len(fea_lal[lal_table_entry])
							lalhead = struct.unpack('<L',dbg.readMemory(FrontEndHeap + (0x30 * lal_table_entry),4))[0]
							for chunkindex in fea_lal[lal_table_entry]:
								lalchunk = fea_lal[lal_table_entry][chunkindex]
								chunksize = lalchunk.size * 8
								flag = getHeapFlag(lalchunk.flag)
								if (self.address >= lalchunk.chunkptr) and (self.address < lalchunk.chunkptr+chunksize):
									foundinlal = True
									if not silent:
										dbg.log("Address is part of chunk on LookAsideList[%d], heap 0x%08x" % (lal_table_entry,mHeap.heapbase))
									break
							if foundinlal:
								expectedsize = lal_table_entry * 8
								if not silent:
									dbg.log("     LAL [%d] @0x%08x, Expected Chunksize: 0x%x (%d), %d chunks, Flink: 0x%08x" % (lal_table_entry,FrontEndHeap + (0x30 * lal_table_entry),expectedsize,expectedsize,nr_of_chunks,lalhead))
								for chunkindex in fea_lal[lal_table_entry]:
									lalchunk = fea_lal[lal_table_entry][chunkindex]
									foundchunk = lalchunk
									chunksize = lalchunk.size * 8
									flag = getHeapFlag(lalchunk.flag)
									extra = "       "
									if (self.address >= lalchunk.chunkptr) and (self.address < lalchunk.chunkptr+chunksize):
										extra = "   --> "
									if not silent:
										dbg.log("%sChunkPtr: 0x%08x, UserPtr: 0x%08x, Flink: 0x%08x, ChunkSize: 0x%x, UserSize: 0x%x, UserSpace: 0x%x (%s)" % (extra,lalchunk.chunkptr,lalchunk.userptr,lalchunk.flink,chunksize,lalchunk.usersize,lalchunk.usersize + lalchunk.remaining,flag))
								if not silent:
									self.showObjectInfo()
									dumpsize = chunksize
									dodump = True
								break

					if not foundinlal:
						# or maybe in BEA
						thisfreelist = mHeap.getFreeList()
						thisfreelistinusebitmap = mHeap.getFreeListInUseBitmap()				
						for flindex in thisfreelist:
							freelist_addy = heapbase + 0x178 + (8 * flindex)
							expectedsize = ">1016"
							expectedsize2 = ">0x%x" % 1016
							if flindex != 0:
								expectedsize2 = str(8 * flindex)
								expectedsize = "0x%x" % (8 * flindex)
							for flentry in thisfreelist[flindex]:
								freelist_chunk = thisfreelist[flindex][flentry]
								chunksize = freelist_chunk.size * 8
								if (self.address >= freelist_chunk.chunkptr) and (self.address < freelist_chunk.chunkptr+chunksize):
									foundinfreelist = True
									if not silent:
										dbg.log("Address is part of chunk on FreeLists[%d] at 0x%08x, heap 0x%08x:" % (flindex,freelist_addy,mHeap.heapbase))
									break
							if foundinfreelist:
								flindicator = 0
								for flentry in thisfreelist[flindex]:
									freelist_chunk = thisfreelist[flindex][flentry]
									chunksize = freelist_chunk.size * 8	
									extra = "     "
									if (self.address >= freelist_chunk.chunkptr) and (self.address < freelist_chunk.chunkptr+chunksize):						
										extra = " --> "
										foundchunk = freelist_chunk
									if not silent:
										dbg.log("%sChunkPtr: 0x%08x, UserPtr: 0x%08x, Flink: 0x%08x, Blink: 0x%08x, ChunkSize: 0x%x (%d), Usersize: 0x%x (%d)" % (extra,freelist_chunk.chunkptr,freelist_chunk.userptr,freelist_chunk.flink,freelist_chunk.blink,chunksize,chunksize,freelist_chunk.usersize,freelist_chunk.usersize))
									if flindex != 0 and chunksize != (8*flindex):
										dbg.log("     ** Header may be corrupted! **", highlight = True)
									flindicator = 1
								if flindex > 1 and int(thisfreelistinusebitmap[flindex]) != flindicator:
									if not silent:
										dbg.log("     ** FreeListsInUseBitmap mismatch for index %d! **" % flindex, highlight = True)
								if not silent:
									self.showObjectInfo()
									dumpsize = chunksize
									dodump = True
								break		

		if dodump and dumpsize > 0 and dumpsize < 1025 and not silent:
			self.dumpObjectAtLocation(dumpsize)	

		return foundinheap, foundinsegment, foundinva, foundinchunk

	def showHeapStackTrace(self,thischunk):
		# show stacktrace if any
		if __DEBUGGERAPP__ == "WinDBG": 
			stacktrace_address = thischunk.dph_block_information_stacktrace
			stacktrace_index = thischunk.dph_block_information_traceindex
			stacktrace_startstamp = 0xabcdaaaa
			if thischunk.hasust and stacktrace_address > 0:
				if stacktrace_startstamp == thischunk.dph_block_information_startstamp:
					cmd2run = "dds 0x%08x L 24" % (stacktrace_address)
					output = dbg.nativeCommand(cmd2run)
					outputlines = output.split("\n")
					if "!" in output:
						dbg.log("Stack trace, index 0x%x:" % stacktrace_index)
						dbg.log("--------------------------")
						for outputline in outputlines:
							if "!" in outputline:
								lineparts = outputline.split(" ")
								if len(lineparts) > 2:
									firstpart = len(lineparts[0])+1
									dbg.log(outputline[firstpart:])
		return
	
	def memLocation(self):
		"""
		Gets the memory location associated with a given pointer (modulename, stack, heap or empty)
		
		Arguments:
		None
		
		Return:
		String
		"""

		memloc = self.belongsTo()
		
		if memloc == "":
			if self.isOnStack():
				return "Stack"
			if self.isInHeap():
				return "Heap"
			return "??"
		return memloc

	def getPtrFunction(self):
		funcinfo = ""
		global silent
		silent = True
		if __DEBUGGERAPP__ == "WinDBG":
			lncmd = "ln 0x%08x" % self.address
			lnoutput = dbg.nativeCommand(lncmd)
			for line in lnoutput.split("\n"):
				if line.replace(" ","") != "" and line.find("%08x" % self.address) > -1:
					lineparts = line.split("|")
					funcrefparts = lineparts[0].split(")")
					if len(funcrefparts) > 1:
						funcinfo = funcrefparts[1].replace(" ","")
						break

		if funcinfo == "":
			memloc = self.belongsTo()
			if not memloc == "":
				mod = MnModule(memloc)
				if not mod is None:
					start = mod.moduleBase
					offset = self.address - start
					offsettxt = ""
					if offset > 0:
						offsettxt = "+0x%08x" % offset
					else:
						offsettxt = "__base__"
					funcinfo = memloc+offsettxt
		silent = False
		return funcinfo

	def dumpObjectAtLocation(self,size,levels=0,nestedsize=0,customthislog="",customlogfile=""):
		dumpdata = {}
		origdumpdata = {} 
		if __DEBUGGERAPP__ == "WinDBG":
			addy = self.address
			if not silent:
				dbg.log("")
				dbg.log("----------------------------------------------------")
				if (size < 0x500):
					dbg.log("[+] Dumping object at 0x%08x, 0x%02x bytes" % (addy,size))
				else:
					dbg.log("[+] Dumping object at 0x%08x, 0x%02x bytes (output below will be limited to the first 0x500 bytes !)" % (addy,size))
					size = 0x500
				if levels > 0:
					dbg.log("[+] Also dumping up to %d levels deep, max size of nested objects: 0x%02x bytes" % (levels, nestedsize))
				dbg.log("")

			parentlist = []
			levelcnt = 0
			if customthislog == "" and customlogfile == "":
				logfile = MnLog("dumpobj.txt")
				thislog = logfile.reset()
			else:
				logfile = customlogfile
				thislog = customthislog
			addys = [addy]
			parent = ""
			parentdata = {}
			while levelcnt <= levels:
				thisleveladdys = []
				for addy in addys:
					cmdtorun = "dps 0x%08x L 0x%02x/%x" % (addy,size,archValue(4,8))
					startaddy = addy
					endaddy = addy + size
					output = dbg.nativeCommand(cmdtorun)
					outputlines = output.split("\n")
					offset = 0
					for outputline in outputlines:
						if not outputline.replace(" ","") == "":
							loc = outputline[0:archValue(8,17)].replace("`","")
							content = outputline[archValue(10,19):archValue(18,36)].replace("`","")
							symbol = outputline[archValue(19,37):]
							if not "??" in content and symbol.replace(" ","") == "":
								contentaddy = hexStrToInt(content)
								info = self.getLocInfo(hexStrToInt(loc),contentaddy,startaddy,endaddy)
								info.append(content)
								dumpdata[hexStrToInt(loc)] = info
							else:
								info = ["",symbol,"",content]
								dumpdata[hexStrToInt(loc)] = info
					if addy in parentdata:
						pdata = parentdata[addy]
						parent = "Referenced at 0x%08x (object 0x%08x, offset +0x%02x)" % (pdata[0],pdata[1],pdata[0]-pdata[1])
					else:
						parent = ""
					
					cmd2torun = "!heap -p -a 0x%08x" % (addy)
					output2 = dbg.nativeCommand(cmd2torun)
					heapdata = output2.split("\n")
					
					self.printObjDump(dumpdata,logfile,thislog,size,parent,heapdata)

					for loc in dumpdata:
						thisdata = dumpdata[loc]
						if thisdata[0] == "ptr_obj":
							thisptr = int(thisdata[3],16)
							thisleveladdys.append(thisptr)
							parentdata[thisptr] = [loc,addy]
					if levelcnt == 0:
						origdumpdata = dumpdata
					dumpdata = {}
				addys = thisleveladdys
				size = nestedsize
				levelcnt += 1
		dumpdata = origdumpdata
		return dumpdata


	def printObjDump(self,dumpdata,logfile,thislog,size=0,parent="",heapdata=[]):
		# dictionary, key = address
		# 0 = type
		# 1 = content info
		# 2 = string type
		# 3 = content
		sortedkeys = sorted(dumpdata)
		if len(sortedkeys) > 0:
			startaddy = sortedkeys[0]
			sizem = ""
			parentinfo = ""
			if size > 0:
				sizem = " (0x%02x bytes)" % size
			logfile.write("",thislog)

			if parent == "":
				logfile.write("=" * 60,thislog)

			line = ">> Object at 0x%08x%s:" % (startaddy,sizem)
			if not silent:
				dbg.log("")
				dbg.log(line)
			
			logfile.write(line,thislog)

			if parent != "":
				line = "   %s" % parent
				if not silent:
					dbg.log(line)
				logfile.write(line,thislog)

			line = "Offset  Address      Contents    Info"
			if arch == 64:
				line = "Offset  Address          Contents            Info"
			logfile.write(line,thislog)
			if not silent:
				dbg.log(line)
			line = "------  -------      --------    -----"
			if arch == 64:
				line = "------  -------          --------            -----"
			logfile.write(line,thislog)
			if not silent:
				dbg.log(line)

			offset = 0
			
			for loc in sortedkeys:
				info = dumpdata[loc]
				if len(info) > 1:
					content = ""
					if len(info) > 3:
						content = info[3]
					contentinfo = toAsciiOnly(info[1])
					offsetstr = toSize("%02x" % offset,4)
					line = "+%s   0x%08x | 0x%s  %s" % (offsetstr,loc,content,contentinfo)
					if not silent:
						dbg.log(line)
					logfile.write(line,thislog)
					offset += archValue(4,8)
			if len(sortedkeys) > 0:
				dbg.log("")
			
			for heapdataline in heapdata:
				logfile.write(heapdataline, thislog)
				dbg.log(heapdataline)
		return

	def getLocInfo(self,loc,addy,startaddy,endaddy):
		locinfo = []
		
		if addy >= startaddy and addy <= endaddy:
			offset = addy - startaddy
			locinfo = ["self","ptr to self+0x%08x" % offset,""]
			return locinfo
			
		ismapped = False

		extra = ""
		ptrx = MnPointer(addy)

		memloc = ptrx.memLocation()
		if not "??" in memloc:
			if "Stack" in memloc or "Heap" in memloc:
				extra = "(%s) " % memloc
			else:
				detailmemloc = ptrx.getPtrFunction()
				extra = " (%s.%s)" % (memloc,detailmemloc)

		# maybe it's a pointer to an object ?
		cmd2run = "dps 0x%08x L 1" % addy
		output = dbg.nativeCommand(cmd2run)
		outputlines = output.split("\n")
		if len(outputlines) > 0:
			if not "??" in outputlines[0]:
				ismapped = True
				ptraddy = outputlines[0][archValue(10,19):archValue(18,36)].replace("`","")
				ptrinfo = outputlines[0][archValue(19,37):]
				if ptrinfo.replace(" ","") != "":
					if "vftable" in ptrinfo or "Heap" in memloc:
						locinfo = ["ptr_obj","%sptr to 0x%08x : %s" % (extra,hexStrToInt(ptraddy),ptrinfo),str(addy)]
					else:
						locinfo = ["ptr","%sptr to 0x%08x : %s" % (extra,hexStrToInt(ptraddy),ptrinfo),str(addy)]
					return locinfo

		if ismapped:

			# pointer to a string ?
			try:
				strdata = dbg.readString(addy)
				if len(strdata) > 2:
					datastr = strdata
					if len(strdata) > 80:
						datastr = strdata[0:80] + "..."
					locinfo = ["ptr_str","%sptr to ASCII (0x%02x) '%s'" % (extra,len(strdata),datastr),"ascii"]
					return locinfo
			except:
				pass

			# maybe it's unicode ?
			try:
				strdata = dbg.readWString(addy)
				if len(strdata) > 2:
					datastr = strdata
					if len(strdata) > 80:
						datastr = strdata[0:80] + "..."
					locinfo = ["ptr_str","%sptr to UNICODE (0x%02x) '%s'" % (extra,len(strdata),datastr),"unicode"]
					return locinfo
			except:
				pass

			# maybe the pointer points into a function ?
			ptrf = ptrx.getPtrFunction()
			if not ptrf == "":
				locinfo = ["ptr_func","%sptr to %s" % (extra,ptrf),str(addy)]
				return locinfo


			# BSTR Unicode ?
			try:
				bstr = struct.unpack('<L',dbg.readMemory(addy,4))[0]
				strdata = dbg.readWString(addy+4)
				if len(strdata) > 2 and (bstr == len(strdata)+1):
					datastr = strdata
					if len(strdata) > 80:
						datastr = strdata[0:80] + "..."
					locinfo = ["ptr_str","%sptr to BSTR UNICODE (0x%02x) '%s'" % (extra,bstr,datastr),"unicode"]
					return locinfo
			except:
				pass


			# pointer to a BSTR ASCII?
			try:
				strdata = dbg.readString(addy+4)
				if len(strdata) > 2 and (bstr == len(strdata)/2):
					datastr = strdata
					if len(strdata) > 80:
						datastr = strdata[0:80] + "..."
					locinfo = ["ptr_str","%sptr to BSTR ASCII (0x%02x) '%s'" % (extra,bstr,datastr),"ascii"]
					return locinfo
			except:
				pass



		# pointer itself is a string ?
		
		if ptrx.isUnicode:
			b1,b2,b3,b4,b5,b6,b7,b8 = (0,)*8
			if arch == 32:
				b1,b2,b3,b4 = splitAddress(addy)
			if arch == 64:
				b1,b2,b3,b4,b5,b6,b7,b8 = splitAddress(addy)
			ptrstr = toAscii(toHexByte(b2)) + toAscii(toHexByte(b4))
			if arch == 64:
				ptrstr += toAscii(toHexByte(b6)) + toAscii(toHexByte(b8))
			if ptrstr.replace(" ","") != "" and not toHexByte(b2) == "00":
				locinfo = ["str","= UNICODE '%s' %s" % (ptrstr,extra),"unicode"]
				return locinfo

		
		if ptrx.isAsciiPrintable:
			b1,b2,b3,b4,b5,b6,b7,b8 = (0,)*8
			if arch == 32:
				b1,b2,b3,b4 = splitAddress(addy)
			if arch == 64:
				b1,b2,b3,b4,b5,b6,b7,b8 = splitAddress(addy)
			ptrstr = toAscii(toHexByte(b1)) + toAscii(toHexByte(b2)) + toAscii(toHexByte(b3)) + toAscii(toHexByte(b4))
			if arch == 64:
				ptrstr += toAscii(toHexByte(b5)) + toAscii(toHexByte(b6)) + toAscii(toHexByte(b7)) + toAscii(toHexByte(b8))
			if ptrstr.replace(" ","") != "" and not toHexByte(b1) == "00" and not toHexByte(b2) == "00" and not toHexByte(b3) == "00" and not toHexByte(b4) == "00":
				if arch != 64 or (not toHexByte(b5) == "00" and not toHexByte(b6) == "00" and not toHexByte(b7) == "00" and not toHexByte(b8) == "00"):
					locinfo = ["str","= ASCII '%s' %s" % (ptrstr,extra),"ascii"]
					return locinfo

		# pointer to heap ?
		if "Heap" in memloc:
			if not "??" in outputlines[0]:
				ismapped = True
				ptraddy = outputlines[0][archValue(10,19):archValue(18,36)]
				locinfo = ["ptr_obj","%sptr to 0x%08x" % (extra,hexStrToInt(ptraddy)),str(addy)]
				return locinfo

		# nothing special to report
		return ["","",""]


		
#---------------------------------------#
#  Various functions                    #
#---------------------------------------#
def getDefaultProcessHeap():
	peb = dbg.getPEBAddress()
	defprocheap = struct.unpack('<L',dbg.readMemory(peb+0x18,4))[0]
	return defprocheap

def getSortedSegmentList(heapbase):
	segments = getSegmentsForHeap(heapbase)
	sortedsegments = []
	for seg in segments:
		sortedsegments.append(seg)
	sortedsegments.sort()
	return sortedsegments

def getSegmentList(heapbase):
	return getSegmentsForHeap(heapbase)


def getSegmentsForHeap(heapbase):
	# either return the base of the segment, or the base of the default process heap
	allsegmentsfound = False
	segmentinfo = {}
	global segmentlistCache
	if heapbase in segmentlistCache:
		return segmentlistCache[heapbase]
	else:
		try:
			if win7mode:
				# first one  = heap itself
				offset = getOsOffset("SegmentList")
				segmentcnt = 0
				subtract = archValue(0x10,0x18)
				firstoffset = 0
				firstsegbase = readPtrSizeBytes(heapbase + archValue(0x24,0x40))
				firstsegend = readPtrSizeBytes(heapbase + archValue(0x28,0x48))
				if not firstsegbase in segmentinfo:
					segmentinfo[heapbase] = [firstsegbase,firstsegend,firstsegbase,firstsegend]
				# optional list with additional segments
				# nested list
				segbase = heapbase
				lastindex = heapbase + offset
				allsegmentsfound = False
				lastsegment = readPtrSizeBytes(heapbase+offset+archValue(4,8)) - subtract
				if heapbase == lastsegment:
					allsegmentsfound = True
				segmentcnt = 1
				while not allsegmentsfound and segmentcnt < 100:
					nextbase = readPtrSizeBytes(segbase + archValue(0x10,0x18)) - subtract
					segbase = nextbase
					if nextbase > 0 and (nextbase+subtract != lastindex):
						segstart = readPtrSizeBytes(segbase + archValue(0x24,0x40))
						segend = readPtrSizeBytes(segbase + archValue(0x28,0x48))
						if not segbase in segmentinfo:
							segmentinfo[segbase] = [segbase,segend,segstart,segend]
					else:
						allsegmentsfound = True
					segmentcnt += 1
			else:
				offset = archValue(0x058,0x0a0)
				i = 0
				while not allsegmentsfound:
					thisbase = readPtrSizeBytes(heapbase + offset + i*archValue(4,8))
					if thisbase > 0 and not thisbase in segmentinfo:
						# get start and end of segment
						segstart = thisbase
						segend = getSegmentEnd(segstart)
						# get first and last valid entry
						firstentry = readPtrSizeBytes(segstart + archValue(0x20,0x38))
						lastentry = readPtrSizeBytes(segstart + archValue(0x24,0x40))
						segmentinfo[thisbase] = [segstart,segend,firstentry,lastentry]
					else:
						allsegmentsfound = True
					i += 1
					# avoid infinite loop
					if i > 100:
						allsegmentsfound = True
		except:
			pass
		segmentlistCache[heapbase] = segmentinfo
		return segmentinfo

def containsBadChars(address,badchars="\x0a\x0d"):
	"""
	checks if the address contains bad chars
	
	Arguments:
	address  - the address
	badchars - string with the characters that should be avoided (defaults to 0x0a and 0x0d)
	
	Return:
	Boolean - True if badchars are found
	"""
	
	bytes = splitAddress(address)
	chars = []
	for byte in bytes:
		chars.append(chr(byte))
	
	# check each char
	for char in chars:
		if char in badchars:
			return True			
	return False


def meetsCriteria(pointer,criteria):
	"""
	checks if an address meets the listed criteria

	Arguments:
	pointer - the MnPointer instance of the address
	criteria - a dictionary with all the criteria to be met

	Return:
	Boolean - True if all the conditions are met
	"""
	
	# Unicode
	if "unicode" in criteria and not (pointer.isUnicode or pointer.unicodeTransform != ""):
		return False
		
	if "unicoderev" in criteria and not pointer.isUnicodeRev:
		return False		
		
	# Ascii
	if "ascii" in criteria and not pointer.isAscii:
		return False
	
	# Ascii printable
	if "asciiprint" in criteria and not pointer.isAsciiPrintable:
		return False
	
	# Uppercase
	if "upper" in criteria and not pointer.isUppercase:
		return False
		
	# Lowercase
	if "lower" in criteria and not pointer.isLowercase:
		return False
	
	# Uppercase numeric
	if "uppernum" in criteria and not pointer.isUpperNum:
		return False
	
	# Lowercase numeric
	if "lowernum" in criteria and not pointer.isLowerNum:
		return False	
		
	# Numeric
	if "numeric" in criteria and not pointer.isNumeric:
		return False
	
	# Alpha numeric
	if "alphanum" in criteria and not pointer.isAlphaNumeric:
		return False
		
	# Bad chars
	if "badchars" in criteria and containsBadChars(pointer.getAddress(), criteria["badchars"]):
		return False

	# Nulls
	if "nonull" in criteria and pointer.hasNulls:
		return False
	
	if "startswithnull" in criteria and not pointer.startsWithNull:
		return False
	
	return True

def search(sequences,criteria=[]):
	"""
	Alias for 'searchInRange'
	search for byte sequences in a specified address range

	Arguments:
	sequences - array of byte sequences to search for
	start - the start address of the search (defaults to 0)
	end   - the end address of the search
	criteria - Dictionary containing the criteria each pointer should comply with

	Return:
	Dictionary (opcode sequence => List of addresses)
	"""	
	return searchInRange(sequences,criteria)
	
	
def searchInRange(sequences, start=0, end=TOP_USERLAND,criteria=[]):
	"""
	search for byte sequences in a specified address range

	Arguments:
	sequences - array of byte sequences to search for
	start - the start address of the search (defaults to 0)
	end   - the end address of the search
	criteria - Dictionary containing the criteria each pointer should comply with

	Return:
	Dictionary (opcode sequence => List of addresses)
	"""
	
	if not "accesslevel" in criteria:
		criteria["accesslevel"] = "*"
	global ptr_counter
	global ptr_to_get
	
	found_opcodes = {}
	
	if (ptr_to_get < 0) or (ptr_to_get > 0 and ptr_counter < ptr_to_get):

		if not sequences:
			return {}
			
		# check that start is before end
		if start > end:
			start, end = end, start

		dbg.setStatusBar("Searching...")
		dbg.getMemoryPages()
		process_error_found = False
		for a in dbg.MemoryPages.keys():

			if (ptr_to_get < 0) or (ptr_to_get > 0 and ptr_counter < ptr_to_get):
		
				# get end address of the page
				page_start = a
				page_size = dbg.MemoryPages[a].getSize()
				page_end   = a + page_size
				
				if ( start > page_end or end < page_start ):
					# we are outside the search range, skip
					continue
				if (not meetsAccessLevel(dbg.MemoryPages[a],criteria["accesslevel"])):
					#skip this page, not executable
					continue
					
				# if the criteria check for nulls or unicode, we can skip
				# modules that start with 00
				start_fb = toHex(page_start)[0:2]
				end_fb = toHex(page_end)[0:2]
				if ( ("nonull" in criteria and criteria["nonull"]) and start_fb == "00" and end_fb == "00"  ):
					if not silent:
						dbg.log("      !Skipped search of range %08x-%08x (Has nulls)" % (page_start,page_end))
					continue
				
				if (( ("startswithnull" in criteria and criteria["startswithnull"]))
						and (start_fb != "00" or end_fb != "00")):
					if not silent:
						dbg.log("      !Skipped search of range %08x-%08x (Doesn't start with null)" % (page_start,page_end))
					continue

				mem = dbg.MemoryPages[a].getMemory()
				if not mem:
					continue
				
				# loop on each sequence
				for seq in sequences:
					if (ptr_to_get < 0) or (ptr_to_get > 0 and ptr_counter < ptr_to_get):
						buf = None
						human_format = ""
						if type(seq) == str:
							human_format = seq.replace("\n"," # ")
							buf = dbg.assemble(seq)
						else:
							human_format = seq[0].replace("\n"," # ")
							buf = seq[1]

						recur_find   = []		
						try:
							buf_len      = len(buf)
							mem_list     = mem.split( buf )
							total_length = buf_len * -1
						except:
							process_error_found = True
							dbg.log(" ** Unable to process searchPattern '%s'. **" % human_format)
							break
						
						for i in mem_list:
							total_length = total_length + len(i) + buf_len
							seq_address = a + total_length
							recur_find.append( seq_address )

						#The last one is the remaining slice from the split
						#so remove it from the list
						del recur_find[ len(recur_find) - 1 ]

						page_find = []
						for i in recur_find:
							if ( i >= start and i <= end ):
								
								ptr = MnPointer(i)

								# check if pointer meets criteria
								if not meetsCriteria(ptr, criteria):
									continue
								
								page_find.append(i)
								
								ptr_counter += 1
								if ptr_to_get > 0 and ptr_counter >= ptr_to_get:
								#stop search
									if human_format in found_opcodes:
										found_opcodes[human_format] += page_find
									else:
										found_opcodes[human_format] = page_find
									return found_opcodes
						#add current pointers to the list and continue		
						if len(page_find) > 0:
							if human_format in found_opcodes:
								found_opcodes[human_format] += page_find
							else:
								found_opcodes[human_format] = page_find
				if process_error_found:
					break
	return found_opcodes

# search for byte sequences in a module
def searchInModule(sequences, name,criteria=[]):
	"""
	search for byte sequences in a specified module

	Arguments:
	sequences - array of byte sequences to search for
	name - the name of the module to search in

	Return:
	Dictionary (text opcode => array of addresses)
	"""	
	
	module = dbg.getModule(name)
	if(not module):
		self.log("module %s not found" % name)
		return []
	
	# get the base and end address of the module
	start = module.getBaseAddress()
	end   = start + module.getSize()

	return searchInRange(sequences, start, end, criteria)

def getRangesOutsideModules():
	"""
	This function will enumerate all memory ranges that are not asssociated with a module
	
	Arguments : none
	
	Returns : array of arrays, each containing a start and end address
	"""	
	ranges=[]
	moduleranges=[]
	#get all ranges associated with modules
	#force full rebuild to get all modules
	populateModuleInfo()
	for thismodule,modproperties in g_modules.iteritems():
		top = 0
		base = 0
		for modprop,modval in modproperties.iteritems():
			if modprop == "top":
				top = modval
			if modprop == "base":
				base = modval
		moduleranges.append([base,top])
	#sort them
	moduleranges.sort()
	#get all ranges before, after and in between modules
	startpointer = 0
	endpointer = TOP_USERLAND
	for modbase,modtop in moduleranges:
		endpointer = modbase-1
		ranges.append([startpointer,endpointer])
		startpointer = modtop+1
	ranges.append([startpointer,TOP_USERLAND])
	#return array
	return ranges

def isModuleLoadedInProcess(modulename):
	if len(g_modules) == 0:
		populateModuleInfo()
	modulefound = False
	module = dbg.getModule(modulename)
	if(not module):
		modulefound = False
	else:
		modulefound = True
	return modulefound
	

def UnicodeTransformInfo(hexaddr):
	"""
	checks if the address can be used as unicode ansi transform
	
	Arguments:
	hexaddr  - a string containing the address in hex format (4 bytes - 8 characters)
	
	Return:
	string with unicode transform info, or empty if address is not unicode transform
	"""
	outstring = ""
	transform=0
	almosttransform=0
	begin = hexaddr[0] + hexaddr[1]
	middle = hexaddr[4] + hexaddr[5]
	twostr=hexaddr[2]+hexaddr[3]
	begintwostr = hexaddr[6]+hexaddr[7]
	threestr=hexaddr[4]+hexaddr[5]+hexaddr[6]
	fourstr=hexaddr[4]+hexaddr[5]+hexaddr[6]+hexaddr[7]
	beginfourstr = hexaddr[0]+hexaddr[1]+hexaddr[2]+hexaddr[3]
	threestr=threestr.upper()
	fourstr=fourstr.upper()
	begintwostr = begintwostr.upper()
	beginfourstr = beginfourstr.upper()
	uniansiconv = [  ["20AC","80"], ["201A","82"],
		["0192","83"], ["201E","84"], ["2026","85"],
		["2020","86"], ["2021","87"], ["02C6","88"],
		["2030","89"], ["0106","8A"], ["2039","8B"],
		["0152","8C"], ["017D","8E"], ["2018","91"],
		["2019","92"], ["201C","93"], ["201D","94"],
		["2022","95"], ["2013","96"], ["2014","97"],
		["02DC","98"], ["2122","99"], ["0161","9A"],
		["203A","9B"], ["0153","9C"], ["017E","9E"],
		["0178","9F"]
		]
	# 4 possible cases :
	# 00xxBBBB
	# 00xxBBBC (close transform)
	# AAAA00xx
	# AAAABBBB
	convbyte=""
	transbyte=""
	ansibytes=""
	#case 1 and 2
	if begin == "00":	
		for ansirec in uniansiconv:
			if ansirec[0]==fourstr:
				convbyte=ansirec[1]
				transbyte=ansirec[1]
				transform=1
				break
		if transform==1:
			outstring +="unicode ansi transformed : 00"+twostr+"00"+convbyte+","
		ansistring=""
		for ansirec in uniansiconv:
			if ansirec[0][:3]==threestr:
				if (transform==0) or (transform==1 and ansirec[1] != transbyte):
					convbyte=ansirec[1]
					ansibytes=ansirec[0]
					ansistring=ansistring+"00"+twostr+"00"+convbyte+"->00"+twostr+ansibytes+" / "
					almosttransform=1
		if almosttransform==1:
			if transform==0:
				outstring += "unicode possible ansi transform(s) : " + ansistring
			else:
				outstring +=" / alternatives (close pointers) : " + ansistring
			
	#case 3
	if middle == "00":
		transform = 0
		for ansirec in uniansiconv:
			if ansirec[0]==beginfourstr:
				convbyte=ansirec[1]
				transform=1
				break
		if transform==1:
			outstring +="unicode ansi transformed : 00"+convbyte+"00"+begintwostr+","
	#case 4
	if begin != "00" and middle != "00":
		convbyte1=""
		convbyte2=""
		transform = 0
		for ansirec in uniansiconv:
			if ansirec[0]==beginfourstr:
				convbyte1=ansirec[1]
				transform=1
				break
		if transform == 1:
			for ansirec in uniansiconv:
				if ansirec[0]==fourstr:
					convbyte2=ansirec[1]
					transform=2	
					break						
		if transform==2:
			outstring +="unicode ansi transformed : 00"+convbyte1+"00"+convbyte2+","
	
	# done
	outstring = outstring.rstrip(" / ")
	
	if outstring:
		if not outstring.endswith(","):
			outstring += ","
	return outstring

	
def getSearchSequences(searchtype,searchcriteria="",type="",criteria={}):
	"""
	will build array with search sequences for a given search type
	
	Arguments:
	searchtype = "jmp", "seh"
	
	SearchCriteria (optional): 
		<register> in case of "jmp" : string containing a register
	
	Return:
	array with all searches to perform
	"""
	offsets = [ "", "0x04","0x08","0x0c","0x10","0x12","0x1C","0x20","0x24"]
	regs=["eax","ebx","ecx","edx","esi","edi","ebp"]
	search=[]
	
	if searchtype.lower() == "jmp":
		if not searchcriteria: 
			searchcriteria = "esp"
		searchcriteria = searchcriteria.lower()
	
		min = 0
		max = 0
		
		if "mindistance" in criteria:
			min = criteria["mindistance"]
		if "maxdistance" in criteria:
			max = criteria["maxdistance"]
		
		minval = min
		
		while minval <= max:
		
			extraval = ""
			
			if minval != 0:
				operator = ""
				negoperator = "-"
				if minval < 0:
					operator = "-"
					negoperator = ""
				thisval = str(minval).replace("-","")
				thishexval = toHex(int(thisval))
				
				extraval = operator + thishexval
			
			if minval == 0:
				search.append("jmp " + searchcriteria )
				search.append("call " + searchcriteria)
				
				for roffset in offsets:
					search.append("push "+searchcriteria+"\nret "+roffset)
					
				for reg in regs:
					if reg != searchcriteria:
						search.append("push " + searchcriteria + "\npop "+reg+"\njmp "+reg)
						search.append("push " + searchcriteria + "\npop "+reg+"\ncall "+reg)			
						search.append("mov "+reg+"," + searchcriteria + "\njmp "+reg)
						search.append("mov "+reg+"," + searchcriteria + "\ncall "+reg)
						search.append("xchg "+reg+","+searchcriteria+"\njmp " + reg)
						search.append("xchg "+reg+","+searchcriteria+"\ncall " + reg)				
						for roffset in offsets:
							search.append("push " + searchcriteria + "\npop "+reg+"\npush "+reg+"\nret "+roffset)			
							search.append("mov "+reg+"," + searchcriteria + "\npush "+reg+"\nret "+roffset)
							search.append("xchg "+reg+","+searchcriteria+"\npush " + reg + "\nret " + roffset)	
			else:
				# offset jumps
				search.append("add " + searchcriteria + "," + operator + thishexval + "\njmp " + searchcriteria)
				search.append("add " + searchcriteria + "," + operator + thishexval + "\ncall " + searchcriteria)
				search.append("sub " + searchcriteria + "," + negoperator + thishexval + "\njmp " + searchcriteria)
				search.append("sub " + searchcriteria + "," + negoperator + thishexval + "\ncall " + searchcriteria)
				for roffset in offsets:
					search.append("add " + searchcriteria + "," + operator + thishexval + "\npush " + searchcriteria + "\nret " + roffset)
					search.append("sub " + searchcriteria + "," + negoperator + thishexval + "\npush " + searchcriteria + "\nret " + roffset)
				if minval > 0:
					search.append("jmp " + searchcriteria + extraval)
					search.append("call " + searchcriteria + extraval)
			minval += 1

	if searchtype.lower() == "seh":
		if type == "rop":
			dbg.log("    - Looking for addresses that will help with SEH overwrite & ROP" )
		for roffset in offsets:
			for r1 in regs:
				if type == "rop":
					search.append( ["add esp,4\npop " + r1+"\npop esp\nret "+roffset,dbg.assemble("add esp,4\npop " + r1+"\npop esp\nret "+roffset)] )
					search.append( ["pop " + r1+"\nadd esp,4\npop esp\nret "+roffset,dbg.assemble("pop " + r1+"\nadd esp,4\npop esp\nret "+roffset)] )				
				else:
					search.append( ["add esp,4\npop " + r1+"\nret "+roffset,dbg.assemble("add esp,4\npop " + r1+"\nret "+roffset)] )
					search.append( ["pop " + r1+"\nadd esp,4\nret "+roffset,dbg.assemble("pop " + r1+"\nadd esp,4\nret "+roffset)] )
				for r2 in regs:
					if type == "rop":
						search.append( ["pop "+r1+"\npop "+r2+"\npop esp\nret "+roffset,dbg.assemble("pop "+r1+"\npop "+r2+"\npop esp\nret "+roffset)] )
						for r3 in regs:
							search.append( ["pop "+r1+"\npop "+r2+"\npop "+r3+"\ncall ["+r3+"]",dbg.assemble("pop "+r1+"\npop "+r2+"\npop "+r3+"\ncall ["+r3+"]")] )
					else:
						thissearch = ["pop "+r1+"\npop "+r2+"\nret "+roffset,dbg.assemble("pop "+r1+"\npop "+r2+"\nret "+roffset)]
						search.append( thissearch )
			if type != "rop":		
				search.append( ["add esp,8\nret "+roffset,dbg.assemble("add esp,8\nret "+roffset)])
				search.append( ["popad\npush ebp\nret "+roffset,dbg.assemble("popad\npush ebp\nret "+roffset)])
			else:
				search.append( ["add esp,8\npop esp\nret "+roffset,dbg.assemble("add esp,8\npop esp\nret "+roffset)])
		if type != "rop":
			#popad + jmp/call
			search.append(["popad\njmp ebp",dbg.assemble("popad\njmp ebp")])
			search.append(["popad\ncall ebp",dbg.assemble("popad\ncall ebp")])		
			#call / jmp dword
			search.append(["call dword ptr ss:[esp+08]","\xff\x54\x24\x08"])
			search.append(["call dword ptr ss:[esp+08]","\xff\x94\x24\x08\x00\x00\x00"])
			search.append(["call dword ptr ds:[esp+08]","\x3e\xff\x54\x24\x08"])

			search.append(["jmp dword ptr ss:[esp+08]","\xff\x64\x24\x08"])
			search.append(["jmp dword ptr ss:[esp+08]","\xff\xa4\x24\x08\x00\x00\x00"])
			search.append(["jmp dword ptr ds:[esp+08]","\x3e\xff\x64\x24\x08"])
			
			search.append(["call dword ptr ss:[esp+14]","\xff\x54\x24\x14"])
			search.append(["call dword ptr ss:[esp+14]","\xff\x94\x24\x14\x00\x00\x00"])	
			search.append(["call dword ptr ds:[esp+14]","\x3e\xff\x54\x24\x14"])
			
			search.append(["jmp dword ptr ss:[esp+14]","\xff\x64\x24\x14"])
			search.append(["jmp dword ptr ss:[esp+14]","\xff\xa4\x24\x14\x00\x00\x00"])		
			search.append(["jmp dword ptr ds:[esp+14]","\x3e\xff\x64\x24\x14"])
			
			search.append(["call dword ptr ss:[esp+1c]","\xff\x54\x24\x1c"])
			search.append(["call dword ptr ss:[esp+1c]","\xff\x94\x24\x1c\x00\x00\x00"])		
			search.append(["call dword ptr ds:[esp+1c]","\x3e\xff\x54\x24\x1c"])
			
			search.append(["jmp dword ptr ss:[esp+1c]","\xff\x64\x24\x1c"])
			search.append(["jmp dword ptr ss:[esp+1c]","\xff\xa4\x24\x1c\x00\x00\x00"])		
			search.append(["jmp dword ptr ds:[esp+1c]","\x3e\xff\x64\x24\x1c"])
			
			search.append(["call dword ptr ss:[esp+2c]","\xff\x54\x24\x2c"])
			search.append(["call dword ptr ss:[esp+2c]","\xff\x94\x24\x2c\x00\x00\x00"])
			search.append(["call dword ptr ds:[esp+2c]","\x3e\xff\x54\x24\x2c"])

			search.append(["jmp dword ptr ss:[esp+2c]","\xff\x64\x24\x2c"])
			search.append(["jmp dword ptr ss:[esp+2c]","\xff\xa4\x24\x2c\x00\x00\x00"])		
			search.append(["jmp dword ptr ds:[esp+2c]","\x3e\xff\x64\x24\x2c"])
			
			search.append(["call dword ptr ss:[esp+44]","\xff\x54\x24\x44"])
			search.append(["call dword ptr ss:[esp+44]","\xff\x94\x24\x44\x00\x00\x00"])		
			search.append(["call dword ptr ds:[esp+44]","\x3e\xff\x54\x24\x44"])		
			
			search.append(["jmp dword ptr ss:[esp+44]","\xff\x64\x24\x44"])
			search.append(["jmp dword ptr ss:[esp+44]","\xff\xa4\x24\x44\x00\x00\x00"])
			search.append(["jmp dword ptr ds:[esp+44]","\x3e\xff\x64\x24\x44"])
			
			search.append(["call dword ptr ss:[esp+50]","\xff\x54\x24\x50"])
			search.append(["call dword ptr ss:[esp+50]","\xff\x94\x24\x50\x00\x00\x00"])		
			search.append(["call dword ptr ds:[esp+50]","\x3e\xff\x54\x24\x50"])		
			
			search.append(["jmp dword ptr ss:[esp+50]","\xff\x64\x24\x50"])
			search.append(["jmp dword ptr ss:[esp+50]","\xff\xa4\x24\x50\x00\x00\x00"])
			search.append(["jmp dword ptr ds:[esp+50]","\x3e\xff\x64\x24\x50"])
			
			search.append(["call dword ptr ss:[ebp+0c]","\xff\x55\x0c"])
			search.append(["call dword ptr ss:[ebp+0c]","\xff\x95\x0c\x00\x00\x00"])		
			search.append(["call dword ptr ds:[ebp+0c]","\x3e\xff\x55\x0c"])		
			
			search.append(["jmp dword ptr ss:[ebp+0c]","\xff\x65\x0c"])
			search.append(["jmp dword ptr ss:[ebp+0c]","\xff\xa5\x0c\x00\x00\x00"])		
			search.append(["jmp dword ptr ds:[ebp+0c]","\x3e\xff\x65\x0c"])		
			
			search.append(["call dword ptr ss:[ebp+24]","\xff\x55\x24"])
			search.append(["call dword ptr ss:[ebp+24]","\xff\x95\x24\x00\x00\x00"])		
			search.append(["call dword ptr ds:[ebp+24]","\x3e\xff\x55\x24"])
			
			search.append(["jmp dword ptr ss:[ebp+24]","\xff\x65\x24"])
			search.append(["jmp dword ptr ss:[ebp+24]","\xff\xa5\x24\x00\x00\x00"])		
			search.append(["jmp dword ptr ds:[ebp+24]","\x3e\xff\x65\x24"])	
			
			search.append(["call dword ptr ss:[ebp+30]","\xff\x55\x30"])
			search.append(["call dword ptr ss:[ebp+30]","\xff\x95\x30\x00\x00\x00"])		
			search.append(["call dword ptr ds:[ebp+30]","\x3e\xff\x55\x30"])
			
			search.append(["jmp dword ptr ss:[ebp+30]","\xff\x65\x30"])
			search.append(["jmp dword ptr ss:[ebp+30]","\xff\xa5\x30\x00\x00\x00"])		
			search.append(["jmp dword ptr ds:[ebp+30]","\x3e\xff\x65\x30"])	
			
			search.append(["call dword ptr ss:[ebp-04]","\xff\x55\xfc"])
			search.append(["call dword ptr ss:[ebp-04]","\xff\x95\xfc\xff\xff\xff"])		
			search.append(["call dword ptr ds:[ebp-04]","\x3e\xff\x55\xfc"])
			
			search.append(["jmp dword ptr ss:[ebp-04]","\xff\x65\xfc",])
			search.append(["jmp dword ptr ss:[ebp-04]","\xff\xa5\xfc\xff\xff\xff",])		
			search.append(["jmp dword ptr ds:[ebp-04]","\x3e\xff\x65\xfc",])		
			
			search.append(["call dword ptr ss:[ebp-0c]","\xff\x55\xf4"])
			search.append(["call dword ptr ss:[ebp-0c]","\xff\x95\xf4\xff\xff\xff"])		
			search.append(["call dword ptr ds:[ebp-0c]","\x3e\xff\x55\xf4"])
			
			search.append(["jmp dword ptr ss:[ebp-0c]","\xff\x65\xf4",])
			search.append(["jmp dword ptr ss:[ebp-0c]","\xff\xa5\xf4\xff\xff\xff",])		
			search.append(["jmp dword ptr ds:[ebp-0c]","\x3e\xff\x65\xf4",])
			
			search.append(["call dword ptr ss:[ebp-18]","\xff\x55\xe8"])
			search.append(["call dword ptr ss:[ebp-18]","\xff\x95\xe8\xff\xff\xff"])		
			search.append(["call dword ptr ds:[ebp-18]","\x3e\xff\x55\xe8"])
			
			search.append(["jmp dword ptr ss:[ebp-18]","\xff\x65\xe8",])
			search.append(["jmp dword ptr ss:[ebp-18]","\xff\xa5\xe8\xff\xff\xff",])		
			search.append(["jmp dword ptr ds:[ebp-18]","\x3e\xff\x65\xe8",])
	return search

	
def getModulesToQuery(criteria):
	"""
	This function will return an array of modulenames
	
	Arguments:
	Criteria - dictionary with module criteria
	
	Return:
	array with module names that meet the given criteria
	
	"""	
	if len(g_modules) == 0:
		populateModuleInfo()
	modulestoquery=[]
	for thismodule,modproperties in g_modules.iteritems():
		#is this module excluded ?
		thismod = MnModule(thismodule)	
		included = True
		if not thismod.isExcluded:
			#check other criteria
			if ("safeseh" in criteria) and ((not criteria["safeseh"]) and thismod.isSafeSEH):
				included = False
			if ("aslr" in criteria) and ((not criteria["aslr"]) and thismod.isAslr):
				included = False
			if ("rebase" in criteria) and ((not criteria["rebase"]) and thismod.isRebase):
				included = False
			if ("os" in criteria) and ((not criteria["os"]) and thismod.isOS):
				included = False
			if ("nx" in criteria) and ((not criteria["nx"]) and thismod.isNX):
				included = False				
		else:
			included = False
		#override all previous decision if "modules" criteria was provided
		thismodkey = thismod.moduleKey.lower().strip()
		if ("modules" in criteria) and (criteria["modules"] != ""):
			included = False
			modulenames=criteria["modules"].split(",")
			for modulename in modulenames:
				modulename = modulename.strip('"').strip("'").lower()
				modulenamewithout = modulename.replace("*","")
				if len(modulenamewithout) <= len(thismodkey):
					#endswith ?
					if modulename[0] == "*":
						if modulenamewithout == thismodkey[len(thismodkey)-len(modulenamewithout):len(thismodkey)]:
							if not thismod.moduleKey in modulestoquery and not thismod.isExcluded:
								modulestoquery.append(thismod.moduleKey)
					#startswith ?
					if modulename[len(modulename)-1] == "*":
						if (modulenamewithout == thismodkey[0:len(modulenamewithout)] and not thismod.isExcluded):
							if not thismod.moduleKey in modulestoquery:
								modulestoquery.append(thismod.moduleKey)
					#contains ?
					if ((modulename[0] == "*" and modulename[len(modulename)-1] == "*") or (modulename.find("*") == -1)) and not thismod.isExcluded:
						if thismodkey.find(modulenamewithout) > -1:
							if not thismod.moduleKey in modulestoquery:
								modulestoquery.append(thismod.moduleKey)

		if included:
			modulestoquery.append(thismod.moduleKey)		
	return modulestoquery	
	
	
	
def getPointerAccess(address):
	"""
	Returns access level of specified address, in human readable format
	
	Arguments:
	address - integer value
	
	Return:
	Access level (human readable format)
	"""
	global MemoryPageACL

	paccess = ""
	try:
		page   = dbg.getMemoryPageByAddress( address )
		if page in MemoryPageACL:
			paccess = MemoryPageACL[page]
		else:
			paccess = page.getAccess( human = True )
			MemoryPageACL[page] = paccess
	except:
		paccess = ""
	return paccess


def getModuleProperty(modname,parameter):
	"""
	Returns value of a given module property
	Argument : 
	modname - module name
	parameter name - (see populateModuleInfo())
	
	Returns : 
	value associcated with the given parameter / module combination
	
	"""
	modname=modname.strip()
	parameter=parameter.lower()
	valtoreturn=""
	# try case sensitive first
	for thismodule,modproperties in g_modules.iteritems():
		if thismodule.strip() == modname:
			return modproperties[parameter]
	return valtoreturn


def populateModuleInfo():
	"""
	Populate global dictionary with information about all loaded modules
	
	Return:
	Dictionary
	"""
	if not silent:
		dbg.setStatusBar("Getting modules info...")
		dbg.log("[+] Generating module info table, hang on...")
		dbg.log("    - Processing modules")
		dbg.updateLog()
	global g_modules
	g_modules={}
	allmodules=dbg.getAllModules()
	curmod = ""
	for key in allmodules.keys():
		modinfo={}
		thismod = MnModule(key)
		if not thismod is None:
			modinfo["path"]		= thismod.modulePath
			modinfo["base"] 	= thismod.moduleBase
			modinfo["size"] 	= thismod.moduleSize
			modinfo["top"]  	= thismod.moduleTop
			modinfo["safeseh"]	= thismod.isSafeSEH
			modinfo["aslr"]		= thismod.isAslr
			modinfo["nx"]		= thismod.isNX
			modinfo["rebase"]	= thismod.isRebase
			modinfo["version"]	= thismod.moduleVersion
			modinfo["os"]		= thismod.isOS
			modinfo["name"]		= key
			modinfo["entry"]	= thismod.moduleEntry
			modinfo["codebase"]	= thismod.moduleCodebase
			modinfo["codesize"]	= thismod.moduleCodesize
			modinfo["codetop"]	= thismod.moduleCodetop
			g_modules[thismod.moduleKey] = modinfo
		else:
			if not silent:
				dbg.log("    - Oops, potential issue with module %s, skipping module" % key)
	if not silent:
		dbg.log("    - Done. Let's rock 'n roll.")
		dbg.setStatusBar("")	
		dbg.updateLog()

def ModInfoCached(modulename):
	"""
	Check if the information about a given module is already cached in the global Dictionary
	
	Arguments:
	modulename -  name of the module to check
	
	Return:
	Boolean - True if the module info is cached
	"""
	if (getModuleProperty(modulename,"base") == ""):
		return False
	else:
		return True

def showModuleTable(logfile="", modules=[]):
	"""
	Shows table with all loaded modules and their properties.

	Arguments :
	empty string - output will be sent to log window
	or
	filename - output will be written to the filename
	
	modules - dictionary with modules to query - result of a populateModuleInfo() call
	"""	
	thistable = ""
	if len(g_modules) == 0:
		populateModuleInfo()
	thistable += "-----------------------------------------------------------------------------------------------------------------------------------------\n"
	thistable += " Module info :\n"
	thistable += "-----------------------------------------------------------------------------------------------------------------------------------------\n"
	if arch == 32:
		thistable += " Base       | Top        | Size       | Rebase | SafeSEH | ASLR  | NXCompat | OS Dll | Version, Modulename & Path\n"
	elif arch == 64:
		thistable += " Base               | Top                | Size               | Rebase | SafeSEH | ASLR  | NXCompat | OS Dll | Version, Modulename & Path\n"
	thistable += "-----------------------------------------------------------------------------------------------------------------------------------------\n"

	for thismodule,modproperties in g_modules.iteritems():
		if (len(modules) > 0 and modproperties["name"] in modules or len(logfile)>0):
			rebase	= toSize(str(modproperties["rebase"]),7)
			base 	= toSize(str("0x" + toHex(modproperties["base"])),10)
			top 	= toSize(str("0x" + toHex(modproperties["top"])),10)
			size 	= toSize(str("0x" + toHex(modproperties["size"])),10)
			safeseh = toSize(str(modproperties["safeseh"]),7)
			aslr 	= toSize(str(modproperties["aslr"]),5)
			nx 		= toSize(str(modproperties["nx"]),7)
			isos 	= toSize(str(modproperties["os"]),7)
			version = str(modproperties["version"])
			path 	= str(modproperties["path"])
			name	= str(modproperties["name"])
			thistable += " " + base + " | " + top + " | " + size + " | " + rebase +"| " +safeseh + " | " + aslr + " |  " + nx + " | " + isos + "| " + version + " [" + name + "] (" + path + ")\n"
	thistable += "-----------------------------------------------------------------------------------------------------------------------------------------\n"
	tableinfo = thistable.split('\n')
	if logfile == "":
		for tline in tableinfo:
			dbg.log(tline)
	else:
		with open(logfile,"a") as fh:
			fh.writelines(thistable)
		
#-----------------------------------------------------------------------#
# This is where the action is
#-----------------------------------------------------------------------#	

def processResults(all_opcodes,logfile,thislog,specialcases = {},ptronly = False):
	"""
	Write the output of a search operation to log file

	Arguments:
	all_opcodes - dictionary containing the results of a search 
	logfile - the MnLog object
	thislog - the filename to write to

	Return:
	written content in log file
	first 20 pointers are shown in the log window
	"""
	ptrcnt = 0
	cnt = 0
	
	global silent
	
	if all_opcodes:
		dbg.log("[+] Writing results to %s" % thislog)
		for hf in all_opcodes:
			if not silent:
				try:
					dbg.log("    - Number of pointers of type '%s' : %d " % (hf,len(all_opcodes[hf])))
				except:
					dbg.log("    - Number of pointers of type '<unable to display>' : %d " % (len(all_opcodes[hf])))
		if not ptronly:

			if not silent:
				dbg.log("[+] Results : ")
			messageshown = False
			for optext,pointers in all_opcodes.iteritems():
				for ptr in pointers:
					ptrinfo = ""
					modinfo = ""
					ptrx = MnPointer(ptr)
					modname = ptrx.belongsTo()
					if not modname == "":
						modobj = MnModule(modname)
						ptrextra = ""
						rva=0
						if (modobj.isRebase or modobj.isAslr):
							rva = ptr - modobj.moduleBase
							ptrextra = " (b+0x" + toHex(rva)+") "
						ptrinfo = "0x" + toHex(ptr) + ptrextra + " : " + optext + " | " + ptrx.__str__()  + " " + modobj.__str__()
					else:
						ptrinfo = "0x" + toHex(ptr) + " : " + optext + " | " + ptrx.__str__() 
						if ptrx.isOnStack():
							ptrinfo += " [Stack] "
						elif ptrx.isInHeap():
							ptrinfo += " [Heap] "
					logfile.write(ptrinfo,thislog)
					if (ptr_to_get > -1) or (cnt < 20):
						if not silent:
							dbg.log("  %s" % ptrinfo,address=ptr)
						cnt += 1
					ptrcnt += 1
					if (ptr_to_get == -1 or ptr_to_get > 20) and cnt == 20 and not silent and not messageshown:
						dbg.log("... Please wait while I'm processing all remaining results and writing everything to file...")
						messageshown = True
			if cnt < ptrcnt:
				if not silent:
					dbg.log("[+] Done. Only the first %d pointers are shown here. For more pointers, open %s..." % (cnt,thislog)) 
		else:
			allptr = []
			ptrcnt = 0
			ptrinfo = ""
			dbg.log("... Please wait while I'm processing results and writing everything to file...")
			for optext,pointers in all_opcodes.iteritems():
				for ptr in pointers:
					if not ptr in allptr:
						ptrinfo += "0x%s\n" % toHex(ptr)
						ptrcnt += 1
			if not silent:
				dbg.log("[+] Writing results to file")
			logfile.write(ptrinfo,thislog)
			if not silent:
				dbg.log("[+] Done")
	dbg.log("    Found a total of %d pointers" % ptrcnt, highlight=1)
	dbg.setStatusBar("Done. Found %d pointers" % ptrcnt)
	
	
def mergeOpcodes(all_opcodes,found_opcodes):
	"""
	merges two dictionaries together

	Arguments:
	all_opcodes - the target dictionary
	found_opcodes - the source dictionary

	Return:
	Dictionary (merged dictionaries)
	"""
	if found_opcodes:
		for hf in found_opcodes:
			if hf in all_opcodes:
				all_opcodes[hf] += found_opcodes[hf]
			else:
				all_opcodes[hf] = found_opcodes[hf]
	return all_opcodes

	
def findSEH(modulecriteria={},criteria={}):
	"""
	Performs a search for pointers to gain code execution in a SEH overwrite exploit

	Arguments:
	modulecriteria - dictionary with criteria modules need to comply with.
	                 Default settings are : ignore aslr, rebase and safeseh protected modules
	criteria - dictionary with criteria the pointers need to comply with.

	Return:
	Dictionary (pointers)
	"""
	type = ""
	if "rop" in criteria:
		type = "rop"
	search = getSearchSequences("seh",0,type) 
	
	found_opcodes = {}
	all_opcodes = {}
		
	modulestosearch = getModulesToQuery(modulecriteria)
	if not silent:
		dbg.log("[+] Querying %d modules" % len(modulestosearch))
	
	starttime = datetime.datetime.now()
	for thismodule in modulestosearch:
		if not silent:
			dbg.log("    - Querying module %s" % thismodule)
		dbg.updateLog()
		#search
		found_opcodes = searchInModule(search,thismodule,criteria)
		#merge results
		all_opcodes = mergeOpcodes(all_opcodes,found_opcodes)
	#search outside modules
	if "all" in criteria:
		if "accesslevel" in criteria:
			if criteria["accesslevel"].find("R") == -1:
				if not silent:
					dbg.log("[+] Setting pointer access level criteria to 'R', to increase search results")
				criteria["accesslevel"] = "R"
				if not silent:
					dbg.log("    New pointer access level : %s" % criteria["accesslevel"])
		if criteria["all"]:
			rangestosearch = getRangesOutsideModules()
			if not silent:
				dbg.log("[+] Querying memory outside modules")
			for thisrange in rangestosearch:
				if not silent:
					dbg.log("    - Querying 0x%08x - 0x%08x" % (thisrange[0],thisrange[1]))
				found_opcodes = searchInRange(search, thisrange[0], thisrange[1],criteria)
				all_opcodes = mergeOpcodes(all_opcodes,found_opcodes)
			if not silent:
				dbg.log("    - Search complete, processing results")
			dbg.updateLog()
	return all_opcodes
	

def findJMP(modulecriteria={},criteria={},register="esp"):
	"""
	Performs a search for pointers to jump to a given register

	Arguments:
	modulecriteria - dictionary with criteria modules need to comply with.
	                 Default settings are : ignore aslr and rebased modules
	criteria - dictionary with criteria the pointers need to comply with.
	register - the register to jump to

	Return:
	Dictionary (pointers)
	"""
	search = getSearchSequences("jmp",register,"",criteria) 
	
	found_opcodes = {}
	all_opcodes = {}
		
	modulestosearch = getModulesToQuery(modulecriteria)
	if not silent:
		dbg.log("[+] Querying %d modules" % len(modulestosearch))
	
	starttime = datetime.datetime.now()
	for thismodule in modulestosearch:
		if not silent:
			dbg.log("    - Querying module %s" % thismodule)
		dbg.updateLog()
		#search
		found_opcodes = searchInModule(search,thismodule,criteria)
		#merge results
		all_opcodes = mergeOpcodes(all_opcodes,found_opcodes)
	if not silent:
		dbg.log("    - Search complete, processing results")
	dbg.updateLog()
	return all_opcodes	


	
def findROPFUNC(modulecriteria={},criteria={},searchfuncs=[]):
	"""
	Performs a search for pointers to pointers to interesting functions to facilitate a ROP exploit

	Arguments:
	modulecriteria - dictionary with criteria modules need to comply with.
	                 Default settings are : ignore aslr and rebased modules
	criteria - dictionary with criteria the pointers need to comply with.
	optional :
	searchfuncs - array with functions to include in the search

	Return:
	Dictionary (pointers)
	"""
	found_opcodes = {}
	all_opcodes = {}
	ptr_counter = 0
	ropfuncs = {}
	funccallresults = []
	ropfuncoffsets = {}
	functionnames = []
	offsets = {}
	
	modulestosearch = getModulesToQuery(modulecriteria)
	if searchfuncs == []:
		functionnames = ["virtualprotect","virtualalloc","heapalloc","winexec","setprocessdeppolicy","heapcreate","setinformationprocess","writeprocessmemory","memcpy","memmove","strncpy","createmutex","getlasterror","strcpy","loadlibrary","freelibrary","getmodulehandle","getprocaddress","openfile","createfile","createfilemapping","mapviewoffile","openfilemapping"]
		offsets["kernel32.dll"] = ["virtualprotect","virtualalloc","writeprocessmemory"]
		# on newer OSes, functions are stored in kernelbase.dll
		offsets["kernelbase.dll"] = ["virtualprotect","virtualalloc","writeprocessmemory"]
	else:
		functionnames = searchfuncs
		offsets["kernel32.dll"] = searchfuncs
		# on newer OSes, functions are stored in kernelbase.dll
		offsets["kernelbase.dll"] = searchfuncs
	if not silent:
		dbg.log("[+] Looking for pointers to interesting functions...")
	curmod = ""
	#ropfuncfilename="ropfunc.txt"
	#objropfuncfile = MnLog(ropfuncfilename)
	#ropfuncfile = objropfuncfile.reset()
	
	offsetpointers = {}
	
	# populate absolute pointers
	for themod in offsets:
		fnames = offsets[themod]
		try:
			themodule = MnModule(themod)
			if not themodule is None:
				allfuncs = themodule.getEAT()
				for fn in allfuncs:
					for fname in fnames:
						if allfuncs[fn].lower().find(fname.lower()) > -1:
							#dbg.log("Found match: %s %s -> %s ?" % (themod, allfuncs[fn].lower(), fname.lower()))
							fname = allfuncs[fn].lower()
							if not fname in offsetpointers:
								offsetpointers[fname] = fn
							break
		except:
			continue

	# found pointers to functions
	# now query IATs
	#dbg.log("%s" % modulecriteria)		
	isrebased = False
	for key in modulestosearch:
		curmod = dbg.getModule(key)
		#dbg.log("Searching in IAT of %s" % key)
		#is this module going to get rebase ?
		themodule = MnModule(key)
		isrebased = themodule.isRebase
		if not silent:
			dbg.log("     - Querying %s" % (key))		
		allfuncs = themodule.getIAT()
		dbg.updateLog()
		for fn in allfuncs:
			thisfuncname = allfuncs[fn].lower()
			thisfuncfullname = thisfuncname
			if not meetsCriteria(MnPointer(fn), criteria):
				continue
			ptr = 0
			try:
				ptr=struct.unpack('<L',dbg.readMemory(fn,4))[0]
			except:
				pass
			if ptr != 0:
				# get offset to one of the offset functions
				# where does pointer belong to ?
				pmodname = MnPointer(ptr).belongsTo()
				if pmodname != "":
					if pmodname.lower() in offsets:
						# find distance to each of the interesting functions in this module
						for interestingfunc in offsets[pmodname.lower()]:
							if interestingfunc in offsetpointers:
								offsetvalue = offsetpointers[interestingfunc] - ptr
								operator = ""
								if offsetvalue < 0:
									operator = "-"
								offsetvaluehex = toHex(offsetvalue).replace("-","")
								thetype = "(%s - IAT 0x%s : %s.%s (0x%s), offset to %s.%s (0x%s) : %d (%s0x%s)" % (key,toHex(fn),pmodname,thisfuncfullname,toHex(ptr),pmodname,interestingfunc,toHex(offsetpointers[interestingfunc]),offsetvalue,operator,offsetvaluehex)
								if not thetype in ropfuncoffsets:
									ropfuncoffsets[thetype] = [fn]
				
				# see if it's a function we are looking for
				for funcsearch in functionnames:
					funcsearch = funcsearch.lower()
					if thisfuncname.find(funcsearch) > -1:
						extra = ""
						extrafunc = ""
						if isrebased:
							extra = " [Warning : module is likely to get rebased !]"
							extrafunc = "-rebased"
						if not silent:
							dbg.log("       0x%s : ptr to %s (0x%s) (%s) %s" % (toHex(fn),thisfuncname,toHex(ptr),key,extra))
						logtxt = thisfuncfullname.lower().strip()+extrafunc+" | 0x" + toHex(ptr)
						if logtxt in ropfuncs:
								ropfuncs[logtxt] += [fn]
						else:
								ropfuncs[logtxt] = [fn]
						ptr_counter += 1
						if ptr_to_get > 0 and ptr_counter >= ptr_to_get:
							ropfuncs,ropfuncoffsets
	return ropfuncs,ropfuncoffsets

def assemble(instructions,encoder=""):
	"""
	Assembles one or more instructions to opcodes

	Arguments:
	instructions = the instructions to assemble (separated by #)

	Return:
	Dictionary (pointers)
	"""
	if not silent:
		dbg.log("Opcode results : ")
		dbg.log("---------------- ")
	allopcodes=""

	instructions = instructions.replace('"',"").replace("'","")

	splitter=re.compile('#')
	instructions=splitter.split(instructions)
	for instruct in instructions:
		try:
			instruct = instruct.strip()
			assembled=dbg.assemble(instruct)
			strAssembled=""
			for assemOpc in assembled:
				if (len(hex(ord(assemOpc)))) == 3:
					subAssembled = "\\x0"+hex(ord(assemOpc)).replace('0x','')
					strAssembled = strAssembled+subAssembled
				else:
					strAssembled =  strAssembled+hex(ord(assemOpc)).replace('0x', '\\x')
			if len(strAssembled) < 30:
				if not silent:
					dbg.log(" %s = %s" % (instruct,strAssembled))
				allopcodes=allopcodes+strAssembled
			else:
				if not silent:
					dbg.log(" %s => Unable to assemble this instruction !" % instruct,highlight=1)
		except:
			if not silent:
				dbg.log("   Could not assemble %s " % instruct)
			pass
	if not silent:
		dbg.log(" Full opcode : %s " % allopcodes)
	return allopcodes
	



	
def findROPGADGETS(modulecriteria={},criteria={},endings=[],maxoffset=40,depth=5,split=False,pivotdistance=0,fast=False,mode="all", sortedprint=False, technique=""):
	"""
	Searches for rop gadgets

	Arguments:
	modulecriteria - dictionary with criteria modules need to comply with.
	                 Default settings are : ignore aslr and rebased modules
	criteria - dictionary with criteria the pointers need to comply with.
	endings - array with all rop gadget endings to look for. Default : RETN and RETN+offsets
	maxoffset - maximum offset value for RETN if endings are set to RETN
	depth - maximum number of instructions to go back
	split - Boolean that indicates whether routine should write all gadgets to one file, or split per module
	pivotdistance - minimum distance a stackpivot needs to be
	fast - Boolean indicating if you want to process less obvious gadgets as well
	mode - internal use only
	sortedprint - sort pointers before printing output to rop.txt
	technique - create all chains if empty. otherwise, create virtualalloc or virtualprotect chain (based on what is specified)
	
	Return:
	Output is written to files, containing rop gadgets, suggestions, stack pivots and virtualprotect/virtualalloc routine (if possible)
	"""
	
	found_opcodes = {}
	all_opcodes = {}
	ptr_counter = 0
	valid_techniques = ["virtualalloc", "virtualprotect"]

	modulestosearch = getModulesToQuery(modulecriteria)
	
	progressid=str(dbg.getDebuggedPid())
	progressfilename="_rop_progress_"+dbg.getDebuggedName()+"_"+progressid+".log"
	
	objprogressfile = MnLog(progressfilename)
	progressfile = objprogressfile.reset()

	dbg.log("[+] Progress will be written to %s" % progressfilename)
	dbg.log("[+] Maximum offset : %d" % maxoffset)
	dbg.log("[+] (Minimum/optional maximum) stackpivot distance : %s" % str(pivotdistance))
	dbg.log("[+] Max nr of instructions : %d" % depth)
	dbg.log("[+] Split output into module rop files ? %s" % split)
	#dbg.log("[+] Technique: %s" % technique)    
	if technique != "" and technique in valid_techniques:
		dbg.log("[+] Only creating rop chain for '%s'" % technique)
	else:
		dbg.log("[+] Going to create rop chains for all relevant/supported techniques: %s" % technique)
	usefiles = False
	filestouse = []
	vplogtxt = ""
	suggestions = {}

	if "f" in criteria:
		if criteria["f"] != "":
			if type(criteria["f"]).__name__.lower() != "bool":		
				usefiles = True
				rawfilenames = criteria["f"].replace('"',"")
				allfiles = rawfilenames.split(',')
				#check if files exist
				dbg.log("[+] Attempting to use %d rop file(s) as input" % len(allfiles))
				for fname in allfiles:
					fname = fname.strip()
					if not os.path.exists(fname):
						dbg.log("     ** %s : Does not exist !" % fname, highlight=1)
					else:
						filestouse.append(fname)
				if len(filestouse) == 0:
					dbg.log(" ** Unable to find any of the source files, aborting... **", highlight=1)
					return
		
	search = []
	
	if not usefiles:
		if len(endings) == 0:
			#RETN only
			search.append("RETN")
			for i in range(0, maxoffset + 1, 2):
				search.append("RETN 0x"+ toHexByte(i))
		else:
			for ending in endings:
				dbg.log("[+] Custom ending : %s" % ending)
				if ending != "":
					search.append(ending)
		if len(modulestosearch) == 0:
			dbg.log("[-] No modules selected, aborting search", highlight = 1)
			return

		dbg.log("[+] Enumerating %d endings in %d module(s)..." % (len(search),len(modulestosearch)))
		for thismodule in modulestosearch:
			dbg.log("    - Querying module %s" % thismodule)
			dbg.updateLog()
			#search
			found_opcodes = searchInModule(search,thismodule,criteria)
			#merge results
			all_opcodes = mergeOpcodes(all_opcodes,found_opcodes)
		dbg.log("    - Search complete :")
	else:
		dbg.log("[+] Reading input files")
		for filename in filestouse:
			dbg.log("     - Reading %s" % filename)
			all_opcodes = mergeOpcodes(all_opcodes,readGadgetsFromFile(filename))
			
	dbg.updateLog()
	tp = 0
	for endingtype in all_opcodes:
		if len(all_opcodes[endingtype]) > 0:
			if usefiles:
				dbg.log("       Ending : %s, Nr found : %d" % (endingtype,len(all_opcodes[endingtype]) / 2))
				tp = tp + len(all_opcodes[endingtype]) / 2
			else:
				dbg.log("       Ending : %s, Nr found : %d" % (endingtype,len(all_opcodes[endingtype])))
				tp = tp + len(all_opcodes[endingtype])
	global silent
	if not usefiles:		
		dbg.log("    - Filtering and mutating %d gadgets" % tp)
	else:
		dbg.log("    - Categorizing %d gadgets" % tp)
		silent = True
	dbg.updateLog()
	ropgadgets = {}
	interestinggadgets = {}
	stackpivots = {}
	stackpivots_safeseh = {}
	adcnt = 0
	tc = 1
	issafeseh = False
	step = 0
	updateth = 1000
	if (tp >= 2000 and tp < 5000):
		updateth = 500
	if (tp < 2000):
		updateth = 100
	for endingtype in all_opcodes:
		if len(all_opcodes[endingtype]) > 0:
			for endingtypeptr in all_opcodes[endingtype]:
				adcnt=adcnt+1
				if usefiles:
					adcnt = adcnt - 0.5
				if adcnt > (tc*updateth):
					thistimestamp=datetime.datetime.now().strftime("%a %Y/%m/%d %I:%M:%S %p")
					updatetext = "      - Progress update : " + str(tc*updateth) + " / " + str(tp) + " items processed (" + thistimestamp + ") - (" + str((tc*updateth*100)/tp)+"%)"
					objprogressfile.write(updatetext.strip(),progressfile)
					dbg.log(updatetext)
					dbg.updateLog()
					tc += 1				
				if not usefiles:
					#first get max backward instruction
					#immlib libanalyze might blow up at (self.ip=opcode[0]  # Instruction pointer), so we have to catch exceptions here
					try:
						thisopcode = dbg.disasmBackward(endingtypeptr,depth+1)
						thisptr = thisopcode.getAddress()
					except:
						dbg.log("        ** Unable to backward disassemble at 0x%0x, depth %d, skipping location" % (endingtypeptr, depth+1))
						thisopcode = ""
						thisptr = 0

					# we now have a range to mine
					startptr = thisptr
					currentmodulename = MnPointer(thisptr).belongsTo()
					modinfo = MnModule(currentmodulename)
					issafeseh = modinfo.isSafeSEH
					while startptr <= endingtypeptr and startptr != 0x0:
						# get the entire chain from startptr to endingtypeptr
						thischain = ""
						msfchain = []
						thisopcodebytes = ""
						chainptr = startptr
						if isGoodGadgetPtr(startptr,criteria) and not startptr in ropgadgets and not startptr in interestinggadgets:
							invalidinstr = False
							while chainptr < endingtypeptr and not invalidinstr:
								thisopcode = dbg.disasm(chainptr)
								thisinstruction = getDisasmInstruction(thisopcode)
								if isGoodGadgetInstr(thisinstruction) and not isGadgetEnding(thisinstruction,search):						
									thischain =  thischain + " # " + thisinstruction
									msfchain.append([chainptr,thisinstruction])
									thisopcodebytes = thisopcodebytes + opcodesToHex(thisopcode.getDump().lower())
									chainptr = dbg.disasmForwardAddressOnly(chainptr,1)
								else:
									invalidinstr = True						
							if endingtypeptr == chainptr and startptr != chainptr and not invalidinstr:
								fullchain = thischain + " # " + endingtype
								msfchain.append([endingtypeptr,endingtype])
								thisopcode = dbg.disasm(endingtypeptr)
								thisopcodebytes = thisopcodebytes + opcodesToHex(thisopcode.getDump().lower())
								msfchain.append(["raw",thisopcodebytes])
								if isInterestingGadget(fullchain):
									interestinggadgets[startptr] = fullchain
									#this may be a good stackpivot too
									stackpivotdistance = getStackPivotDistance(fullchain,pivotdistance) 
									if stackpivotdistance > 0:
										#safeseh or not ?
										if issafeseh:
											if not stackpivotdistance in stackpivots_safeseh:
												stackpivots_safeseh.setdefault(stackpivotdistance,[[startptr,fullchain]])
											else:
												stackpivots_safeseh[stackpivotdistance] += [[startptr,fullchain]]
										else:
											if not stackpivotdistance in stackpivots:
												stackpivots.setdefault(stackpivotdistance,[[startptr,fullchain]])
											else:
												stackpivots[stackpivotdistance] += [[startptr,fullchain]]								
								else:
									if not fast:
										ropgadgets[startptr] = fullchain
						startptr = startptr+1
						
				else:
					if step == 0:
						startptr = endingtypeptr
					if step == 1:
						thischain = endingtypeptr
						chainptr = startptr
						ptrx = MnPointer(chainptr)
						modname = ptrx.belongsTo()
						issafeseh = False
						if modname != "":
							thism = MnModule(modname)
							issafeseh = thism.isSafeSEH
						if isGoodGadgetPtr(startptr,criteria) and not startptr in ropgadgets and not startptr in interestinggadgets:
							fullchain = thischain
							if isInterestingGadget(fullchain):
								interestinggadgets[startptr] = fullchain
								#this may be a good stackpivot too
								stackpivotdistance = getStackPivotDistance(fullchain,pivotdistance) 
								if stackpivotdistance > 0:
									#safeseh or not ?
									if issafeseh:
										if not stackpivotdistance in stackpivots_safeseh:
											stackpivots_safeseh.setdefault(stackpivotdistance,[[startptr,fullchain]])
										else:
											stackpivots_safeseh[stackpivotdistance] += [[startptr,fullchain]]
									else:
										if not stackpivotdistance in stackpivots:
											stackpivots.setdefault(stackpivotdistance,[[startptr,fullchain]])
										else:
											stackpivots[stackpivotdistance] += [[startptr,fullchain]]	
							else:
								if not fast:
									ropgadgets[startptr] = fullchain
						step = -1
					step += 1
	
	thistimestamp = datetime.datetime.now().strftime("%a %Y/%m/%d %I:%M:%S %p")
	updatetext = "      - Progress update : " + str(tp) + " / " + str(tp) + " items processed (" + thistimestamp + ") - (100%)"
	objprogressfile.write(updatetext.strip(),progressfile)
	dbg.log(updatetext)
	dbg.updateLog()

	if mode == "all":
		if len(ropgadgets) > 0 and len(interestinggadgets) > 0:
			# another round of filtering
			updatetext = "[+] Creating suggestions list"
			dbg.log(updatetext)
			objprogressfile.write(updatetext.strip(),progressfile)
			suggestions = getRopSuggestion(interestinggadgets,ropgadgets)
			#see if we can propose something
			updatetext = "[+] Processing suggestions"
			dbg.log(updatetext)
			objprogressfile.write(updatetext.strip(),progressfile)
			suggtowrite=""
			for suggestedtype in suggestions:
				limitnr = 0x7fffffff
				if suggestedtype.startswith("pop "):		# only write up to 10 pop r32 into suggestions file
					limitnr = 10
				gcnt = 0

				suggtowrite += "[%s]\n" % suggestedtype
				for suggestedpointer in suggestions[suggestedtype]:
					if gcnt < limitnr:
						sptr = MnPointer(suggestedpointer)
						modname = sptr.belongsTo()
						modinfo = MnModule(modname)
						if not modinfo.moduleBase.__class__.__name__ == "instancemethod":
							rva = suggestedpointer - modinfo.moduleBase	
						suggesteddata = suggestions[suggestedtype][suggestedpointer]
						if not modinfo.moduleBase.__class__.__name__ == "instancemethod":
							ptrinfo = "0x" + toHex(suggestedpointer) + " (RVA : 0x" + toHex(rva) + ") : " + suggesteddata + "    ** [" + modname + "] **   |  " + sptr.__str__()+"\n"
						else:
							ptrinfo = "0x" + toHex(suggestedpointer) + " : " + suggesteddata + "    ** [" + modname + "] **   |  " + sptr.__str__()+"\n"
						suggtowrite += ptrinfo
					else:
						break
					gcnt += 1
			dbg.log("[+] Launching ROP generator")
			updatetext = "Attempting to create rop chain proposals"
			objprogressfile.write(updatetext.strip(),progressfile)
			vplogtxt = createRopChains(suggestions,interestinggadgets,ropgadgets,modulecriteria,criteria,objprogressfile,progressfile,technique)
			dbg.logLines(vplogtxt.replace("\t","    "))
			dbg.log("    ROP generator finished")
		else:
			updatetext = "[+] Oops, no gadgets found, aborting.."
			dbg.log(updatetext)
			objprogressfile.write(updatetext.strip(),progressfile)

	#done, write to log files
	dbg.setStatusBar("Writing to logfiles...")
	dbg.log("")
	logfile = MnLog("stackpivot.txt")
	thislog = logfile.reset()	
	objprogressfile.write("Writing " + str(len(stackpivots)+len(stackpivots_safeseh))+" stackpivots with minimum offset " + str(pivotdistance)+" to file " + thislog,progressfile)
	dbg.log("[+] Writing stackpivots to file " + thislog)
	logfile.write("Stack pivots, minimum distance " + str(pivotdistance),thislog)
	logfile.write("-------------------------------------",thislog)
	logfile.write("Non-SafeSEH protected pivots :",thislog)
	logfile.write("------------------------------",thislog)
	arrtowrite = ""	
	pivotcount = 0
	try:
		with open(thislog,"a") as fh:
			arrtowrite = ""
			stackpivots_index = sorted(stackpivots) # returns sorted keys as an array
			for sdist in stackpivots_index:
				for spivot, schain in stackpivots[sdist]:
					ptrx = MnPointer(spivot)
					modname = ptrx.belongsTo()
					sdisthex = "%02x" % sdist
					ptrinfo = "0x" + toHex(spivot) + " : {pivot " + str(sdist) + " / 0x" + sdisthex + "} : " + schain + "    ** [" + modname + "] **   |  " + ptrx.__str__()+"\n"
					pivotcount += 1
					arrtowrite += ptrinfo
			fh.writelines(arrtowrite)
	except:
		pass
	logfile.write("", thislog)
	logfile.write("", thislog)
	logfile.write("SafeSEH protected pivots :",thislog)
	logfile.write("--------------------------",thislog)	
	arrtowrite = ""	
	try:
		with open(thislog, "a") as fh:
			arrtowrite = ""
			stackpivots_safeseh_index = sorted(stackpivots_safeseh)
			for sdist in stackpivots_safeseh_index:
				for spivot, schain in stackpivots_safeseh[sdist]:
					ptrx = MnPointer(spivot)
					modname = ptrx.belongsTo()
					#modinfo = MnModule(modname)
					sdisthex = "%02x" % sdist
					ptrinfo = "0x" + toHex(spivot) + " : {pivot " + str(sdist) + " / 0x" + sdisthex + "} : " + schain + "    ** [" + modname + "] SafeSEH **   |  " + ptrx.__str__()+"\n"
					pivotcount += 1
					arrtowrite += ptrinfo
			fh.writelines(arrtowrite)
	except:
		pass	
	dbg.log("    Wrote %d pivots to file " % pivotcount)
	arrtowrite = ""
	if mode == "all":
		if len(suggestions) > 0:
			logfile = MnLog("rop_suggestions.txt")
			thislog = logfile.reset()
			objprogressfile.write("Writing all suggestions to file "+thislog,progressfile)
			dbg.log("[+] Writing suggestions to file " + thislog )
			logfile.write("Suggestions",thislog)
			logfile.write("-----------",thislog)
			with open(thislog, "a") as fh:
				fh.writelines(suggtowrite)
				fh.write("\n")
			nrsugg = len(suggtowrite.split("\n"))
			dbg.log("    Wrote %d suggestions to file" % nrsugg)

		if not split:
			logfile = MnLog("rop.txt")
			thislog = logfile.reset()
			objprogressfile.write("Gathering interesting gadgets",progressfile)
			dbg.log("[+] Writing results to file " + thislog + " (" + str(len(interestinggadgets))+" interesting gadgets)")
			logfile.write("Interesting gadgets",thislog)
			logfile.write("-------------------",thislog)
			dbg.updateLog()
			try:
				with open(thislog, "a") as fh:
					arrtowrite = ""
					if sortedprint:
						arrptrs = []
						dbg.log("    Sorting interesting gadgets first")
						for gadget in interestinggadgets:
							arrptrs.append(gadget)
						arrptrs.sort()
						dbg.log("    Done sorting, let's go")
						for gadget in arrptrs:
							ptrx = MnPointer(gadget)
							modname = ptrx.belongsTo()
							#modinfo = MnModule(modname)
							ptrinfo = "0x" + toHex(gadget) + " : " + interestinggadgets[gadget] + "    ** [" + modname + "] **   |  " + ptrx.__str__()+"\n"
							arrtowrite += ptrinfo

					else:
						for gadget in interestinggadgets:
							ptrx = MnPointer(gadget)
							modname = ptrx.belongsTo()
							#modinfo = MnModule(modname)
							ptrinfo = "0x" + toHex(gadget) + " : " + interestinggadgets[gadget] + "    ** [" + modname + "] **   |  " + ptrx.__str__()+"\n"
							arrtowrite += ptrinfo
					objprogressfile.write("Writing results to file " + thislog + " (" + str(len(interestinggadgets))+" interesting gadgets)",progressfile)
					fh.writelines(arrtowrite)
				dbg.log("    Wrote %d interesting gadgets to file" % len(interestinggadgets))
			except:
				pass
			arrtowrite=""
			if not fast:
				objprogressfile.write("Enumerating other gadgets (" + str(len(ropgadgets))+")",progressfile)
				dbg.log("[+] Writing other gadgets to file " + thislog + " (" + str(len(ropgadgets))+" gadgets)")
				try:
					logfile.write("",thislog)
					logfile.write("Other gadgets",thislog)
					logfile.write("-------------",thislog)
					with open(thislog, "a") as fh:
						arrtowrite=""
						if sortedprint:
							arrptrs = []
							dbg.log("    Sorting other gadgets too")
							for gadget in ropgadgets:
								arrptrs.append(gadget)
							arrptrs.sort()
							dbg.log("    Done sorting, let's go")
							for gadget in arrptrs:
								ptrx = MnPointer(gadget)
								modname = ptrx.belongsTo()
								#modinfo = MnModule(modname)
								ptrinfo = "0x" + toHex(gadget) + " : " + ropgadgets[gadget] + "    ** [" + modname + "] **   |  " + ptrx.__str__()+"\n"
								arrtowrite += ptrinfo
						else:	
							for gadget in ropgadgets:
								ptrx = MnPointer(gadget)
								modname = ptrx.belongsTo()
								#modinfo = MnModule(modname)
								ptrinfo = "0x" + toHex(gadget) + " : " + ropgadgets[gadget] + "    ** [" + modname + "] **   |  " + ptrx.__str__()+"\n"
								arrtowrite += ptrinfo

						dbg.log("    Wrote %d other gadgets to file" % len(ropgadgets))
						objprogressfile.write("Writing results to file " + thislog + " (" + str(len(ropgadgets))+" other gadgets)",progressfile)
						fh.writelines(arrtowrite)
				except:
					pass
			
		else:
			dbg.log("[+] Writing results to individual files (grouped by module)")
			dbg.updateLog()
			for thismodule in modulestosearch:
				thismodname = thismodule.replace(" ","_")
				thismodversion = getModuleProperty(thismodule,"version")
				logfile = MnLog("rop_"+thismodname+"_"+thismodversion+".txt")
				thislog = logfile.reset()
				logfile.write("Interesting gadgets",thislog)
				logfile.write("-------------------",thislog)
			for gadget in interestinggadgets:
				ptrx = MnPointer(gadget)
				modname = ptrx.belongsTo()
				modinfo = MnModule(modname)
				thismodversion = getModuleProperty(modname,"version")
				thismodname = modname.replace(" ","_")
				logfile = MnLog("rop_"+thismodname+"_"+thismodversion+".txt")
				thislog = logfile.reset(False)
				ptrinfo = "0x" + toHex(gadget) + " : " + interestinggadgets[gadget] + "    ** " + modinfo.__str__() + " **   |  " + ptrx.__str__()+"\n"
				with open(thislog, "a") as fh:
					fh.write(ptrinfo)
			if not fast:
				for thismodule in modulestosearch:
					thismodname = thismodule.replace(" ","_")
					thismodversion = getModuleProperty(thismodule,"version")
					logfile = MnLog("rop_"+thismodname+"_"+thismodversion+".txt")
					logfile.write("Other gadgets",thislog)
					logfile.write("-------------",thislog)
				for gadget in ropgadgets:
					ptrx = MnPointer(gadget)
					modname = ptrx.belongsTo()
					modinfo = MnModule(modname)
					thismodversion = getModuleProperty(modname,"version")
					thismodname = modname.replace(" ","_")
					logfile = MnLog("rop_"+thismodname+"_"+thismodversion+".txt")
					thislog = logfile.reset(False)
					ptrinfo = "0x" + toHex(gadget) + " : " + ropgadgets[gadget] + "    ** " + modinfo.__str__() + " **   |  " + ptrx.__str__()+"\n"
					with open(thislog, "a") as fh:
						fh.write(ptrinfo)
	thistimestamp=datetime.datetime.now().strftime("%a %Y/%m/%d %I:%M:%S %p")
	objprogressfile.write("Done (" + thistimestamp+")",progressfile)
	dbg.log("Done")
	return interestinggadgets,ropgadgets,suggestions,vplogtxt

	

#----- JOP gadget finder ----- #			
def findJOPGADGETS(modulecriteria={},criteria={},depth=6):
	"""
	Searches for jop gadgets

	Arguments:
	modulecriteria - dictionary with criteria modules need to comply with.
	                 Default settings are : ignore aslr and rebased modules
	criteria - dictionary with criteria the pointers need to comply with.
	depth - maximum number of instructions to go back
	
	Return:
	Output is written to files, containing jop gadgets and suggestions
	"""
	found_opcodes = {}
	all_opcodes = {}
	ptr_counter = 0
	
	modulestosearch = getModulesToQuery(modulecriteria)
	
	progressid=toHex(dbg.getDebuggedPid())
	progressfilename="_jop_progress_"+dbg.getDebuggedName()+"_"+progressid+".log"
	
	objprogressfile = MnLog(progressfilename)
	progressfile = objprogressfile.reset()

	dbg.log("[+] Progress will be written to %s" % progressfilename)
	dbg.log("[+] Max nr of instructions : %d" % depth)

	filesok = 0
	usefiles = False
	filestouse = []
	vplogtxt = ""
	suggestions = {}
	fast = False
	
	search = []
	
	jopregs = ["EAX","EBX","ECX","EDX","ESI","EDI","EBP"]
	
	offsetval = 0
	
	for jreg in jopregs:
		search.append("JMP " + jreg)
		search.append("JMP [" + jreg + "]")
		for offsetval in range(0, 40+1, 2):
			search.append("JMP [" + jreg + "+0x" + toHexByte(offsetval)+"]")

	search.append("JMP [ESP]")
		
	for offsetval in range(0, 40+1, 2):
		search.append("JMP [ESP+0x" + toHexByte(offsetval) + "]")
	
	dbg.log("[+] Enumerating %d endings in %d module(s)..." % (len(search),len(modulestosearch)))
	for thismodule in modulestosearch:
		dbg.log("    - Querying module %s" % thismodule)
		dbg.updateLog()
		#search
		found_opcodes = searchInModule(search,thismodule,criteria)
		#merge results
		all_opcodes = mergeOpcodes(all_opcodes,found_opcodes)
	dbg.log("    - Search complete :")
			
	dbg.updateLog()
	tp = 0
	for endingtype in all_opcodes:
		if len(all_opcodes[endingtype]) > 0:
			if usefiles:
				dbg.log("       Ending : %s, Nr found : %d" % (endingtype,len(all_opcodes[endingtype]) / 2))
				tp = tp + len(all_opcodes[endingtype]) / 2
			else:
				dbg.log("       Ending : %s, Nr found : %d" % (endingtype,len(all_opcodes[endingtype])))
				tp = tp + len(all_opcodes[endingtype])
	global silent
	dbg.log("    - Filtering and mutating %d gadgets" % tp)
		
	dbg.updateLog()
	jopgadgets = {}
	interestinggadgets = {}

	adcnt = 0
	tc = 1
	issafeseh = False
	step = 0
	for endingtype in all_opcodes:
		if len(all_opcodes[endingtype]) > 0:
			for endingtypeptr in all_opcodes[endingtype]:
				adcnt += 1
				if usefiles:
					adcnt = adcnt - 0.5
				if adcnt > (tc*1000):
					thistimestamp=datetime.datetime.now().strftime("%a %Y/%m/%d %I:%M:%S %p")
					updatetext = "      - Progress update : " + str(tc*1000) + " / " + str(tp) + " items processed (" + thistimestamp + ") - (" + str((tc*1000*100)/tp)+"%)"
					objprogressfile.write(updatetext.strip(),progressfile)
					dbg.log(updatetext)
					dbg.updateLog()
					tc += 1			
				#first get max backward instruction
				thisopcode = dbg.disasmBackward(endingtypeptr,depth+1)
				thisptr = thisopcode.getAddress()
				# we now have a range to mine
				startptr = thisptr

				while startptr <= endingtypeptr and startptr != 0x0:
					# get the entire chain from startptr to endingtypeptr
					thischain = ""
					msfchain = []
					thisopcodebytes = ""
					chainptr = startptr
					if isGoodGadgetPtr(startptr,criteria) and not startptr in jopgadgets and not startptr in interestinggadgets:
						# new pointer
						invalidinstr = False
						while chainptr < endingtypeptr and not invalidinstr:
							thisopcode = dbg.disasm(chainptr)
							thisinstruction = getDisasmInstruction(thisopcode)
							if isGoodJopGadgetInstr(thisinstruction) and not isGadgetEnding(thisinstruction,search):
								thischain =  thischain + " # " + thisinstruction
								msfchain.append([chainptr,thisinstruction])
								thisopcodebytes = thisopcodebytes + opcodesToHex(thisopcode.getDump().lower())
								chainptr = dbg.disasmForwardAddressOnly(chainptr,1)
							else:
								invalidinstr = True
						if endingtypeptr == chainptr and startptr != chainptr and not invalidinstr:
							fullchain = thischain + " # " + endingtype
							msfchain.append([endingtypeptr,endingtype])
							thisopcode = dbg.disasm(endingtypeptr)
							thisopcodebytes = thisopcodebytes + opcodesToHex(thisopcode.getDump().lower())
							msfchain.append(["raw",thisopcodebytes])
							if isInterestingJopGadget(fullchain):					
								interestinggadgets[startptr] = fullchain
							else:
								if not fast:
									jopgadgets[startptr] = fullchain
					startptr = startptr+1
	
	thistimestamp=datetime.datetime.now().strftime("%a %Y/%m/%d %I:%M:%S %p")
	updatetext = "      - Progress update : " + str(tp) + " / " + str(tp) + " items processed (" + thistimestamp + ") - (100%)"
	objprogressfile.write(updatetext.strip(),progressfile)
	dbg.log(updatetext)
	dbg.updateLog()

	logfile = MnLog("jop.txt")
	thislog = logfile.reset()
	objprogressfile.write("Enumerating gadgets",progressfile)
	dbg.log("[+] Writing results to file " + thislog + " (" + str(len(interestinggadgets))+" interesting gadgets)")
	logfile.write("Interesting gadgets",thislog)
	logfile.write("-------------------",thislog)
	dbg.updateLog()
	arrtowrite = ""
	try:
		with open(thislog, "a") as fh:
			arrtowrite = ""
			for gadget in interestinggadgets:
					ptrx = MnPointer(gadget)
					modname = ptrx.belongsTo()
					modinfo = MnModule(modname)
					ptrinfo = "0x" + toHex(gadget) + " : " + interestinggadgets[gadget] + "    ** " + modinfo.__str__() + " **   |  " + ptrx.__str__()+"\n"
					arrtowrite += ptrinfo
			objprogressfile.write("Writing results to file " + thislog + " (" + str(len(interestinggadgets))+" interesting gadgets)",progressfile)
			fh.writelines(arrtowrite)
	except:
		pass				

	return interestinggadgets,jopgadgets,suggestions,vplogtxt	
	

	#----- File compare ----- #

def findFILECOMPARISON(modulecriteria={},criteria={},allfiles=[],tomatch="",checkstrict=True,rangeval=0,fast=False):
	"""
	Compares two or more files generated with mona.py and lists the entries that have been found in all files

	Arguments:
	modulecriteria =  not used
	criteria = not used
	allfiles = array with filenames to compare
	tomatch = variable containing a string each line should contain
	checkstrict = Boolean, when set to True, both the pointer and the instructions should be exactly the same
	
	Return:
	File containing all matching pointers
	"""
	dbg.setStatusBar("Comparing files...")	
	dbg.updateLog()

	filenotfound = False
	for fcnt in xrange(len(allfiles)):
		fname = allfiles[fcnt]
		fname = fname.strip()
		if os.path.exists(fname):
			dbg.log("     - %d. %s" % (fcnt, allfiles[fcnt]))
		else:
			dbg.log("     ** %s : Does not exist !" % allfiles[fcnt], highlight=1)
			filenotfound = True
	if filenotfound:
		return
	objcomparefile = MnLog("filecompare.txt")
	comparefile = objcomparefile.reset()
	objcomparefilenot = MnLog("filecompare_not.txt")
	comparefilenot = objcomparefilenot.reset()
	objcomparefilenot.write("Source files:",comparefilenot)
	for fcnt in xrange(len(allfiles)):
		objcomparefile.write(" - " + str(fcnt)+". "+allfiles[fcnt],comparefile)
		objcomparefilenot.write(" - " + str(fcnt)+". "+allfiles[fcnt],comparefilenot)
	objcomparefile.write("",comparefile)
	objcomparefile.write("Pointers found :",comparefile)
	objcomparefile.write("----------------",comparefile)
	objcomparefilenot.write("",comparefilenot)
	objcomparefilenot.write("Pointers not found :",comparefilenot)
	objcomparefilenot.write("-------------------",comparefilenot)

	# transform the files into dictionaries
	dbg.log("[+] Reading input files ...")
	all_input_files = {}
	all_pointers = {}
	fcnt = 0
	for thisfile in allfiles:
		filedata = {}
		content = []
		with open(thisfile,"rb") as inputfile:
			content = inputfile.readlines()
		pointerlist = []
		for thisLine in content:
			refpointer,instr = splitToPtrInstr(thisLine)
			instr = instr.replace('\n','').replace('\r','').strip(":")
			if refpointer != -1 and not refpointer in filedata:
				filedata[refpointer] = instr
				pointerlist.append(refpointer)
		all_input_files[fcnt] = filedata
		all_pointers[fcnt] = pointerlist
		fcnt += 1
	# select smallest one
	dbg.log("[+] Finding shortest array, to use as the reference")
	shortestarray = 0
	shortestlen = 0
	for inputfile in all_input_files:
		if (len(all_input_files[inputfile]) < shortestlen) or (shortestlen == 0):
			shortestlen = len(all_input_files[inputfile])
			shortestarray = inputfile
	dbg.log("    Reference file: %s (%d pointers)" % (allfiles[shortestarray],shortestlen))

	fileorder = []
	fileorder.append(shortestarray)
	cnt = 0
	while cnt <= len(all_input_files):
		if not cnt in fileorder:
			fileorder.append(cnt)
		cnt += 1
	remaining = []
	fulllist = []
	if rangeval == 0:
		dbg.log("[+] Starting compare, please wait...")
		dbg.updateLog()		
		fcnt =  1
		remaining = all_pointers[shortestarray]
		fulllist = all_pointers[shortestarray]
		while fcnt < len(fileorder)-1 and len(remaining) > 0:
			dbg.log("    Comparing %d reference pointers with %s" % (len(remaining),allfiles[fileorder[fcnt]]))
			remaining = list(set(remaining).intersection(set(all_pointers[fileorder[fcnt]])))
			fulllist = list(set(fulllist).union(set(all_pointers[fileorder[fcnt]])))
			fcnt += 1
	else:
		dbg.log("[+] Exploding reference list with values within range")
		dbg.updateLog()
		# create first reference list with ALL pointers within the range
		allrefptr = []
		reflist = all_pointers[shortestarray]
		for refptr in reflist:
			start_range = refptr - rangeval
			if start_range < 0:
				start_range = 0
			end_range = refptr + rangeval
			if start_range > end_range:
				tmp = start_range
				start_range = end_range
				end_range = tmp
			while start_range <= end_range:
				if not start_range in allrefptr:
					allrefptr.append(start_range)
				start_range += 1
		# do normal intersection
		dbg.log("[+] Starting compare, please wait...")
		dbg.updateLog()		
		s_remaining = allrefptr
		s_fulllist = allrefptr
		fcnt = 1
		while fcnt < len(fileorder)-1 and len(s_remaining) > 0:
			s_remaining = list(set(s_remaining).intersection(set(all_pointers[fileorder[fcnt]])))
			s_fulllist = list(set(s_fulllist).union(set(all_pointers[fileorder[fcnt]])))
			fcnt += 1
		for s in s_remaining:
			if not s in remaining:
				remaining.append(s)
		for s in s_fulllist:
			if not s in fulllist:
				fulllist.append(s)

	nonmatching = list(set(fulllist) - set(remaining))
	dbg.log("    Total nr of unique pointers : %d" % len(fulllist))
	dbg.log("    Nr of matching pointers before filtering : %d" % len(remaining))
	dbg.log("    Nr of non-matching pointers before filtering : %d" % len(nonmatching))

	dbg.log("[+] Transforming results into output...")
	outputlines = ""
	outputlines_not = ""
	# start building output
	remaining.sort()
	for remptr in remaining:
		if fast:
			outputlines += "0x%08x\n" % remptr
		else:
			thisinstr = all_input_files[shortestarray][remptr]
			include = True
			if checkstrict:
				# check if all entries are the same
				fcnt = 1
				while (fcnt < len(fileorder)-1) and include:
					if thisinstr != all_input_files[fileorder[fcnt]][remptr]:
						include = False
					fcnt += 1
			else:
				include = True
			if include and (tomatch == "" or tomatch in thisinstr):
				outputlines += "0x%08x : %s\n" % (remptr,thisinstr)

	for nonptr in nonmatching:
		if fast:
			outputlines_not += "0x%08x\n" % nonptr
		else:
			thisinstr = ""
			if nonptr in all_input_files[shortestarray]:
				thisinstr = all_input_files[shortestarray][nonptr]
			outputlines_not += "File(%d) 0x%08x : %s\n" % (shortestarray,nonptr,thisinstr)
			for fileindex in all_input_files:
				if fileindex != shortestarray:
					these_entries = all_input_files[fileindex]
					if nonptr in these_entries:
						thisinstr = these_entries[nonptr]
						outputlines_not += "   File (%d). %s\n" % (fileindex,thisinstr)
					else:
						outputlines_not += "   File (%d). Entry not found \n" % fileindex

	dbg.log("[+] Writing output to files")
	objcomparefile.write(outputlines, comparefile)
	objcomparefilenot.write(outputlines_not, comparefilenot)
	nrmatching = len(outputlines.split("\n")) - 1
	dbg.log("    Wrote %d matching pointers to file" % nrmatching)

	dbg.log("[+] Done.")
	return



#------------------#
# Heap state       #
#------------------#

def getCurrentHeapState():
	heapstate = {}
	allheaps = []
	try:
		allheaps = dbg.getHeapsAddress()
	except:
		allheaps = []
	if len(allheaps) > 0:
		for heap in allheaps:
			objHeap = MnHeap(heap)
			thisheapstate = objHeap.getState()
			heapstate[heap] = thisheapstate
	return heapstate

#------------------#
# Cyclic pattern   #
#------------------#	

def createPattern(size,args={}):
	"""
	Create a cyclic (metasploit) pattern of a given size
	
	Arguments:
	size - value indicating desired length of the pattern
	       if value is > 20280, the pattern will repeat itself until it reaches desired length
		   
	Return:
	string containing the cyclic pattern
	"""
	char1="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	char2="abcdefghijklmnopqrstuvwxyz"
	char3="0123456789"

	if "extended" in args:
		char3 += ",.;+=-_!&()#@({})[]%"	# ascii, 'filename' friendly
	
	if "c1" in args and args["c1"] != "":
		char1 = args["c1"]
	if "c2" in args and args["c2"] != "":
		char2 = args["c2"]
	if "c3" in args and args["c3"] != "":
		char3 = args["c3"]
			
	if not silent:
		if not "extended" in args and size > 20280 and (len(char1) <= 26 or len(char2) <= 26 or len(char3) <= 10):
			msg = "** You have asked to create a pattern > 20280 bytes, but with the current settings\n"
			msg += "the pattern generator can't create a pattern of " + str(size) + " bytes. As a result,\n"
			msg += "the pattern will be repeated for " + str(size-20280)+" bytes until it reaches a length of " + str(size) + " bytes.\n"
			msg += "If you want a unique pattern larger than 20280 bytes, please either use the -extended option\n"
			msg += "or extend one of the 3 charsets using options -c1, -c2 and/or -c3 **\n"
			dbg.logLines(msg,highlight=1)
			
	
	pattern = []
	max = int(size)
	while len(pattern) < max:
		for ch1 in char1:
			for ch2 in char2:
				for ch3 in char3:
					if len(pattern) < max:
						pattern.append(ch1)

					if len(pattern) < max:
						pattern.append(ch2)

					if len(pattern) < max:
						pattern.append(ch3)

	pattern = "".join(pattern)
	return pattern

def findOffsetInPattern(searchpat,size=20280,args = {}):
	"""
	Check if a given searchpattern can be found in a cyclic pattern
	
	Arguments:
	searchpat : the ascii value or hexstr to search for
	
	Return:
	entries in the log window, indicating if the pattern was found and at what position
	"""
	mspattern=""


	searchpats = []
	modes = []
	modes.append("normal")
	modes.append("upper")
	modes.append("lower")
	extratext = ""

	patsize=int(size)
	
	if patsize == -1:
		size = 500000
		patsize = size
	
	global silent
	oldsilent=silent
	
	for mode in modes:
		silent=oldsilent		
		if mode == "normal":
			silent=True
			mspattern=createPattern(size,args)
			silent=oldsilent
			extratext = " "
		elif mode == "upper":
			silent=True
			mspattern=createPattern(size,args).upper()
			silent=oldsilent
			extratext = " (uppercase) "
		elif mode == "lower":
			silent=True
			mspattern=createPattern(size,args).lower()
			silent=oldsilent
			extratext = " (lowercase) "
		if len(searchpat)==3:
			#register ?
			searchpat = searchpat.upper()
			regs = dbg.getRegs()		
			if searchpat in regs:
				searchpat = "0x" + toHex(regs[searchpat])
		if len(searchpat)==4:
			ascipat=searchpat
			if not silent:
				dbg.log("Looking for %s in pattern of %d bytes" % (ascipat,patsize))
			if ascipat in mspattern:
				patpos = mspattern.find(ascipat)
				if not silent:
					dbg.log(" - Pattern %s found in cyclic pattern%sat position %d" % (ascipat,extratext,patpos),highlight=1)
			else:
				#reversed ?
				ascipat_r = ascipat[3]+ascipat[2]+ascipat[1]+ascipat[0]
				if ascipat_r in mspattern:
					patpos = mspattern.find(ascipat_r)
					if not silent:
						dbg.log(" - Pattern %s (%s reversed) found in cyclic pattern%sat position %d" % (ascipat_r,ascipat,extratext,patpos),highlight=1)			
				else:
					if not silent:
						dbg.log(" - Pattern %s not found in cyclic pattern%s" % (ascipat_r,extratext))
		if len(searchpat)==8:
				searchpat="0x"+searchpat
		if len(searchpat)==10:
				hexpat=searchpat
				ascipat3 = toAscii(hexpat[8]+hexpat[9])+toAscii(hexpat[6]+hexpat[7])+toAscii(hexpat[4]+hexpat[5])+toAscii(hexpat[2]+hexpat[3])
				if not silent:
					dbg.log("Looking for %s in pattern of %d bytes" % (ascipat3,patsize))
				if ascipat3 in mspattern:
					patpos = mspattern.find(ascipat3)
					if not silent:
						dbg.log(" - Pattern %s (%s) found in cyclic pattern%sat position %d" % (ascipat3,hexpat,extratext,patpos),highlight=1)
				else:
					#maybe it's reversed
					ascipat4=toAscii(hexpat[2]+hexpat[3])+toAscii(hexpat[4]+hexpat[5])+toAscii(hexpat[6]+hexpat[7])+toAscii(hexpat[8]+hexpat[9])
					if not silent:
						dbg.log("Looking for %s in pattern of %d bytes" % (ascipat4,patsize))
					if ascipat4 in mspattern:
						patpos = mspattern.find(ascipat4)
						if not silent:
							dbg.log(" - Pattern %s (%s reversed) found in cyclic pattern%sat position %d" % (ascipat4,hexpat,extratext,patpos),highlight=1)
					else:
						if not silent:
							dbg.log(" - Pattern %s not found in cyclic pattern%s " % (ascipat4,extratext))

							
def findPatternWild(modulecriteria,criteria,pattern,base,top,patterntype):
	"""
	Performs a search for instructions, accepting wildcards
	
	Arguments :
	modulecriteria - dictionary with criteria modules need to comply with.
	criteria - dictionary with criteria the pointers need to comply with.
	pattern - the pattern to search for.
	base - the base address in memory the search should start at
	top - the top address in memory the search should not go beyond
	patterntype - type of search to conduct (str or bin)
	"""
	
	global silent	
	
	rangestosearch = []
	tmpsearch = []
	
	allpointers = {}
	results = {}
	
	mindistance = 4
	maxdistance = 40
	
	if "mindistance" in criteria:
		mindistance = criteria["mindistance"]
	if "maxdistance" in criteria:
		maxdistance = criteria["maxdistance"]
	
	maxdepth = 8
	
	preventbreak = True
	
	if "all" in criteria:
		preventbreak = False
	
	if "depth" in criteria:
		maxdepth = criteria["depth"]
	
	if not silent:
		dbg.log("[+] Type of search: %s" % patterntype)
		dbg.log("[+] Searching for matches up to %d instructions deep" % maxdepth)

	if len(modulecriteria) > 0:
		modulestosearch = getModulesToQuery(modulecriteria)
		# convert modules to ranges
		for modulename in modulestosearch:
			objmod = MnModule(modulename)
			mBase = objmod.moduleBase
			mTop = objmod.moduleTop
			if mBase < base and base < mTop:
				mBase = base
			if mTop > top:
				mTop = top
			if mBase >= base and mBase < top:
				if not [mBase,mTop] in rangestosearch:
					rangestosearch.append([mBase,mTop])
		# if no modules were specified, then also add  the other ranges (outside modules)
		if not "modules" in modulecriteria:
			outside = getRangesOutsideModules()
			for range in outside:
				mBase = range[0]
				mTop = range[1]
				if mBase < base and base < mTop:
					mBase = base
				if mTop > top:
					mTop = top
				if mBase >= base and mBase < top:
					if not [mBase,mTop] in rangestosearch:
						rangestosearch.append([mBase,mTop])
	else:
		rangestosearch.append([base,top])
	
	pattern = pattern.replace("'","").replace('"',"").replace("  "," ").replace(", ",",").replace(" ,",",").replace("# ","#").replace(" #","#")
	if len(pattern) == 0:
		dbg.log("** Invalid search pattern **")
		return
	
	# break apart the instructions
	# search for the first instruction(s)
	allinstructions = pattern.split("#")
	instructionparts = []
	instrfound = False
	for instruction in allinstructions:
		instruction = instruction.strip().lower()
		if instrfound and instruction != "":
			instructionparts.append(instruction)
		else:
			if instruction != "*" and instruction != "":
				instructionparts.append(instruction)
				instrfound = True
				
	# remove wildcards placed at the end
	for i in rrange(len(instructionparts)):
		if instructionparts[i] == "*":
			instructionparts.pop(i)
		else:
			break

	# glue simple instructions together if possible
	# reset array
	allinstructions = []
	stopnow = False
	mergeinstructions = []
	mergestopped = False
	mergetxt = ""
	for instr in instructionparts:
		if instr.find("*") == -1 and instr.find("r32") == -1 and not mergestopped:
			mergetxt += instr + "\n"
		else:
			allinstructions.append(instr)
			mergestopped = True
	mergetxt = mergetxt.strip("\n")

	searchPattern = []
	remaining = allinstructions

	if mergetxt != "":
		searchPattern.append(mergetxt)
	else:
		# at this point, we're sure the first instruction has some kind of r32 and/or offset variable
		# get all of the combinations for this one
		# and use them as searchPattern
		cnt = 0
		stopped = False		
		for instr in allinstructions:
			if instr != "*" and (instr.find("r32") > -1 or instr.find("*") > -1) and not stopped:
				if instr.find("r32") > -1:
					for reg in dbglib.Registers32BitsOrder:
						thisinstr = instr.replace("r32",reg.lower())
						if instr.find("*") > -1:
							# contains a wildcard offset
							startdist = mindistance
							while startdist < maxdistance:
								operator = ""
								if startdist < 0:
									operator = "-"
								replacewith = operator + "0x%02x" % startdist
								thisinstr2 = thisinstr.replace("*",replacewith)
								searchPattern.append(thisinstr2)
								startdist += 1
						else:
							searchPattern.append(thisinstr)
				else:
					# no r32
					if instr.find("*") > -1:
						# contains a wildcard offset
						startdist = mindistance
						while startdist < maxdistance:
							operator = ""
							if startdist < 0:
								operator = "-"
							replacewith = operator + "0x%02x" % startdist
							thisinstr2 = instr.replace("*",replacewith)
							searchPattern.append(thisinstr2)
							startdist += 1
					else:
						searchPattern.append(instr)
				remaining.pop(cnt)
				stopped = True
			cnt += 1
		
	# search for all these beginnings
	if len(searchPattern) > 0:
		if not silent:
			dbg.log("[+] Started search (%d start patterns)" % len(searchPattern))
		dbg.updateLog()
		for ranges in rangestosearch:
			mBase = ranges[0]
			mTop = ranges[1]
			if not silent:
				dbg.log("[+] Searching startpattern between 0x%s and 0x%s" % (toHex(mBase),toHex(mTop)))
			dbg.updateLog()
			oldsilent=silent
			silent=True
			pointers = searchInRange(searchPattern,mBase,mTop,criteria)
			silent=oldsilent
			allpointers = mergeOpcodes(allpointers,pointers)	
	
	# for each of the findings, see if it contains the other instructions too
	# disassemble forward up to 'maxdepth' instructions

	for ptrtypes in allpointers:
		for ptrs in allpointers[ptrtypes]:
			thisline = ""
			try:
				for depth in xrange(maxdepth):
					tinstr = getDisasmInstruction(dbg.disasmForward(ptrs, depth)).lower() + "\n"
					if tinstr != "???":
						thisline += tinstr
					else:
						thisline = ""
						break	
			except:
				continue
			allfound = True
			thisline = thisline.strip("\n")
			
			if thisline != "":
				parts = thisline.split("\n")
				maxparts = len(parts)-1
				partcnt = 1
				searchfor = ""
				remcnt = 0
				lastpos = 0
				remmax = len(remaining)
				while remcnt < remmax:
				
					searchfor = remaining[remcnt]
						
					searchlist = []
					if searchfor == "*":
						while searchfor == "*" and remcnt < remmax:
							searchfor = remaining[remcnt+1]
							rangemin = partcnt
							rangemax = maxparts
							remcnt += 1

					else:
						rangemin = partcnt
						rangemax = partcnt
						
					if searchfor.find("r32") > -1:
						for reg in dbglib.Registers32BitsOrder:
							searchlist.append(searchfor.replace("r32",reg.lower()))	
					else:
						searchlist.append(searchfor)
						
					partfound = False
					
					while rangemin <= rangemax and not partfound and rangemax <= maxparts:
						for searchfor in searchlist:
							if parts[rangemin].find(searchfor) > -1:						
								partfound = True
								lastpos = rangemin
								partcnt = lastpos # set counter to current position
								break
						if not partfound and preventbreak:
							#check if current instruction would break chain
							if wouldBreakChain(parts[rangemin]):
								# bail out
								partfound = False
								break
						rangemin += 1
						
					remcnt += 1
					partcnt += 1					
					
					if not partfound:
						allfound = False
						break

					
			if allfound:
				theline = " # ".join(parts[:lastpos+1])
				if theline != "":
					if not theline in results:
						results[theline] = [ptrs]
					else:
						results[theline] += [ptrs]
	return results

	
def wouldBreakChain(instruction):
	"""
	Checks if the given instruction would potentially break the instruction chain
	Argument :
	instruction:  the instruction to check
	
	Returns :
	boolean 
	"""
	goodinstruction = isGoodGadgetInstr(instruction)
	if goodinstruction:
		return False
	return True


def findPattern(modulecriteria,criteria,pattern,ptype,base,top,consecutive=False,rangep2p=0,level=0,poffset=0,poffsetlevel=0):
	"""
	Performs a find in memory for a given pattern
	
	Arguments:
	modulecriteria - dictionary with criteria modules need to comply with.
	criteria - dictionary with criteria the pointers need to comply with.
				One of the criteria can be "p2p", indicating that the search should look for
				pointers to pointers to the pattern
	pattern - the pattern to search for.
	ptype - the type of the pattern, can be 'asc', 'bin', 'ptr', 'instr' or 'file'
		If no type is specified, the routine will try to 'guess' the types
		when type is set to file, it won't actually search in memory for pattern, but it will
		read all pointers from that file and search for pointers to those pointers
		(so basically, type 'file' is only useful in combination with -p2p)
	base - the base address in memory the search should start at
	top - the top address in memory the search should not go beyond
	consecutive - Boolean, indicating if consecutive pointers should be skipped
	rangep2p - if not set to 0, the pointer to pointer search will also look rangep2p bytes back for each pointer,
			thus allowing you to find close pointer to pointers
	poffset - only used when doing p2p, will add offset to found pointer address before looking to ptr to ptr
	poffsetlevel - apply the offset at this level of the chain
	level - number of levels deep to look for ptr to ptr. level 0 is default, which means search for pointer to searchpattern
	
	Return:
	all pointers (or pointers to pointers) to the given search pattern in memory
	"""

	wildcardsearch = False
	rangestosearch = []
	tmpsearch = []
	p2prangestosearch = []
	global silent	
	if len(modulecriteria) > 0:
		modulestosearch = getModulesToQuery(modulecriteria)
		# convert modules to ranges
		for modulename in modulestosearch:
			objmod = MnModule(modulename)
			mBase = objmod.moduleBase
			mTop = objmod.moduleTop
			if mBase < base and base < mTop:
				mBase = base
			if mTop > top:
				mTop = top
			if mBase >= base and mBase < top:
				if not [mBase,mTop] in rangestosearch:
					rangestosearch.append([mBase,mTop])
		# if no modules were specified, then also add  the other ranges (outside modules)
		if not "modules" in modulecriteria:
			outside = getRangesOutsideModules()
			for range in outside:
				mBase = range[0]
				mTop = range[1]
				if mBase < base and base < mTop:
					mBase = base
				if mTop > top:
					mTop = top
				if mBase >= base and mBase < top:
					if not [mBase,mTop] in rangestosearch:
						rangestosearch.append([mBase,mTop])
	else:
		rangestosearch.append([base,top])
	
	tmpsearch.append([0,TOP_USERLAND])
	
	allpointers = {}
	originalPattern = pattern
	
	# guess the type if it is not specified
	if ptype == "":
		if len(pattern) > 2 and pattern[0:2].lower() == "0x":
			ptype = "ptr"
		elif "\\x" in pattern:
			ptype = "bin"
		else:
			ptype = "asc"

	if ptype == "bin" and ".." in pattern:
		wildcardsearch = True
		if not silent:
			dbg.log("    - Wildcard \\x.. detected")
			
	if "unic" in criteria and ptype == "asc":
		ptype = "bin"
		binpat = ""
		pattern = pattern.replace('"',"")
		for thischar in pattern:
			binpat += "\\x" + str(toHexByte(ord(thischar))) + "\\x00"
		pattern = binpat
		originalPattern += " (unicode)"
		if not silent:
			dbg.log("    - Expanded ascii pattern to unicode, switched search mode to bin")

	bytes = ""
	patternfilename = ""
	split1 = re.compile(' ')		
	split2 = re.compile(':')
	split3 = re.compile("\*")		
	
	if not silent:
		dbg.log("    - Treating search pattern as %s" % ptype)
		
	if ptype == "ptr":
		pattern = pattern.replace("0x","")
		value = int(pattern,16)
		bytes = struct.pack('<I',value)
	elif ptype == "bin":
		if len(pattern) % 2 != 0:
			dbg.log("Invalid hex pattern", highlight=1)
			return
		if not wildcardsearch:
			bytes = hex2bin(pattern)
		else:
			# check if first byte is a byte and not a wildcard
			if len(pattern) > 3 and pattern[2:4] == "..":
				dbg.log(" *** Can't start a wildcard search with a wildcard. Specify a byte instead ***",highlight =1)
				return
			else:
				# search for the first byte and then check wildcards later
				foundstartbytes = False
				sindex = 0
				while not foundstartbytes:
					b = pattern[sindex:sindex+4]
					if not ".." in b:
						bytes += hex2bin(pattern[sindex:sindex+4])
					else:
						foundstartbytes = True
					sindex += 4

	elif ptype == "asc":
		if pattern.startswith('"') and pattern.endswith('"'):
			pattern = pattern.replace('"',"")
		elif pattern.startswith("'") and pattern.endswith("'"):
			pattern = pattern.replace("'","")
		bytes = pattern
	elif ptype == "instr":
		pattern = pattern.replace("'","").replace('"',"").replace("  "," ").replace(", ",",").replace(" #","#").replace("# ","#")
		silent = True
		bytes = hex2bin(assemble(pattern,""))
		silent = False
		if bytes == "":
			dbg.log("Invalid instruction - could not assemble %s" % pattern,highlight=1)
			return
	elif ptype == "file":
		patternfilename = pattern.replace("'","").replace('"',"")
		dbg.log("    - Search patterns = all pointers in file %s" % patternfilename)
		dbg.log("      Extracting pointers...")
		FILE=open(patternfilename,"r")
		contents = FILE.readlines()
		FILE.close()
		extracted = 0	
		for thisLine in contents:
			if thisLine.lower().startswith("0x"):
				lineparts=split1.split(thisLine)
				thispointer = lineparts[0]
				#get type  = from : to *
				if len(lineparts) > 1:
					subparts = split2.split(thisLine)
					if len(subparts) > 1:
						if subparts[1] != "":
							subsubparts = split3.split(subparts[1])
							if not subsubparts[0] in allpointers:
								allpointers[subsubparts[0]] = [hexStrToInt(thispointer)]
							else:
								allpointers[subsubparts[0]] += [hexStrToInt(thispointer)]
							extracted += 1
		dbg.log("      %d pointers extracted." % extracted)							
	dbg.updateLog()
	
	fakeptrcriteria = {}
	
	fakeptrcriteria["accesslevel"] = "*"
	
	if "p2p" in criteria or level > 0:
		#save range for later, search in all of userland for now
		p2prangestosearch = rangestosearch
		rangestosearch = tmpsearch
	
	if ptype != "file":
		for ranges in rangestosearch:
			mBase = ranges[0]
			mTop = ranges[1]
			if not silent:
				dbg.log("[+] Searching from 0x%s to 0x%s" % (toHex(mBase),toHex(mTop)))
			dbg.updateLog()
			searchPattern = []
			searchPattern.append([originalPattern, bytes])
			oldsilent=silent
			silent=True
			pointers = searchInRange(searchPattern,mBase,mTop,criteria)
			silent=oldsilent
			allpointers = mergeOpcodes(allpointers,pointers)
	
	# filter out bad ones if wildcardsearch is enabled
	if wildcardsearch and ptype == "bin":
		nrbytes = ( len(pattern) / 4) - len(bytes)
		if nrbytes > 0:
			maskpart = pattern[len(bytes)*4:]
			tocomparewith_tmp = maskpart.split("\\x")
			tocomparewith = []
			for tcw in tocomparewith_tmp:
				if len(tcw) == 2:
					tocomparewith.append(tcw)
			dbg.log("[+] Applying wildcard mask, %d remaining bytes: %s" % (nrbytes,maskpart))
			remptrs = {} 
			for ptrtype in allpointers:
				for ptr in allpointers[ptrtype]:
					rfrom = ptr + len(bytes)
					bytesatlocation = dbg.readMemory(rfrom,nrbytes)
					#dbg.log("Read %d bytes from 0x%08x" % (len(bytesatlocation),rfrom))
					compareindex = 0
					wildcardmatch = True
					for thisbyte in bytesatlocation:
						thisbytestr = bin2hexstr(thisbyte).replace("\\x","")
						thisbytecompare = tocomparewith[compareindex]
						if thisbytecompare != ".." and thisbytestr.lower() != thisbytecompare.lower():
							wildcardmatch=False
							break
						compareindex += 1
					if wildcardmatch:
						if not ptrtype in remptrs:
							remptrs[ptrtype] = [ptr]
						else:
							remptrs[ptrtype].append(ptr)

			allpointers = remptrs

	if ptype == "file" and level == 0:
		level = 1
		
	if consecutive:
		# get all pointers and sort them
		rawptr = {}
		for ptrtype in allpointers:
			for ptr in allpointers[ptrtype]:
				if not ptr in rawptr:
					rawptr[ptr]=ptrtype
		if not silent:
			dbg.log("[+] Number of pointers to process : %d" % len(rawptr))
		sortedptr = rawptr.items()
		sortedptr.sort(key = itemgetter(0))
		#skip consecutive ones and increment size
		consec_delta = len(bytes)
		previousptr = 0
		savedptr = 0
		consec_size = 0
		allpointers = {}
		for ptr,ptrinfo in sortedptr:
			if previousptr == 0:
				previousptr = ptr
				savedptr = ptr
			if previousptr != ptr:
				if ptr <= (previousptr + consec_delta):
					previousptr = ptr
				else:
					key = ptrinfo + " ("+ str(previousptr+consec_delta-savedptr) + ")"
					if not key in allpointers:
						allpointers[key] = [savedptr]
					else:
						allpointers[key] += [savedptr]
					previousptr = ptr
					savedptr = ptr

	#recursive search ? 
	if len(allpointers) > 0:
		remainingpointers = allpointers
		if level > 0:
			thislevel = 1
			while thislevel <= level:
				if not silent:
					pcnt = 0
					for ptype,ptrs in remainingpointers.iteritems():
						for ptr in ptrs:					
							pcnt += 1
					dbg.log("[+] %d remaining types found at this level, total of %d pointers" % (len(remainingpointers),pcnt))				
				dbg.log("[+] Looking for pointers to pointers, level %d..." % thislevel)
				poffsettxt = ""
				if	thislevel == poffsetlevel:
					dbg.log("    I will apply offset %d (decimal) to discovered pointers to pointers..." % poffset)
					poffsettxt = "%d(%xh)" % (poffset,poffset)
				dbg.updateLog()
				searchPattern = []
				foundpointers = {}
				for ptype,ptrs in remainingpointers.iteritems():
					for ptr in ptrs:
						cnt = 0
						#if thislevel == poffsetlevel:
						#	ptr = ptr + poffset
						while cnt <= rangep2p:
							bytes = struct.pack('<I',ptr-cnt)
							if ptype == "file":
								originalPattern = ptype
							if cnt == 0:
								searchPattern.append(["ptr" + poffsettxt + " to 0x" + toHex(ptr) +" (-> ptr to " + originalPattern + ") ** ", bytes])
							else:
								searchPattern.append(["ptr" + poffsettxt + " to 0x" + toHex(ptr-cnt) +" (-> close ptr to " + originalPattern + ") ** ", bytes])	
							cnt += 1
							#only apply rangep2p in level 1
							if thislevel == 1:
								rangep2p = 0
				remainingpointers = {}
				for ranges in p2prangestosearch:
					mBase = ranges[0]
					mTop = ranges[1]
					if not silent:
						dbg.log("[+] Searching from 0x%s to 0x%s" % (toHex(mBase),toHex(mTop)))
					dbg.updateLog()
					oldsilent = silent
					silent=True
					pointers = searchInRange(searchPattern,mBase,mTop,fakeptrcriteria)
					silent=oldsilent
					for ptrtype in pointers:
						if not ptrtype in remainingpointers:
							if poffsetlevel == thislevel:
								# fixup found pointers, apply offset now
								ptrlist = []
								for thisptr in pointers[ptrtype]:
									thisptr = thisptr + poffset
									ptrlist.append(thisptr)
								pointers[ptrtype] = ptrlist
							remainingpointers[ptrtype] = pointers[ptrtype]
				thislevel += 1
				if len(remainingpointers) == 0:
					if not silent:
						dbg.log("[+] No more pointers left, giving up...", highlight=1)
						break
		allpointers = remainingpointers

	return allpointers
		

# def compareFileWithMemory(filename,startpos,skipmodules=False,findunicode=False):
# 	dbg.log("[+] Reading file %s..." % filename)
# 	srcdata_normal=[]
# 	srcdata_unicode=[]
# 	tagresults=[]
# 	criteria = {}
# 	criteria["accesslevel"] = "*"
# 	try:
# 		srcfile = open(filename,"rb")
# 		content = srcfile.readlines()
# 		srcfile.close()
# 		for eachLine in content:
# 			srcdata_normal += eachLine
# 		for eachByte in srcdata_normal:
# 			eachByte+=struct.pack('B', 0)
# 			srcdata_unicode += eachByte
# 		dbg.log("    Read %d bytes from file" % len(srcdata_normal))
# 	except:
# 		dbg.log("Error while reading file %s" % filename, highlight=1)
# 		return
# 	# loop normal and unicode
# 	comparetable=dbg.createTable('mona Memory comparison results',['Address','Status','BadChars','Type','Location'])	
# 	modes = ["normal", "unicode"]
# 	if not findunicode:
# 		modes.remove("unicode")
# 	objlogfile = MnLog("compare.txt")
# 	logfile = objlogfile.reset()
# 	for mode in modes:
# 		if mode == "normal":
# 			srcdata = srcdata_normal
# 		if mode == "unicode":
# 			srcdata = srcdata_unicode
# 		maxcnt = len(srcdata)
# 		if maxcnt < 8:
# 			dbg.log("Error - file does not contain enough bytes (min 8 bytes needed)",highlight=1)
# 			return
# 		locations = []
# 		if startpos == 0:
# 			dbg.log("[+] Locating all copies in memory (%s)" % mode)
# 			btcnt = 0
# 			cnt = 0
# 			linecount = 0
# 			hexstr = ""
# 			hexbytes = ""
# 			for eachByte in srcdata:
# 				if cnt < 8:
# 					hexbytes += eachByte
# 					if len((hex(ord(srcdata[cnt]))).replace('0x',''))==1:
# 						hexchar=hex(ord(srcdata[cnt])).replace('0x', '\\x0')
# 					else:
# 						hexchar = hex(ord(srcdata[cnt])).replace('0x', '\\x')
# 					hexstr += hexchar					
# 				cnt += 1
# 			dbg.log("    - searching for "+hexstr)
# 			global silent
# 			silent = True
# 			results = findPattern({},criteria,hexstr,"bin",0,TOP_USERLAND,False)

# 			for type in results:
# 				for ptr in results[type]:
# 					ptrinfo = MnPointer(ptr).memLocation()
# 					if not skipmodules or (skipmodules and (ptrinfo in ["Heap","Stack","??"])):
# 						locations.append(ptr)
# 			if len(locations) == 0:
# 				dbg.log("      Oops, no copies found")
# 		else:
# 			startpos_fixed = startpos
# 			locations.append(startpos_fixed)
# 		if len(locations) > 0:
# 			dbg.log("    - Comparing %d location(s)" % (len(locations)))
# 			dbg.log("Comparing bytes from file with memory :")
# 			for location in locations:
# 				memcompare(location,srcdata,comparetable,mode, smart=(mode == 'normal'))
# 		silent = False
# 	return

def compareFormattedFileWithMemory(filename,format,startpos,skipmodules=False,findunicode=False):

	isDebug=False

	def out(x): 
		dbg.log(x)
			
	def ok(x): dbg.log("[+] " + x) 
	def verbose(x):
		if isDebug:
			dbg.log("[dbg] " + x)

	def warn(x): dbg.log("[?] " + x, highlight=1)
	def err(x): dbg.log(x, highlight=1)

	#Class ported from https://github.com/mgeeky/expdevBadChars, author: mgeeky, Mariusz B.
	#Ported by: onlylonly, Z.Y Liew
	class BytesParser():
		formats_rex = {
			'xxd': r'^[^0-9a-f]*[0-9a-f]{2,}\:\s((?:[0-9a-f]{4}\s)+)\s+.+$',
			'hexdump': r'^[^0-9a-f]*[0-9a-f]{2,}\s+([0-9a-f\s]+[0-9a-f])$',
			'classic-hexdump':r'^[0-9a-f]*[0-9a-f]{2,}(?:\:|\s)+\s([0-9a-f\s]+)\s{2,}.+$',
			'hexdump-C': r'^[0-9a-f]*[0-9a-f]{2,}\s+\s([0-9a-f\s]+)\s*\|', 
			'escaped-hexes': r'^[^\'"]*((?:\'[\\\\x0-9a-f]{8,}\')|(?:"[\\\\x0-9a-f]{8,}"))',
			'hexstring': r'^([0-9a-f]+)$',
			'msfvenom-powershell': r'^[^0x]+((?:0x[0-9a-f]{1,2},?)+)$',
			'byte-array': r'^[^0x]*((?:0x[0-9a-f]{2}(?:,\s?))+)',
			'js-unicode': r'^[^%u0-9a-f]*((?:%u[0-9a-f]{4})+)$',
			'dword': r'^(?:((?:0x[0-9a-f]{1,8}\s[<>\w\+]+)|(?:0x[0-9a-f]{1,8})):\s*)?((?:0x[0-9a-f]{8},?\s*)+)$',
		}
		formats_aliases = {
			'classic-hexdump': ['ollydbg'],
			'escaped-hexes': ['msfvenom-ruby','msfvenom-c', 'msfvenom-carray', 'msfvenom-python'],
			'dword': ['gdb']
		}
		formats_compiled = {}

		def __init__(self, input, name = None, format = None):
			#convert list to string
			self.input = ''.join(input)
			self.name = name
			self.bytes = []
			self.parsed = False
			self.format = None

			BytesParser.compile_regexps()


			if format:
				verbose("Using user-specified format: %s" % format)
	
				try:
					self.format = BytesParser.interpret_format_name(format)
				except Exception as e:
					verbose(str(e))

				#exit when user-specified format not in both formats_rex and formats_aliases 
				assert (format in BytesParser.formats_rex.keys() or self.format is not None), \
						"Format '%s' is not implemented." % format
						
				if self.format is None:
					self.format = format

			else:
				self.recognize_format()

			#do not normalize input on raw format to prevent input tempering
			if str(self.format).lower() != "raw":
				self.normalize_input()

			if not self.format:
				self.parsed = False
			else:
				if self.fetch_bytes():
					ok("Fetched %d bytes successfully from %s" % (len(self.bytes), self.name))
					self.parsed = True
				else:
					if format and len(format):
						err("Could not parse %s with user-specified format: %s" % (self.name, format))
					else:
						err("Recognized input %s as formatted with %s but failed fetching bytes." %
							(self.name, self.format))

		def normalize_input(self):
			input = []
			for line in self.input.split('\n'):
				line = line.strip()
				line2 = line.encode('string-escape')
				input.append(line2)
			self.input = '\n'.join(input)

		@staticmethod
		def interpret_format_name(name):
			if str(format).lower() == "raw":
				return "raw"

			for k, v in BytesParser.formats_aliases.items():
				if name.lower() in v:
					return k
			raise Exception("Format name: %s not recognized as alias." % name)

		@staticmethod
		def compile_regexps():
			if len(BytesParser.formats_compiled) == 0:
				for name, rex in BytesParser.formats_rex.items():
					BytesParser.formats_compiled[name] = re.compile(rex, re.I)

		@staticmethod
		def make_line_printable(line):
			return ''.join([c if c in string.printable else '.' for c in line])

		def recognize_format(self):
			for line in self.input.split('\n'):
				if self.format: break
				for format, rex in BytesParser.formats_compiled.items():
					line = BytesParser.make_line_printable(line)

					verbose("Trying format %s on ('%s')" % (format, line))
					
					if rex.match(line):
						ok("%s has been recognized as %s formatted." % (self.name, format))
						self.format = format
						break

			if not self.format:
				if not all(c in string.printable for c in self.input):
					ok("%s has been recognized as RAW bytes." % (self.name))
					self.format = 'raw'
					return True
				else:
					err("Could not recognize input bytes format of the %s!" % self.name)
					return False


			return (len(self.format) > 0)

		@staticmethod
		def post_process_bytes_line(line):
			outb = []
			l = line.strip()[:]
			strip = ['0x', ',', ' ', '\\', 'x', '%u', '+', '.', "'", '"']
			for s in strip:
				l = l.replace(s, '')

			for i in xrange(0, len(l), 2):
				outb.append(int(l[i:i+2], 16))
			return outb

		@staticmethod
		def preprocess_bytes_line(line):
			l = line.strip()[:]
			strip = ['(byte)', '+', '.']
			for s in strip:
				l = l.replace(s, '')
			return l

		@staticmethod
		def unpack_dword(line):
			outs = ''
			i = 0

			for m in re.finditer(r'((?:0x[0-9a-f]{8}(?!:),?\s*))', line):
				l = m.group(0)
				l = l.replace(',', '')
				l = l.replace(' ', '')
				dword = int(l, 16)
				unpack = reversed([
					(dword & 0xff000000) >> 24,
					(dword & 0x00ff0000) >> 16,
					(dword & 0x0000ff00) >>  8,
					(dword & 0x000000ff)
				])
				i += 4
				for b in unpack:
					outs += '%02x' % b

			verbose("After callback ('%s')" % outs)
			return BytesParser.formats_compiled['hexstring'].match(outs)

		def fetch_bytes(self):
			if not self.format:
				err("fetch_bytes(): Format has not been specified!")
				return False

			if self.format == 'raw':
				verbose("Parsing %s as raw bytes." % self.name)
				self.bytes = [ord(c) for c in list(self.input)]
				return len(self.bytes) > 0
			
			for line in self.input.split('\n'):
				callback_called = False
				if self.format in BytesParser.formats_callbacks.keys() and \
						BytesParser.formats_callbacks[self.format]:
					verbose("Before callback ('%s')" % line)
					m = BytesParser.formats_callbacks[self.format].__func__(line)
					callback_called = True
				else:
					line = BytesParser.preprocess_bytes_line(line[:])
					m = BytesParser.formats_compiled[self.format].match(line)

				if m:
					extract = ''
					for mg in m.groups()[0:]:
						if len(mg) > 0:
							extract = mg
					bytes = BytesParser.post_process_bytes_line(extract)
					if not bytes:
						err("Could not process %s bytes line ('%s') as %s formatted! Quitting." \
								% (self.name, line, self.format))
					else:
						verbose("Line ('%s'), bytes ('%s'), extracted ('%s'), len: %d" % (line, extract, bytes, len(bytes)))
						self.bytes.extend(bytes)
				else:
					if callback_called:
						verbose("Callback failure: transformed string ('%s') did not catched on returned match" % (line))
					else:
						verbose("Parsing line ('%s') failed with format '%s'." % (line, self.format))

			return len(self.bytes) > 0

		@staticmethod
		def get_available_format():
			#check is input format valid?
			avail_formats = ['raw',]
			avail_formats.extend(BytesParser.formats_rex.keys())
			for k, v in BytesParser.formats_aliases.items():
				avail_formats.extend(v)

			formats = ', '.join(["'"+x+"'" for x in avail_formats]) #list all available formats
			return formats

		@staticmethod
		def is_valid_format(format):
			avail_formats = BytesParser.get_available_format()
			return format in avail_formats		

		def get_bytes(self):
			return self.bytes

		formats_callbacks = {
			'dword': unpack_dword
		}

	########## END Class : BytesParser

	dbg.log("[+] Reading file %s..." % filename)
	srcdata_normal=[]
	srcdata_unicode=[]
	tagresults=[]
	criteria = {}
	criteria["accesslevel"] = "*"
	try:
		srcfile = open(filename,"rb")
		content = srcfile.readlines()
		srcfile.close()
		for eachLine in content:
			srcdata_normal += eachLine
		for eachByte in srcdata_normal:
			eachByte+=struct.pack('B', 0)
			srcdata_unicode += eachByte
		dbg.log("    Read %d bytes from file" % len(srcdata_normal))
	except:
		dbg.log("Error while reading file %s" % filename, highlight=1)
		return
	# loop normal and unicode
	comparetable=dbg.createTable('mona Memory comparison results',['Address','Status','BadChars','Type','Location'])	
	modes = ["normal", "unicode"]
	if not findunicode:
		modes.remove("unicode")
	objlogfile = MnLog("compare.txt")
	logfile = objlogfile.reset()
	for mode in modes:
		if mode == "normal":
			srcdata = srcdata_normal
		if mode == "unicode":
			srcdata = srcdata_unicode

		#check is user supplied input is valid input
		if format and not BytesParser.is_valid_format(format):
			err("Format that was specified is not recognized.")
			err("Valid formats: %s" % BytesParser.get_available_format())		

		#parse input file
		b = BytesParser(srcdata, filename, format)
		if not b.parsed:
			return False
		else:
			srcdata = b.get_bytes()

		#convert bytes array(from BytesParser) to string array
		#mona expect input as string array 
		bytetostr = []
		for eachByte in srcdata:
			bytetostr += chr(eachByte)
		srcdata = bytetostr
		
		maxcnt = len(srcdata)
		if maxcnt < 8:
			dbg.log("Error - file does not contain enough bytes (min 8 bytes needed)",highlight=1)
			return
		locations = []
		if startpos == 0:
			dbg.log("[+] Locating all copies in memory (%s)" % mode)
			btcnt = 0
			cnt = 0
			linecount = 0
			hexstr = ""
			hexbytes = ""
			for eachByte in srcdata:
				if cnt < 8:
					hexbytes += eachByte
					if len((hex(ord(srcdata[cnt]))).replace('0x',''))==1:
						hexchar=hex(ord(srcdata[cnt])).replace('0x', '\\x0')
					else:
						hexchar = hex(ord(srcdata[cnt])).replace('0x', '\\x')
					hexstr += hexchar					
				cnt += 1
			dbg.log("    - searching for "+hexstr)
			global silent
			silent = True
			results = findPattern({},criteria,hexstr,"bin",0,TOP_USERLAND,False)

			for _type in results:
				for ptr in results[_type]:
					ptrinfo = MnPointer(ptr).memLocation()
					if not skipmodules or (skipmodules and (ptrinfo in ["Heap","Stack","??"])):
						locations.append(ptr)
			if len(locations) == 0:
				dbg.log("      Oops, no copies found")
		else:
			startpos_fixed = startpos
			locations.append(startpos_fixed)
		if len(locations) > 0:
			dbg.log("    - Comparing %d location(s)" % (len(locations)))
			dbg.log("Comparing bytes from file with memory :")
			for location in locations:
				memcompare(location,srcdata,comparetable,mode, smart=(mode == 'normal'))
		silent = False
	return


def memoized(func):
	''' A function decorator to make a function cache it's return values.
	If a function returns a generator, it's transformed into a list and
	cached that way. '''
	cache = {}
	def wrapper(*args):
		if args in cache:
			return cache[args]
		import time; start = time.time()
		val = func(*args)
		if isinstance(val, types.GeneratorType):
			val = list(val)
		cache[args] = val
		return val
	wrapper.__doc__ = func.__doc__
	wrapper.func_name = '%s_memoized' % func.func_name
	return wrapper

class MemoryComparator(object):
	''' Solve the memory comparison problem with a special dynamic programming
	algorithm similar to that for the LCS problem '''

	Chunk = namedtuple('Chunk', 'unmodified i j dx dy xchunk ychunk')

	move_to_gradient = {
			0: (0, 0),
			1: (0, 1),
			2: (1, 1),
			3: (2, 1),
			}

	def __init__(self, x, y):
		self.x, self.y = x, y

	@memoized
	def get_last_unmodified_chunk(self):
		''' Returns the index of the last chunk of size > 1 that is unmodified '''
		try:
			return max(i for i, c in enumerate(self.get_chunks()) if c.unmodified and c.dx > 1)
		except:
			# no match
			return -1

	@memoized
	def get_grid(self):
		''' Builds a 2-d suffix grid for our DP algorithm. '''
		x = self.x
		y = self.y[:len(x)*2]
		width, height  = len(x), len(y)
		values = [[0] * (width + 1) for j in range(height + 1)]
		moves  = [[0] * (width + 1) for j in range(height + 1)]
		equal  = [[x[i] == y[j] for i in range(width)] for j in range(height)]
		equal.append([False] * width)

		for j, i in itertools.product(rrange(height + 1), rrange(width + 1)):
			value = values[j][i]
			if i >= 1 and j >= 1:
				if equal[j-1][i-1]:
					values[j-1][i-1] = value + 1
					moves[j-1][i-1] = 2
				elif value > values[j][i-1]:
					values[j-1][i-1] = value
					moves[j-1][i-1] = 2
			if i >= 1 and not equal[j][i-1] and value - 2 > values[j][i-1]:
				values[j][i-1] = value - 2
				moves[j][i-1] = 1
			if i >= 1 and j >= 2 and not equal[j-2][i-1] and value - 1 > values[j-2][i-1]:
				values[j-2][i-1] = value - 1
				moves[j-2][i-1] = 3
		return (values, moves)

	@memoized
	def get_blocks(self):
		'''
		Compares two binary strings under the assumption that y is the result of
		applying the following transformations onto x:

		 * change single bytes in x (likely)
		 * expand single bytes in x to two bytes (less likely)
		 * drop single bytes in x (even less likely)

		Returns a generator that yields elements of the form (unmodified, xdiff, ydiff),
		where each item represents a binary chunk with "unmodified" denoting whether the
		chunk is the same in both strings, "xdiff" denoting the size of the chunk in x
		and "ydiff" denoting the size of the chunk in y.

		Example:
		>>> x = "abcdefghijklm"
		>>> y = "mmmcdefgHIJZklm"
		>>> list(MemoryComparator(x, y).get_blocks())
		[(False, 2, 3), (True, 5, 5),
		 (False, 3, 4), (True, 3, 3)]
		'''
		x, y = self.x, self.y
		_, moves = self.get_grid()

		# walk the grid
		path = []
		i, j = 0, 0
		while True:
			dy, dx = self.move_to_gradient[moves[j][i]]
			if dy == dx == 0: break
			path.append((dy == 1 and x[i] == y[j], dy, dx))
			j, i = j + dy, i + dx

		for i, j in zip(range(i, len(x)), itertools.count(j)):
			if j < len(y): path.append((x[i] == y[j], 1, 1))
			else:          path.append((False,        0, 1))

		i = j = 0
		for unmodified, subpath in itertools.groupby(path, itemgetter(0)):
			ydiffs = map(itemgetter(1), subpath)
			dx, dy = len(ydiffs), sum(ydiffs)
			yield unmodified, dx, dy
			i += dx
			j += dy

	@memoized
	def get_chunks(self):
		i = j = 0
		for unmodified, dx, dy in self.get_blocks():
			yield self.Chunk(unmodified, i, j, dx, dy, self.x[i:i+dx], self.y[j:j+dy])
			i += dx
			j += dy

	@memoized
	def guess_mapping(self):
		''' Tries to guess how the bytes in x have been mapped to substrings in y by
		applying nasty heuristics.

		Examples:
		>>> list(MemoryComparator("abcdefghijklm", "mmmcdefgHIJZklm").guess_mapping())
		[('m', 'm'), ('m',), ('c',), ('d',), ('e',), ('f',), ('g',), ('H', 'I'), ('J',),
		 ('Z',), ('k',), ('l',), ('m',)]
		>>> list(MemoryComparator("abcdefgcbadefg", "ABBCdefgCBBAdefg").guess_mapping())
		[('A',), ('B', 'B'), ('C',), ('d',), ('e',), ('f',), ('g',), ('C',), ('B', 'B'),
		 ('A',), ('d',), ('e',), ('f',), ('g',)]
		'''
		x, y = self.x, self.y

		mappings_by_byte = defaultdict(lambda: defaultdict(int))
		for c in self.get_chunks():
			dx, dy = c.dx, c.dy
			# heuristics to detect expansions
			if dx < dy and dy - dx <= 3 and dy <= 5:
				for i, b in enumerate(c.xchunk):
					slices = set()
					for start in range(i, min(2*i + 1, dy)):
						for size in range(1, min(dy - start + 1, 3)):
							slc = tuple(c.ychunk[start:start+size])
							if slc in slices: continue
							mappings_by_byte[b][slc] += 1
							slices.add(slc)

		for b, values in mappings_by_byte.iteritems():
			mappings_by_byte[b] = sorted(values.items(), key=lambda value, count : (-count, -len(value)))

		for c in self.get_chunks():
			dx, dy, xchunk, ychunk = c.dx, c.dy, c.xchunk, c.ychunk
			if dx < dy:  # expansion
				# try to apply heuristics for small chunks
				if dx <= 10:
					res = []
					for b in xchunk:
						if dx == dy or dy >= 2*dx: break
						for value, count in mappings_by_byte[b]:
							if tuple(ychunk[:len(value)]) != value: continue
							res.append(value)
							ychunk = ychunk[len(value):]
							dy -= len(value)
							break
						else:
							yield (ychunk[0],)
							ychunk = ychunk[1:]
							dy -= 1
						dx -= 1
					for c in res: yield c

				# ... or do it the stupid way. If n bytes were changed to m, simply do
				# as much drops/expansions as necessary at the beginning and than
				# yield the rest of the y chunk as single-byte modifications
				for k in range(dy - dx): yield tuple(ychunk[2*k:2*k+2])
				ychunk = ychunk[2*(dy - dx):]
			elif dx > dy:
				for _ in range(dx - dy): yield ()

			for b in ychunk: yield (b,)

def read_memory(dbg, location, max_size):
	''' read the maximum amount of memory from the given address '''
	for i in rrange(max_size + 1, 0):
		mem = dbg.readMemory(location, i)
		if len(mem) == i:
			return mem
	# we should never get here, i == 0 should always fulfill the above condition
	assert False

def shorten_bytes(bytes, size=8):
	if len(bytes) <= size: return bin2hex(bytes)
	return '%02x ... %02x' % (ord(bytes[0]), ord(bytes[-1]))

def draw_byte_table(mapping, log, columns=16):
	hrspace = 3 * columns - 1
	hr = '-'*hrspace
	log('    ,' + hr + '.')
	log('    |' + ' Comparison results:'.ljust(hrspace) + '|')
	log('    |' + hr + '|')
	for i, chunk in enumerate(extract_chunks(mapping, columns)):
		chunk = list(chunk)  # save generator result in a list
		src, mapped = zip(*chunk)
		values = []
		for left, right in zip(src, mapped):
			if   left == right:   values.append('')             # byte matches original
			elif len(right) == 0: values.append('-1')           # byte dropped
			elif len(right) == 2: values.append('+1')           # byte expanded
			else:                 values.append(bin2hex(right)) # byte modified
		line1 = '%3x' % (i * columns) + ' |' + bin2hex(src)
		line2 = '    |' + ' '.join(sym.ljust(2) for sym in values) 

		# highlight lines if a modification was detected - removed, looks bad in WinDBG
		#highlight = any(x != y for x, y in chunk)
		#for l in (line1, line2):
		log(line1.ljust(5 + hrspace) + '| File')	
		log(line2.ljust(5 + hrspace) + '| Memory')
	log('    `' + hr + "'")

def draw_chunk_table(cmp, log):
	''' Outputs a table that compares the found memory chunks side-by-side
	in input file vs. memory '''
	table = [('', '', '', '', 'File', 'Memory', 'Note')]
	delims = (' ', ' ', ' ', ' | ', ' | ', ' | ', '')
	last_unmodified = cmp.get_last_unmodified_chunk()
	for c in cmp.get_chunks():
		if   c.dy == 0:    note = 'missing'
		elif c.dx > c.dy:  note = 'compacted'
		elif c.dx < c.dy:  note = 'expanded'
		elif c.unmodified: note = 'unmodified!'
		else:              note = 'corrupted'
		table.append((c.i, c.j, c.dx, c.dy, shorten_bytes(c.xchunk), shorten_bytes(c.ychunk), note))

	# draw the table
	sizes = tuple(max(len(str(c)) for c in col) for col in zip(*table))
	for i, row in enumerate(table):
		log(''.join(str(x).ljust(size) + delim for x, size, delim in zip(row, sizes, delims)))
		if i == 0 or (i == last_unmodified + 1 and i < len(table)):
			log('-' * (sum(sizes) + sum(len(d) for d in delims)))

def guess_bad_chars(cmp, log, logsilent):
	guessed_badchars = []
	''' Tries to guess bad characters and outputs them '''
	bytes_in_changed_blocks = defaultdict(int)
	chunks = cmp.get_chunks()
	last_unmodified = cmp.get_last_unmodified_chunk()
	for i, c in enumerate(chunks):
		if c.unmodified: continue
		if i == last_unmodified + 1:
			# only report the first character as bad in the final corrupted chunk
			bytes_in_changed_blocks[c.xchunk[0]] += 1
			break
		for b in set(c.xchunk):
			bytes_in_changed_blocks[b] += 1

	# guess bad chars
	likely_bc = [char for char, count in bytes_in_changed_blocks.iteritems() if count > 2]
	if likely_bc:
		if not logsilent:
			log("Very likely bad chars: %s" % bin2hex(sorted(likely_bc)))
		guessed_badchars += list(sorted(likely_bc))
	if not logsilent:
		log("Possibly bad chars: %s" % bin2hex(sorted(bytes_in_changed_blocks)))
	guessed_badchars += list(sorted(bytes_in_changed_blocks))
	
	# list bytes already omitted from the input
	bytes_omitted_from_input = set(map(chr, range(0, 256))) - set(cmp.x)
	if bytes_omitted_from_input:
		log("Bytes omitted from input: %s" % bin2hex(sorted(bytes_omitted_from_input)))
		guessed_badchars += list(sorted( bytes_omitted_from_input))
		
	# return list, use list(set(..)) to remove dups
	return list(set(guessed_badchars))

def memcompare(location, src, comparetable, sctype, smart=True, tablecols=16):
	''' Thoroughly compares an input binary string with a location in memory
	and outputs the results. '''

	# set up logging
	objlogfile = MnLog("compare.txt")
	logfile = objlogfile.reset(False)

	# helpers
	def log(msg='', **kw):
		msg = str(msg)
		dbg.log(msg, address=location, **kw)
		objlogfile.write(msg, logfile)

	def add_to_table(msg,badbytes = []):
		locinfo = MnPointer(location).memLocation()
		badbstr = " "
		if len(badbytes) > 0:
			badbstr = "%s " % bin2hex(sorted(badbytes))
		comparetable.add(0, ['0x%08x' % location, msg, badbstr, sctype, locinfo])

	objlogfile.write("-" * 100,logfile)
	log('[+] Comparing with memory at location : 0x%08x (%s)' % (location,MnPointer(location).memLocation()), highlight=1)
	dbg.updateLog()

	mem = read_memory(dbg, location, 2*len(src))
	if smart:
		cmp = MemoryComparator(src, mem)
		mapped_chunks = map(''.join, cmp.guess_mapping())
	else:
		mapped_chunks = list(mem[:len(src)]) + [()] * (len(src) - len(mem))
	mapping = zip(src, mapped_chunks)

	broken = [(i,x,y) for i,(x,y) in enumerate(mapping) if x != y]
	if not broken:
		log('!!! Hooray, %s shellcode unmodified !!!' % sctype, focus=1, highlight=1)
		add_to_table('Unmodified')
		guessed_bc = guess_bad_chars(cmp, log, True)
	else:
		log("Only %d original bytes of '%s' code found." % (len(src) - len(broken), sctype))
		draw_byte_table(mapping, log, columns=tablecols)
		log()
		guessed_bc = []
		if smart:
			# print additional analysis
			draw_chunk_table(cmp, log)
			log()
			guessed_bc = guess_bad_chars(cmp, log, False)
			log()
		add_to_table('Corruption after %d bytes' % broken[0][0],guessed_bc)


#-----------------------------------------------------------------------#
# ROP related functions
#-----------------------------------------------------------------------#

def createRopChains(suggestions,interestinggadgets,allgadgets,modulecriteria,criteria,objprogressfile,progressfile,technique):
	"""
	Will attempt to produce ROP chains
	"""
	
	global ptr_to_get
	global ptr_counter
	global silent
	global noheader
	global ignoremodules
	

	#vars
	vplogtxt = ""
	
	# RVA ?
	showrva = False
	if "rva" in criteria:
		showrva = True

	#define rop routines
	routinedefs = {}
	routinesetup = {}
	
	virtualprotect 				= [["esi","api"],["ebp","jmp esp"],["ebx",0x201],["edx",0x40],["ecx","&?W"],["edi","ropnop"],["eax","nop"]]
	virtualalloc				= [["esi","api"],["ebp","jmp esp"],["ebx",0x01],["edx",0x1000],["ecx",0x40],["edi","ropnop"],["eax","nop"]]
	setinformationprocess		= [["ebp","api"],["edx",0x22],["ecx","&","0x00000002"],["ebx",0xffffffff],["eax",0x4],["edi","pop"]] 
	setprocessdeppolicy			= [["ebp","api"],["ebx","&","0x00000000"],["edi","pop"]]
	
	routinedefs["VirtualProtect"] 			= virtualprotect
	routinedefs["VirtualAlloc"] 			= virtualalloc
	# only run these on older systems
	osver=dbg.getOsVersion()
	if not (osver == "6" or osver == "7" or osver == "8" or osver == "vista" or osver == "win7" or osver == "2008server" or osver == "win8" or osver == "win8.1" or osver == "win10"):
		routinedefs["SetInformationProcess"]	= setinformationprocess
		routinedefs["SetProcessDEPPolicy"]		= setprocessdeppolicy	
	
	modulestosearch = getModulesToQuery(modulecriteria)
	
	routinesetup["VirtualProtect"] = """--------------------------------------------
 EAX = NOP (0x90909090)
 ECX = lpOldProtect (ptr to W address)
 EDX = NewProtect (0x40)
 EBX = dwSize
 ESP = lPAddress (automatic)
 EBP = ReturnTo (ptr to jmp esp)
 ESI = ptr to VirtualProtect()
 EDI = ROP NOP (RETN)
 --- alternative chain ---
 EAX = ptr to &VirtualProtect()
 ECX = lpOldProtect (ptr to W address)
 EDX = NewProtect (0x40)
 EBX = dwSize
 ESP = lPAddress (automatic)
 EBP = POP (skip 4 bytes)
 ESI = ptr to JMP [EAX]
 EDI = ROP NOP (RETN)
 + place ptr to "jmp esp" on stack, below PUSHAD
--------------------------------------------"""


	routinesetup["VirtualAlloc"] = """--------------------------------------------
 EAX = NOP (0x90909090)
 ECX = flProtect (0x40)
 EDX = flAllocationType (0x1000)
 EBX = dwSize
 ESP = lpAddress (automatic)
 EBP = ReturnTo (ptr to jmp esp)
 ESI = ptr to VirtualAlloc()
 EDI = ROP NOP (RETN)
 --- alternative chain ---
 EAX = ptr to &VirtualAlloc()
 ECX = flProtect (0x40)
 EDX = flAllocationType (0x1000)
 EBX = dwSize
 ESP = lpAddress (automatic)
 EBP = POP (skip 4 bytes)
 ESI = ptr to JMP [EAX]
 EDI = ROP NOP (RETN)
 + place ptr to "jmp esp" on stack, below PUSHAD
--------------------------------------------"""

	routinesetup["SetInformationProcess"] = """--------------------------------------------
 EAX = SizeOf(ExecuteFlags) (0x4)
 ECX = &ExecuteFlags (ptr to 0x00000002)
 EDX = ProcessExecuteFlags (0x22)
 EBX = NtCurrentProcess (0xffffffff)
 ESP = ReturnTo (automatic)
 EBP = ptr to NtSetInformationProcess()
 ESI = <not used>
 EDI = ROP NOP (4 byte stackpivot)
--------------------------------------------"""

	routinesetup["SetProcessDEPPolicy"] = """--------------------------------------------
 EAX = <not used>
 ECX = <not used>
 EDX = <not used>
 EBX = dwFlags (ptr to 0x00000000)
 ESP = ReturnTo (automatic)
 EBP = ptr to SetProcessDEPPolicy()
 ESI = <not used>
 EDI = ROP NOP (4 byte stackpivot)
--------------------------------------------"""

	updatetxt = ""
    
	# restrict techniques if needed
	validatedroutinedefs = {}
	if technique != "":
		for routine in routinedefs:
			if technique.lower() == routine.lower():
				validatedroutinedefs[routine] = routinedefs[routine]            
		routinedefs = validatedroutinedefs

	for routine in routinedefs:
	
		thischain = {}
		updatetxt = "Attempting to produce rop chain for %s" % routine 
		dbg.log("[+] %s" % updatetxt)
		objprogressfile.write("- " + updatetxt,progressfile)
		vplogtxt += "\n"
		vplogtxt += "#" * 80
		vplogtxt += "\n\nRegister setup for " + routine + "() :\n" + routinesetup[routine] + "\n\n"
		targetOS = "(XP/2003 Server and up)"
		if routine == "SetInformationProcess":
			targetOS = "(XP/2003 Server only)"
		if routine == "SetProcessDEPPolicy":
			targetOS = "(XP SP3/Vista SP1/2008 Server SP1, can be called only once per process)"
		title = "ROP Chain for %s() [%s] :" % (routine,targetOS)
		vplogtxt += "\n%s\n" % title
		vplogtxt += ("-" * len(title)) + "\n\n"
		vplogtxt += "*** [ Ruby ] ***\n\n"
		vplogtxt += "  def create_rop_chain()\n"
		vplogtxt += '\n    # rop chain generated with mona.py - www.corelan.be'
		vplogtxt += "\n    rop_gadgets = \n"
		vplogtxt += "    [\n"
		
		thischaintxt = ""
		
		dbg.updateLog()
		modused = {}
		
		skiplist = []
		replacelist = {}
		toadd = {}
		
		movetolast = []
		regsequences = []
		stepcnt = 1
		for step in routinedefs[routine]:
			thisreg = step[0]
			thistarget = step[1]
			
			if thisreg in replacelist:
				thistarget = replacelist[thisreg]
			
			thistimestamp=datetime.datetime.now().strftime("%a %Y/%m/%d %I:%M:%S %p")
			dbg.log("    %s: Step %d/%d: %s" % (thistimestamp,stepcnt,len(routinedefs[routine]),thisreg))
			stepcnt += 1

			if not thisreg in skiplist:
			
				regsequences.append(thisreg)
				
				# this must be done first, so we can determine deviations to the chain using
				# replacelist and skiplist arrays
				if str(thistarget) == "api":
					objprogressfile.write("  * Enumerating ROPFunc info (IAT Query)",progressfile)
					#dbg.log("    Enumerating ROPFunc info")
					# routine to put api pointer in thisreg
					funcptr,functext = getRopFuncPtr(routine,modulecriteria,criteria,"iat", objprogressfile, progressfile)
					if routine == "SetProcessDEPPolicy" and funcptr == 0:
						# read EAT
						funcptr,functext = getRopFuncPtr(routine,modulecriteria,criteria,"eat", objprogressfile, progressfile)
						extra = ""
						if funcptr == 0:
							extra = "[-] Unable to find ptr to "
							thischain[thisreg] = [[0,extra + routine + "() (-> to be put in " + thisreg + ")",0]]
						else:
							thischain[thisreg] = putValueInReg(thisreg,funcptr,routine + "() [" + MnPointer(funcptr).belongsTo() + "]",suggestions,interestinggadgets,criteria)
					else:
						objprogressfile.write("    Function pointer : 0x%0x" % funcptr, progressfile)
						objprogressfile.write("  * Getting pickup gadget",progressfile)
						thischain[thisreg],skiplist = getPickupGadget(thisreg,funcptr,functext,suggestions,interestinggadgets,criteria,modulecriteria,routine)
						# if skiplist is not empty, then we are using the alternative pickup (via jmp [eax])
						# this means we have to make some changes to the routine
						# and place this pickup at the end
						
						if len(skiplist) > 0:
							if routine.lower() == "virtualprotect" or routine.lower() == "virtualalloc":
								replacelist["ebp"] = "pop"

								#set up call to finding jmp esp
								oldsilent = silent
								silent=True
								ptr_counter = 0
								ptr_to_get = 3
								jmpreg = findJMP(modulecriteria,criteria,"esp")
								ptr_counter = 0
								ptr_to_get = -1
								jmpptr = 0
								jmptype = ""
								silent=oldsilent
								total = getNrOfDictElements(jmpreg)
								if total > 0:
									ptrindex = random.randint(1,total)
									indexcnt= 1
									for regtype in jmpreg:
										for ptr in jmpreg[regtype]:
											if indexcnt == ptrindex:
												jmpptr = ptr
												jmptype = regtype
												break
											indexcnt += 1
								if jmpptr > 0:
									toadd[thistarget] = [jmpptr,"ptr to '" + jmptype + "'"]
								else:
									toadd[thistarget] = [jmpptr,"ptr to 'jmp esp'"]
								# make sure the pickup is placed last
								movetolast.append(thisreg)
								
					
				if str(thistarget).startswith("jmp"):
					targetreg = str(thistarget).split(" ")[1]
					#set up call to finding jmp esp
					oldsilent = silent
					silent=True
					ptr_counter = 0
					ptr_to_get = 3
					jmpreg = findJMP(modulecriteria,criteria,targetreg)
					ptr_counter = 0
					ptr_to_get = -1
					jmpptr = 0
					jmptype = ""
					silent=oldsilent
					total = getNrOfDictElements(jmpreg)
					if total > 0:
						ptrindex = random.randint(1,total)
						indexcnt= 1					
						for regtype in jmpreg:
							for ptr in jmpreg[regtype]:
								if indexcnt == ptrindex:
									jmpptr = ptr
									jmptype = regtype
									break
								indexcnt += 1
					jmpinfo = ""
					jmpmodinfo = ""
					if jmpptr == 0:
						jmptype = ""
						jmpinfo = "Unable to find ptr to 'JMP ESP'"
					else:
						jmpinfo = MnPointer(jmpptr).belongsTo() 
						tmod = MnModule(jmpinfo)
						jmpmodinfo = getGadgetAddressInfo(jmpptr)
					thischain[thisreg] = putValueInReg(thisreg,jmpptr,"& " + jmptype + " [" + jmpinfo + "]" + jmpmodinfo,suggestions,interestinggadgets,criteria)
				
				if str(thistarget) == "ropnop":
					ropptr = 0
					for poptype in suggestions:
						if poptype.startswith("pop "):
							for retptr in suggestions[poptype]:
								if getOffset(interestinggadgets[retptr]) == 0 and interestinggadgets[retptr].count("#") == 2:
									ropptr = retptr+1
									break
						if poptype.startswith("inc "):
							for retptr in suggestions[poptype]:
								if getOffset(interestinggadgets[retptr]) == 0 and interestinggadgets[retptr].count("#") == 2:
									ropptr = retptr+1
									break
						if poptype.startswith("dec "):
							for retptr in suggestions[poptype]:
								if getOffset(interestinggadgets[retptr]) == 0 and interestinggadgets[retptr].count("#") == 2:
									ropptr = retptr+1
									break
						if poptype.startswith("neg "):
							for retptr in suggestions[poptype]:
								if getOffset(interestinggadgets[retptr]) == 0 and interestinggadgets[retptr].count("#") == 2:
									ropptr = retptr+2
									break
								
					if ropptr == 0:
						for emptytype in suggestions:
							if emptytype.startswith("empty "):
								for retptr in suggestions[emptytype]:
									if interestinggadgets[retptr].startswith("# XOR"):
										if getOffset(interestinggadgets[retptr]) == 0:
											ropptr = retptr+2
										break
					if ropptr > 0:
						thismodname = MnPointer(ropptr).belongsTo()
						tmod = MnModule(thismodname)
						ropnopinfo = getGadgetAddressInfo(ropptr)

						thischain[thisreg] = putValueInReg(thisreg,ropptr,"RETN (ROP NOP) [" + thismodname + "]" + ropnopinfo,suggestions,interestinggadgets,criteria)
					else:
						thischain[thisreg] = putValueInReg(thisreg,ropptr,"[-] Unable to find ptr to RETN (ROP NOP)",suggestions,interestinggadgets,criteria)					
				
				
				if thistarget.__class__.__name__ == "int" or thistarget.__class__.__name__ == "long":
					thischain[thisreg] = putValueInReg(thisreg,thistarget,"0x" + toHex(thistarget) + "-> " + thisreg,suggestions,interestinggadgets,criteria)
				
				
				if str(thistarget) == "nop":
					thischain[thisreg] = putValueInReg(thisreg,0x90909090,"nop",suggestions,interestinggadgets,criteria)

					
				if str(thistarget).startswith("&?"):
					#pointer to
					rwptr = getAPointer(modulestosearch,criteria,"RW")
					if rwptr == 0:
						rwptr = getAPointer(modulestosearch,criteria,"W")
					if rwptr != 0:

						rwmodname = MnPointer(rwptr).belongsTo()
						
						rwmodinfo = getGadgetAddressInfo(rwptr)
						thischain[thisreg] = putValueInReg(thisreg,rwptr,"&Writable location [" + rwmodname+"]" + rwmodinfo,suggestions,interestinggadgets,criteria)
					else:
						thischain[thisreg] = putValueInReg(thisreg,rwptr,"[-] Unable to find writable location",suggestions,interestinggadgets,criteria)
				
				
				if str(thistarget).startswith("pop"):
					#get distance
					if "pop " + thisreg in suggestions:
						popptr = getShortestGadget(suggestions["pop "+thisreg])
						junksize = getJunk(interestinggadgets[popptr])-4
						thismodname = MnPointer(popptr).belongsTo()
						tmodinfo = getGadgetAddressInfo(popptr)
						thischain[thisreg] = [[popptr,"",junksize],[popptr,"skip 4 bytes [" + thismodname + "]" + tmodinfo]]
					else:
						thischain[thisreg] = [[0,"[-] Couldn't find a gadget to put a pointer to a stackpivot (4 bytes) into "+ thisreg,0]]
	
				
				if str(thistarget)==("&"):
					pattern = step[2]
					base = 0
					top = TOP_USERLAND
					type = "ptr"
					al = criteria["accesslevel"]
					criteria["accesslevel"] = "R"
					ptr_counter = 0				
					ptr_to_get = 2
					oldsilent = silent
					silent=True				
					allpointers = findPattern(modulecriteria,criteria,pattern,type,base,top)
					silent = oldsilent
					criteria["accesslevel"] = al
					if len(allpointers) > 0:
						theptr = 0
						for ptrtype in allpointers:
							for ptrs in allpointers[ptrtype]:
								theptr = ptrs
								break
						thischain[thisreg] = putValueInReg(thisreg,theptr,"&" + str(pattern) + " [" + MnPointer(theptr).belongsTo() + "]",suggestions,interestinggadgets,criteria)
					else:
						thischain[thisreg] = putValueInReg(thisreg,0,"[-] Unable to find ptr to " + str(pattern),suggestions,interestinggadgets,criteria)
						
		returnoffset = 0
		delayedfill = 0
		junksize = 0
		# get longest modulename
		longestmod = 0
		fillersize = 0
		for step in routinedefs[routine]:
			thisreg = step[0]
			if thisreg in thischain:
				for gadget in thischain[thisreg]:
					thismodname = sanitize_module_name(MnPointer(gadget[0]).belongsTo())
					if len(thismodname) > longestmod:
						longestmod = len(thismodname)
		if showrva:
			fillersize = longestmod + 8
		else:
			fillersize = 0
		
		# modify the chain order (regsequences array)
		for reg in movetolast:
			if reg in regsequences:
				regsequences.remove(reg)
				regsequences.append(reg)
		

		regimpact = {}
		# create the current chain
		ropdbchain = ""
		tohex_array = []
		for step in regsequences:
			thisreg = step
			vplogtxt += 	"      #[---INFO:gadgets_to_set_%s:---]\n" % (thisreg) 
			thischaintxt += "      #[---INFO:gadgets_to_set_%s:---]\n" % (thisreg)
			if thisreg in thischain:
				for gadget in thischain[thisreg]:
					gadgetstep = gadget[0]
					steptxt = gadget[1]
					junksize = 0
					showfills = False
					if len(gadget) > 2:
						junksize = gadget[2]
					if gadgetstep in interestinggadgets and steptxt == "":
						thisinstr = interestinggadgets[gadgetstep].lstrip()
						if thisinstr.startswith("#"):
							thisinstr = thisinstr[2:len(thisinstr)]
							showfills = True
						thismodname = MnPointer(gadgetstep).belongsTo()
						thisinstr += " [" + thismodname + "]"
						tmod = MnModule(thismodname)
						thisinstr += getGadgetAddressInfo(gadgetstep)
						if not thismodname in modused:
							modused[thismodname] = [tmod.moduleBase,tmod.__str__()]	
						modprefix = "base_" + sanitize_module_name(thismodname)
						if showrva:
							alignsize = longestmod - len(sanitize_module_name(thismodname))
							vplogtxt += "      %s + 0x%s,%s  # %s %s\n" % (modprefix,toHex(gadgetstep-tmod.moduleBase),toSize("",alignsize),thisinstr,steptxt)
							thischaintxt += "      %s + 0x%s,%s  # %s %s\n" % (modprefix,toHex(gadgetstep-tmod.moduleBase),toSize("",alignsize),thisinstr,steptxt)
						else:
							vplogtxt += "      0x%s,  # %s %s\n" % (toHex(gadgetstep),thisinstr,steptxt)
							thischaintxt += "      0x%s,  # %s %s\n" % (toHex(gadgetstep),thisinstr,steptxt)
						ropdbchain += '    <gadget offset="0x%s">%s</gadget>\n' % (toHex(gadgetstep-tmod.moduleBase),thisinstr.strip(" "))
						tohex_array.append(gadgetstep)
						
						if showfills:
							vplogtxt += createJunk(returnoffset,"Filler (RETN offset compensation)",fillersize)
							thischaintxt += createJunk(returnoffset,"Filler (RETN offset compensation)",fillersize)
							if returnoffset > 0:
								ropdbchain += '    <gadget value="junk">Filler</gadget>\n'
							returnoffset = getOffset(interestinggadgets[gadgetstep])
							if delayedfill > 0:
								vplogtxt += createJunk(delayedfill,"Filler (compensate)",fillersize)
								thischaintxt += createJunk(delayedfill,"Filler (compensate)",fillersize)
								ropdbchain += '    <gadget value="junk">Filler</gadget>\n'
								delayedfill = 0
							if thisinstr.startswith("POP "):
								delayedfill = junksize
							else:
								vplogtxt += createJunk(junksize,"Filler (compensate)",fillersize)
								thischaintxt += createJunk(junksize,"Filler (compensate)",fillersize)
								if junksize > 0:
									ropdbchain += '    <gadget value="junk">Filler</gadget>\n'
					else:
						# still could be a pointer
						thismodname = MnPointer(gadgetstep).belongsTo()
						if thismodname != "":
							tmod = MnModule(thismodname)
							if not thismodname in modused:
								modused[thismodname] = [tmod.moduleBase,tmod.__str__()]
							modprefix = "base_" + sanitize_module_name(thismodname)
							if showrva:
								alignsize = longestmod - len(sanitize_module_name(thismodname))
								vplogtxt += "      %s + 0x%s,%s  # %s\n" % (modprefix,toHex(gadgetstep-tmod.moduleBase),toSize("",alignsize),steptxt)
								thischaintxt += "      %s + 0x%s,%s  # %s\n" % (modprefix,toHex(gadgetstep-tmod.moduleBase),toSize("",alignsize),steptxt)
							else:
								vplogtxt += "      0x%s,  # %s\n" % (toHex(gadgetstep),steptxt)		
								thischaintxt += "      0x%s,  # %s\n" % (toHex(gadgetstep),steptxt)
							ropdbchain += '    <gadget offset="0x%s">%s</gadget>\n' % (toHex(gadgetstep-tmod.moduleBase),steptxt.strip(" "))
						else:						
							vplogtxt += "      0x%s,%s  # %s\n" % (toHex(gadgetstep),toSize("",fillersize),steptxt)
							thischaintxt += "      0x%s,%s  # %s\n" % (toHex(gadgetstep),toSize("",fillersize),steptxt)						
							ropdbchain += '    <gadget value="0x%s">%s</gadget>\n' % (toHex(gadgetstep),steptxt.strip(" "))
						
						if steptxt.startswith("[-]"):
							vplogtxt += createJunk(returnoffset,"Filler (RETN offset compensation)",fillersize)
							thischaintxt += createJunk(returnoffset,"Filler (RETN offset compensation)",fillersize)
							ropdbchain += '    <gadget value="junk">Filler</gadget>\n'
							returnoffset = 0
						if delayedfill > 0:
							vplogtxt += createJunk(delayedfill,"Filler (compensate)",fillersize)
							thischaintxt += createJunk(delayedfill,"Filler (compensate)",fillersize)
							ropdbchain += '    <gadget value="junk">Filler</gadget>\n'
							delayedfill = 0							
						vplogtxt += createJunk(junksize,"",fillersize)
						thischaintxt += createJunk(junksize,"",fillersize)
						if fillersize > 0:
							ropdbchain += '    <gadget value="junk">Filler</gadget>\n'						
		# finish it off
		steptxt = ""
		vplogtxt += 	"      #[---INFO:pushad:---]\n"  
		thischaintxt += "      #[---INFO:pushad:---]\n"
		if "pushad" in suggestions:
			shortest_pushad = getShortestGadget(suggestions["pushad"])
			junksize = getJunk(interestinggadgets[shortest_pushad])
			thisinstr = interestinggadgets[shortest_pushad].lstrip()
			if thisinstr.startswith("#"):
				thisinstr = thisinstr[2:len(thisinstr)]
			regimpact = getRegImpact(thisinstr)
			thismodname = MnPointer(shortest_pushad).belongsTo()
			thisinstr += " [" + thismodname + "]"
			tmod = MnModule(thismodname)
			thisinstr += getGadgetAddressInfo(shortest_pushad)
			if not thismodname in modused:
				modused[thismodname] = [tmod.moduleBase,tmod.__str__()]				
			modprefix = "base_" + sanitize_module_name(thismodname)
			if showrva:
				alignsize = longestmod - len(thismodname)
				vplogtxt += "      %s + 0x%s,%s  # %s %s\n" % (modprefix,toHex(shortest_pushad - tmod.moduleBase),toSize("",alignsize),thisinstr,steptxt)
				thischaintxt += "      %s + 0x%s,%s  # %s %s\n" % (modprefix,toHex(shortest_pushad - tmod.moduleBase),toSize("",alignsize),thisinstr,steptxt)
			else:
				vplogtxt += "      0x%s,  # %s %s\n" % (toHex(shortest_pushad),thisinstr,steptxt)
				thischaintxt += "      0x%s,  # %s %s\n" % (toHex(shortest_pushad),thisinstr,steptxt)
			ropdbchain += '    <gadget offset="0x%s">%s</gadget>\n' % (toHex(shortest_pushad-tmod.moduleBase),thisinstr.strip(" "))
			vplogtxt += createJunk(returnoffset,"Filler (RETN offset compensation)",fillersize)
			thischaintxt += createJunk(returnoffset,"Filler (RETN offset compensation)",fillersize)
			if fillersize > 0:
				ropdbchain += '    <gadget value="junk">Filler</gadget>\n'						
			vplogtxt += createJunk(junksize,"",fillersize)
			thischaintxt += createJunk(junksize,"",fillersize)
			if fillersize > 0:
				ropdbchain += '    <gadget value="junk">Filler</gadget>\n'						
			
		else:
			vplogtxt += "      0x00000000,%s  # %s\n" % (toSize("",fillersize),"[-] Unable to find pushad gadget")
			thischaintxt += "      0x00000000,%s  # %s\n" % (toSize("",fillersize),"[-] Unable to find pushad gadget")
			ropdbchain += '    <gadget offset="0x00000000">Unable to find PUSHAD gadget</gadget>\n'
			vplogtxt += createJunk(returnoffset,"Filler (RETN offset compensation)",fillersize)
			thischaintxt += createJunk(returnoffset,"Filler (RETN offset compensation)",fillersize)
			if returnoffset > 0:
				ropdbchain += '    <gadget value="junk">Filler</gadget>\n'	
		
		# anything else to add ?
		if len(toadd) > 0:
			vplogtxt += 	"      #[---INFO:extras:---]\n"  
			thischaintxt += "      #[---INFO:extras:---]\n"
			for adds in toadd:
				theptr = toadd[adds][0]
				freetext = toadd[adds][1]
				if theptr > 0:
					thismodname = MnPointer(theptr).belongsTo()
					freetext += " [" + thismodname + "]"
					tmod = MnModule(thismodname)
					freetext += getGadgetAddressInfo(theptr)
					if not thismodname in modused:
						modused[thismodname] = [tmod.moduleBase,tmod.__str__()]				
					modprefix = "base_" + sanitize_module_name(thismodname)
					if showrva:
						alignsize = longestmod - len(thismodname)
						vplogtxt += "      %s + 0x%s,%s  # %s\n" % (modprefix,toHex(theptr - tmod.moduleBase),toSize("",alignsize),freetext)
						thischaintxt += "      %s + 0x%s,%s  # %s\n" % (modprefix,toHex(theptr - tmod.moduleBase),toSize("",alignsize),freetext)
					else:
						vplogtxt += "      0x%s,  # %s\n" % (toHex(theptr),freetext)
						thischaintxt += "      0x%s,  # %s\n" % (toHex(theptr),freetext)
					ropdbchain += '    <gadget offset="0x%s">%s</gadget>\n' % (toHex(theptr-tmod.moduleBase),freetext.strip(" "))
				else:
					vplogtxt += "      0x%s,  # <- Unable to find %s\n" % (toHex(theptr),freetext)
					thischaintxt += "      0x%s,  # <- Unable to find %s\n" % (toHex(theptr),freetext)
					ropdbchain += '    <gadget offset="0x%s">Unable to find %s</gadget>\n' % (toHex(theptr),freetext.strip(" "))
		
		vplogtxt += '    ].flatten.pack("V*")\n'
		vplogtxt += '\n    return rop_gadgets\n\n'
		vplogtxt += '  end\n'
		vplogtxt += '\n\n  # Call the ROP chain generator inside the \'exploit\' function :\n\n'
		calltxt = "rop_chain = create_rop_chain("
		argtxt = ""
		vplogtxtpy = ""
		vplogtxtc = ""
		vplogtxtjs = ""
		argtxtpy = ""
		if showrva:
			for themod in modused:
				repr_mod = sanitize_module_name(themod)
				vplogtxt += "  # " + modused[themod][1] + "\n"
				vplogtxtpy += "  # " + modused[themod][1] + "\n"
				vplogtxtc += "  // " + modused[themod][1] + "\n"
				vplogtxtjs += "  // " + modused[themod][1] + "\n"
				vplogtxt += "  base_" + repr_mod + " = 0x%s\n" % toHex(modused[themod][0])
				vplogtxtjs += "  var base_" + repr_mod + " = 0x%s;\n" % toHex(modused[themod][0])
				vplogtxtpy += "  base_" + repr_mod + " = 0x%s\n" % toHex(modused[themod][0])
				vplogtxtc += "  unsigned int base_" + repr_mod + " = 0x%s;\n" % toHex(modused[themod][0])
				calltxt += "base_" + repr_mod + ","
				argtxt += "base_" + repr_mod + ","
				argtxtpy += "base_" + repr_mod + ","				
		calltxt = calltxt.rstrip(",") + ")\n"
		argtxt = argtxt.strip(",")
		argtxtpy = argtxtpy.strip(",")
		argtxtjs = argtxtpy.replace(".","")
		
		vplogtxt = vplogtxt.replace("create_rop_chain()","create_rop_chain(" + argtxt + ")")
		vplogtxt += '\n  ' + calltxt
		vplogtxt += '\n\n\n'
		# C
		vplogtxt += "*** [ C ] ***\n\n"
		vplogtxt += "  #define CREATE_ROP_CHAIN(name, ...) \\\n"
		vplogtxt += "    int name##_length = create_rop_chain(NULL, ##__VA_ARGS__); \\\n"
		vplogtxt += "    unsigned int name[name##_length / sizeof(unsigned int)]; \\\n"
		vplogtxt += "    create_rop_chain(name, ##__VA_ARGS__);\n\n"
		vplogtxt += "  int create_rop_chain(unsigned int *buf, %s)\n" % ", ".join("unsigned int %s" % _ for _ in argtxt.split(","))
		vplogtxt += "  {\n"
		vplogtxt += "    // rop chain generated with mona.py - www.corelan.be\n"			
		vplogtxt += "    unsigned int rop_gadgets[] = {\n"
		vplogtxt += thischaintxt.replace("#", "//")
		vplogtxt += "    };\n"
		vplogtxt += "    if(buf != NULL) {\n"
		vplogtxt += "      memcpy(buf, rop_gadgets, sizeof(rop_gadgets));\n"
		vplogtxt += "    };\n"
		vplogtxt += "    return sizeof(rop_gadgets);\n"
		vplogtxt += "  }\n\n"
		vplogtxt += vplogtxtc
		vplogtxt += "  // use the 'rop_chain' variable after this call, it's just an unsigned int[]\n"
		vplogtxt += "  CREATE_ROP_CHAIN(rop_chain, %s);\n" % argtxtpy
		vplogtxt += "  // alternatively just allocate a large enough buffer and get the rop chain, i.e.:\n"
		vplogtxt += "  // unsigned int rop_chain[256];\n"
		vplogtxt += "  // int rop_chain_length = create_rop_chain(rop_chain, %s);\n\n" % argtxtpy
		# Python
		vplogtxt += "*** [ Python ] ***\n\n"		
		vplogtxt += "  def create_rop_chain(%s):\n" % argtxt
		vplogtxt += "\n    # rop chain generated with mona.py - www.corelan.be\n"			
		vplogtxt += "    rop_gadgets = [\n"
		vplogtxt += thischaintxt
		vplogtxt += "    ]\n"
		vplogtxt += "    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)\n\n"
		vplogtxt += vplogtxtpy
		vplogtxt += "  rop_chain = create_rop_chain(%s)\n\n" % argtxtpy
		# Javascript
		vplogtxt += "\n\n*** [ JavaScript ] ***\n\n"
		vplogtxt += "  //rop chain generated with mona.py - www.corelan.be\n"		
		if not showrva:
			vplogtxt += "  rop_gadgets = unescape(\n"
			allptr = thischaintxt.split("\n")
			tptrcnt = 0
			for tptr in allptr:
				comments = tptr.split(",")
				comment = ""
				if len(comments) > 1:
					# add everything
					ic = 1
					while ic < len(comments):
						comment += "," + comments[ic]
						ic += 1
				tptrcnt += 1
				comment = comment.replace("  ","")
				if tptrcnt < len(allptr):
					vplogtxt += "    \"" + toJavaScript(tptr) + "\" + // " + comments[0].replace("  ","").replace(" ","") + " : " + comment + "\n"
				else:
					vplogtxt += "    \"" + toJavaScript(tptr) + "\"); // " + comments[0].replace("  ","").replace(" ","") + " : " + comment + "\n\n"
		else:
			vplogtxt += "  function get_rop_chain(%s) {\n" % argtxtjs
			vplogtxt += "    var rop_gadgets = [\n"
			vplogtxt += thischaintxt.replace("  #","  //").replace(".","")
			vplogtxt += "      ];\n"
			vplogtxt += "    return rop_gadgets;\n"
			vplogtxt += "  }\n\n"
			vplogtxt += "  function gadgets2uni(gadgets) {\n"
			vplogtxt += "    var uni = \"\";\n"
			vplogtxt += "    for(var i=0;i<gadgets.length;i++){\n"
			vplogtxt += "      uni += d2u(gadgets[i]);\n"
			vplogtxt += "    }\n"
			vplogtxt += "    return uni;\n"
			vplogtxt += "  }\n\n"
			vplogtxt += "  function d2u(dword) {\n"
			vplogtxt += "    var uni = String.fromCharCode(dword & 0xFFFF);\n"
			vplogtxt += "    uni += String.fromCharCode(dword>>16);\n"
			vplogtxt += "    return uni;\n"
			vplogtxt += "  }\n\n"
			vplogtxt += "%s" % vplogtxtjs
			vplogtxt += "\n  var rop_chain = gadgets2uni(get_rop_chain(%s));\n\n" % argtxtjs
		vplogtxt += '\n--------------------------------------------------------------------------------------------------\n\n'
		
		# MSF RopDB XML Format - spit out if only one module was selected
		if len(modused) == 1:
			modulename = ""
			for modname in modused:
				modulename = modname
			objMod = MnModule(modulename)
			modversion = objMod.moduleVersion
			modbase = objMod.moduleBase
			ropdb = '<?xml version="1.0" encoding="ISO-8859-1"?>\n'
			ropdb += "<db>\n<rop>\n"
			ropdb += "  <compatibility>\n"
			ropdb += "    <target>%s</target>\n" % modversion
			ropdb += "  </compatibility>\n\n"
			ropdb += '  <gadgets base="0x%s">\n' % toHex(modbase)
			ropdb += ropdbchain.replace('[' + modulename + ']','').replace('&','').replace('[IAT ' + modulename + ']','')
			ropdb += '  </gadgets>\n'
			ropdb += '</rop>\n</db>'
			# write to file if needed
			shortmodname = modulename.replace(".dll","")
			ignoremodules = True
			if ropdbchain.lower().find("virtualprotect") > -1:
				ofile = MnLog(shortmodname+"_virtualprotect.xml")
				thisofile = ofile.reset(showheader = False)
				ofile.write(ropdb,thisofile)
			if ropdbchain.lower().find("virtualalloc") > -1:
				ofile = MnLog(shortmodname+"_virtualalloc.xml")
				thisofile = ofile.reset(showheader = False)
				ofile.write(ropdb,thisofile)
			ignoremodules = False
		
		#go to the next one
		
	vpfile = MnLog("rop_chains.txt")
	thisvplog = vpfile.reset()
	vpfile.write(vplogtxt,thisvplog)
	
	dbg.log("[+] ROP chains written to file %s" % thisvplog)
	objprogressfile.write("Done creating rop chains",progressfile)
	return vplogtxt


def getGadgetAddressInfo(gadgetptr):
	gadgetmodname = MnPointer(gadgetptr).belongsTo()
	infotxt = ""
	tmod = MnModule(gadgetmodname)
	if (tmod.isRebase):
		infotxt += " ** REBASED"
	if (tmod.isAslr):
		infotxt += " ** ASLR"	
	return infotxt


def getRegImpact(instructionstr):
	rimpact = {}
	instrlineparts = instructionstr.split(" # ")
	changers = ["ADD","SUB","ADC","INC","DEC","XOR"]
	for i in instrlineparts:
		instrparts = i.split(" ")
		dreg = ""
		dval = 0
		if len(instrparts) > 1:
			if instrparts[0] in changers:
				dreg = instrparts[1]
				if instrparts[0] == "INC":
					dval = -1
				elif instrparts[0] == "DEC":
					dval = 1
				else:
					vparts = i.split(",")
					if len(vparts) > 1:
						vpart = vparts[1]
						dval = vpart

		if dreg != "":
			if not dreg in rimpact:
				rimpact[dreg] = dval
			else:
				rimpact[dreg] = rimpact[dreg] + dval

	return rimpact


def getPickupGadget(targetreg,targetval,freetext,suggestions,interestinggadgets,criteria,modulecriteria,routine=""):
	"""
	Will attempt to find a gadget that will pickup a pointer to pointer into a register
	
	Arguments : the destination register, the value to pick up, some free text about the value,
	suggestions and interestinggadgets dictionaries
	
	Returns :
	an array with the gadgets
	"""
	
	shortest_pickup = 0
	thisshortest_pickup = 0
	shortest_move = 0
	popptr = 0
	
	pickupfrom = ""
	pickupreg = ""
	pickupfound = False
	
	pickupchain = []
	movechain = []
	movechain1 = []
	movechain2 = []
	
	disablelist = []
	
	allregs = ["eax","ebx","ecx","edx","ebp","esi","edi"]
	
	for pickuptypes in suggestions:
		if pickuptypes.find("pickup pointer into " + targetreg) > -1: 
			thisshortest_pickup = getShortestGadget(suggestions[pickuptypes])
			if shortest_pickup == 0 or (thisshortest_pickup != 0 and thisshortest_pickup < shortest_pickup):
				shortest_pickup = thisshortest_pickup
				smallparts = pickuptypes.split(" ")
				pickupreg = smallparts[len(smallparts)-1].lower()
				parts2 = interestinggadgets[shortest_pickup].split("#")
				 #parts2[0] is empty
				smallparts = parts2[1].split("[")
				smallparts2 = smallparts[1].split("]")
				pickupfrom = smallparts2[0].lower()
				pickupfound = True
				if (pickupfrom.find("+") > -1):
					pickupfields = pickupfrom.split("+")
					if pickupfields[1].lower in allregs:
						pickupfound = False
						shortest_pickup = 0
				if (pickupfrom.find("-") > -1):
					pickupfields = pickupfrom.split("-")
					if pickupfields[1].lower in allregs:
						pickupfound = False
						shortest_pickup = 0				

	if shortest_pickup == 0:
		# no direct pickup, look for indirect pickup, but prefer EAX first
		for movetypes in suggestions:
			if movetypes.find("move eax") == 0 and movetypes.endswith("-> " + targetreg):
				typeparts = movetypes.split(" ")
				movefrom = "eax"
				shortest_move = getShortestGadget(suggestions[movetypes])
				movechain = getGadgetMoveRegToReg(movefrom,targetreg,suggestions,interestinggadgets)
				for pickuptypes in suggestions:
					if pickuptypes.find("pickup pointer into " + movefrom) > -1:
						thisshortest_pickup = getShortestGadget(suggestions[pickuptypes])
						if shortest_pickup == 0 or (thisshortest_pickup != 0 and thisshortest_pickup < shortest_pickup):
							shortest_pickup = thisshortest_pickup
							smallparts = pickuptypes.split(" ")
							pickupreg = smallparts[len(smallparts)-1].lower()
							parts2 = interestinggadgets[shortest_pickup].split("#")
							 #parts2[0] is empty
							smallparts = parts2[1].split("[")
							smallparts2 = smallparts[1].split("]")
							pickupfrom = smallparts2[0].lower()
							pickupfound = True
							if (pickupfrom.find("+") > -1):
								pickupfields = pickupfrom.split("+")
								if pickupfields[1].lower in allregs:
									pickupfound = False
									shortest_pickup = 0
							if (pickupfrom.find("-") > -1):
								pickupfields = pickupfrom.split("-")
								if pickupfields[1].lower in allregs:
									pickupfound = False
									shortest_pickup = 0
				if pickupfound:
					break
				
	if shortest_pickup == 0:
		# no direct pickup, look for indirect pickup
		for movetypes in suggestions:
			if movetypes.find("move") == 0 and movetypes.endswith("-> " + targetreg):
				typeparts = movetypes.split(" ")
				movefrom = typeparts[1]
				if movefrom != "esp":
					shortest_move = getShortestGadget(suggestions[movetypes])
					movechain = getGadgetMoveRegToReg(movefrom,targetreg,suggestions,interestinggadgets)
					for pickuptypes in suggestions:
						if pickuptypes.find("pickup pointer into " + movefrom) > -1:
							thisshortest_pickup = getShortestGadget(suggestions[pickuptypes])
							if shortest_pickup == 0 or (thisshortest_pickup != 0 and thisshortest_pickup < shortest_pickup):
								shortest_pickup = thisshortest_pickup
								smallparts = pickuptypes.split(" ")
								pickupreg = smallparts[len(smallparts)-1].lower()
								parts2 = interestinggadgets[shortest_pickup].split("#")
								 #parts2[0] is empty
								smallparts = parts2[1].split("[")
								smallparts2 = smallparts[1].split("]")
								pickupfrom = smallparts2[0].lower()
								pickupfound = True
								if (pickupfrom.find("+") > -1):
									pickupfields = pickupfrom.split("+")
									if pickupfields[1].lower in allregs:
										pickupfound = False
										shortest_pickup = 0
								if (pickupfrom.find("-") > -1):
									pickupfields = pickupfrom.split("-")
									if pickupfields[1].lower in allregs:
										pickupfound = False
										shortest_pickup = 0
					if pickupfound:
						break
						
	if shortest_pickup == 0:
		movechain = []
		#double move
		for movetype1 in suggestions:
			if movetype1.find("move") == 0 and movetype1.endswith("-> " + targetreg):
				interimreg = movetype1.split(" ")[1]
				if interimreg != "esp":
					for movetype2 in suggestions:
						if movetype2.find("move") == 0 and movetype2.endswith("-> " + interimreg):
							topickupreg= movetype2.split(" ")[1]
							if topickupreg != "esp":
								move1 = getShortestGadget(suggestions[movetype1])
								move2 = getShortestGadget(suggestions[movetype2])								
								for pickuptypes in suggestions:
									if pickuptypes.find("pickup pointer into " + topickupreg) > -1:
										thisshortest_pickup = getShortestGadget(suggestions[pickuptypes])
										if shortest_pickup == 0 or (thisshortest_pickup != 0 and thisshortest_pickup < shortest_pickup):
											shortest_pickup = thisshortest_pickup
											smallparts = pickuptypes.split(" ")
											pickupreg = smallparts[len(smallparts)-1].lower()
											parts2 = interestinggadgets[shortest_pickup].split("#")
											 #parts2[0] is empty
											smallparts = parts2[1].split("[")
											smallparts2 = smallparts[1].split("]")
											pickupfrom = smallparts2[0].lower()
											pickupfound = True
											if (pickupfrom.find("+") > -1):
												pickupfields = pickupfrom.split("+")
												if pickupfields[1].lower in allregs:
													pickupfound = False
													shortest_pickup = 0
											if (pickupfrom.find("-") > -1):
												pickupfields = pickupfrom.split("-")
												if pickupfields[1].lower in allregs:
													pickupfound = False
													shortest_pickup = 0		
								if pickupfound:
									movechain = []
									movechain1 = getGadgetMoveRegToReg(interimreg,targetreg,suggestions,interestinggadgets)
									movechain2 = getGadgetMoveRegToReg(topickupreg,interimreg,suggestions,interestinggadgets)
									break
									
	if shortest_pickup > 0:
		# put a value in a register
		if targetval > 0:
			poproutine = putValueInReg(pickupfrom,targetval,freetext,suggestions,interestinggadgets,criteria)
			for popsteps in poproutine:
				pickupchain.append([popsteps[0],popsteps[1],popsteps[2]])
		else:
			pickupchain.append([0,"[-] Unable to find API pointer -> " + pickupfrom,0])
		# pickup
		junksize = getJunk(interestinggadgets[shortest_pickup])
		pickupchain.append([shortest_pickup,"",junksize])
		# move if needed
		if len(movechain) > 0:
			for movesteps in movechain:
				pickupchain.append([movesteps[0],movesteps[1],movesteps[2]])
		
		if len(movechain2) > 0:
			for movesteps in movechain2:
				pickupchain.append([movesteps[0],movesteps[1],movesteps[2]])
		
		if len(movechain1) > 0:
			for movesteps in movechain1:
				pickupchain.append([movesteps[0],movesteps[1],movesteps[2]])
	elif (routine.lower() == "virtualalloc" or routine.lower() == "virtualprotect"):
		# use alternative technique, in case of virtualprotect/virtualalloc routine
		if "pop " + targetreg in suggestions and "pop eax" in suggestions:
			# find a jmp [eax]
			pattern = "jmp [eax]"
			base = 0
			top = TOP_USERLAND
			type = "instr"
			al = criteria["accesslevel"]
			criteria["accesslevel"] = "X"
			global ptr_to_get
			global ptr_counter
			ptr_counter = 0				
			ptr_to_get = 5
			theptr = 0
			global silent
			oldsilent = silent
			silent=True				
			allpointers = findPattern(modulecriteria,criteria,pattern,type,base,top)
			silent = oldsilent
			criteria["accesslevel"] = al
			thismodname = ""
			if len(allpointers) > 0:
				for ptrtype in allpointers:
					for ptrs in allpointers[ptrtype]:
						theptr = ptrs
						thismodname = MnPointer(theptr).belongsTo()
						break
			if theptr > 0:
				popptrtar = getShortestGadget(suggestions["pop "+targetreg])
				popptreax = getShortestGadget(suggestions["pop eax"])
				junksize = getJunk(interestinggadgets[popptrtar])-4
				pickupchain.append([popptrtar,"",junksize])
				pickupchain.append([theptr,"JMP [EAX] [" + thismodname + "]",0])
				junksize = getJunk(interestinggadgets[popptreax])-4
				pickupchain.append([popptreax,"",junksize])
				pickupchain.append([targetval,freetext,0])
				disablelist.append("eax")
				pickupfound = True	

	if not pickupfound:
		pickupchain.append([0,"[-] Unable to find gadgets to pickup the desired API pointer into " + targetreg,0])
		pickupchain.append([targetval,freetext,0])
		
	return pickupchain,disablelist
	
def getRopFuncPtr(apiname,modulecriteria,criteria,mode, objprogressfile, progressfile):
	"""
	Will get a pointer to pointer to the given API name in the IAT of the selected modules
	
	Arguments :
	apiname : the name of the function
	modulecriteria & criteria : module/pointer criteria
	
	Returns :
	a pointer (integer value, 0 if no pointer was found)
	text (with optional info)
	"""
	global silent
	oldsilent = silent
	silent = True
	global ptr_to_get
	ptr_to_get = -1	
	rfuncsearch = apiname.lower()
    
	selectedmodules = False
	if "modules" in modulecriteria:
		if len(modulecriteria["modules"]) > 0:
			selectedmodules = True

	arrfuncsearch = [rfuncsearch]
	if rfuncsearch == "virtualloc":
		arrfuncsearch.append("virtuallocstub")
	
	ropfuncptr = 0
	ropfuncoffsets = {}
	ropfunctext = "ptr to &" + apiname + "()"
	objprogressfile.write("  * Ropfunc - Looking for %s (IAT) - modulecriteria: %s" % (ropfunctext, modulecriteria), progressfile)
	if mode == "iat":
		if rfuncsearch != "":
			ropfuncs,ropfuncoffsets = findROPFUNC(modulecriteria,criteria, [rfuncsearch])
		else:
			ropfuncs,ropfuncoffsets = findROPFUNC(modulecriteria)
		silent = oldsilent
		#first look for good one
		objprogressfile.write("  * Ropfunc - Found %d pointers" % len(ropfuncs), progressfile)
		for ropfunctypes in ropfuncs:
			#dbg.log("Ropfunc - %s %s" % (ropfunctypes, rfuncsearch))
			if ropfunctypes.lower().find(rfuncsearch) > -1 and ropfunctypes.lower().find("rebased") == -1:
				ropfuncptr = ropfuncs[ropfunctypes][0]
				break
                
		if ropfuncptr == 0:
			for ropfunctypes in ropfuncs:
				if ropfunctypes.lower().find(rfuncsearch) > -1:
					ropfuncptr = ropfuncs[ropfunctypes][0]
					break
		#dbg.log("Ropfunc - Selected pointer: 0x%08x" % ropfuncptr)
        
		#haven't found pointer, and you were looking at specific modules only? remove module restriction, but still exclude ASLR/rebase
		if (ropfuncptr == 0) and selectedmodules:
			objprogressfile.write("  * Ropfunc - No results yet, expanding search to all non ASLR/rebase modules", progressfile)
			oldsilent = silent
			silent = True
			limitedmodulecriteria = {}
			limitedmodulecriteria["aslr"] = False
			limitedmodulecriteria["rebase"] = False
			limitedmodulecriteria["os"] = False
			ropfuncs,ropfuncoffsets = findROPFUNC(limitedmodulecriteria,criteria)
			silent = oldsilent
			for ropfunctypes in ropfuncs:
				#dbg.log("Ropfunc - %s %s" % (ropfunctypes, rfuncsearch))
				if ropfunctypes.lower().find(rfuncsearch) > -1 and ropfunctypes.lower().find("rebased") == -1:
					ropfuncptr = ropfuncs[ropfunctypes][0]
					break
                
		#still haven't found ? clear out modulecriteria, include ASLR/rebase modules (but not OS modules)
		if (ropfuncptr == 0) and not selectedmodules:
			objprogressfile.write("  * Ropfunc - Still no results, now going to search in all application modules", progressfile)
			oldsilent = silent
			silent = True
			limitedmodulecriteria = {}
			# search in anything except known OS modules - bad idea anyway
			limitedmodulecriteria["os"] = False
			ropfuncs2,ropfuncoffsets2 = findROPFUNC(limitedmodulecriteria,criteria)
			silent = oldsilent
			for ropfunctypes in ropfuncs2:
				if ropfunctypes.lower().find(rfuncsearch) > -1 and ropfunctypes.lower().find("rebased") == -1:
					ropfuncptr = ropfuncs2[ropfunctypes][0]
					ropfunctext += " (skipped module criteria, check if pointer is reliable !)"
					break	
		
		if ropfuncptr == 0:
			ropfunctext = "[-] Unable to find ptr to &" + apiname+"()"
		else:
			ropfptrmodname = MnPointer(ropfuncptr).belongsTo()
			tmod = MnModule(ropfptrmodname)					
			ropfptrmodinfo = getGadgetAddressInfo(ropfuncptr)
			ropfunctext += " [IAT " + ropfptrmodname  + "]" + ropfptrmodinfo
	else:
		# read EAT
		modulestosearch = getModulesToQuery(modulecriteria)
		for mod in modulestosearch:
			tmod = MnModule(mod)
			funcs = tmod.getEAT()
			for func in funcs:
				funcname = funcs[func].lower()
				if funcname.find(rfuncsearch) > -1:
					ropfuncptr = func
					break
		if ropfuncptr == 0:
			ropfunctext = "[-] Unable to find required API pointer"
	return ropfuncptr,ropfunctext

	
def putValueInReg(reg,value,freetext,suggestions,interestinggadgets,criteria):

	putchain = []
	allownull = True
	popptr = 0
	gadgetfound = False
	
	offset = 0
	if "+" in reg:
		try:
			rval = reg.split("+")[1].strip("h")
			offset = int(rval,16) * (-1)
			reg = reg.split("+")[0]
		except:
			reg = reg.split("+")[0]
			offset = 0
	elif "-" in reg:
		try:
			rval = reg.split("-")[1].strip("h")
			offset = int(rval,16)
			reg = reg.split("-")[0]
		except:
			reg = reg.split("-")[0]
			offset = 0
			
	if value != 0:	
		value = value + offset

	if value < 0:
		value = 0xffffffff + value + 1
		
	negvalue = 4294967296 - value
	
	ptrval = MnPointer(value)	
	
	if meetsCriteria(ptrval,criteria):
		# easy way - just pop it into a register
		for poptype in suggestions:
			if poptype.find("pop "+reg) == 0:
				popptr = getShortestGadget(suggestions[poptype])
				junksize = getJunk(interestinggadgets[popptr])-4
				putchain.append([popptr,"",junksize])
				putchain.append([value,freetext,0])
				gadgetfound = True
				break
		if not gadgetfound:
			# move
			for movetype in suggestions:
				if movetype.startswith("move") and movetype.endswith("-> " + reg):
					# get "from" reg
					fromreg = movetype.split(" ")[1].lower()
					for poptype in suggestions:
						if poptype.find("pop "+fromreg) == 0:
							popptr = getShortestGadget(suggestions[poptype])
							junksize = getJunk(interestinggadgets[popptr])-4
							putchain.append([popptr,"",junksize])
							putchain.append([value,freetext,0])
							moveptr = getShortestGadget(suggestions[movetype])
							movechain = getGadgetMoveRegToReg(fromreg,reg,suggestions,interestinggadgets)
							for movesteps in movechain:
								putchain.append([movesteps[0],movesteps[1],movesteps[2]])
							gadgetfound = True
							break
					if gadgetfound:
						break
	if not gadgetfound or not meetsCriteria(ptrval,criteria):
		if meetsCriteria(MnPointer(negvalue),criteria):
			if "pop " + reg in suggestions and "neg "+reg in suggestions:
				popptr = getShortestGadget(suggestions["pop "+reg])
				junksize = getJunk(interestinggadgets[popptr])-4
				putchain.append([popptr,"",junksize])
				putchain.append([negvalue,"Value to negate, will become 0x" + toHex(value),0])
				negptr = getShortestGadget(suggestions["neg "+reg])
				junksize = getJunk(interestinggadgets[negptr])
				putchain.append([negptr,"",junksize])
				gadgetfound = True
			if not gadgetfound:
				for movetype in suggestions:
					if movetype.startswith("move") and movetype.endswith("-> " + reg):
						fromreg = movetype.split(" ")[1]
						if "pop " + fromreg in suggestions and "neg " + fromreg in suggestions:
							popptr = getShortestGadget(suggestions["pop "+fromreg])
							junksize = getJunk(interestinggadgets[popptr])-4
							putchain.append([popptr,"",junksize])
							putchain.append([negvalue,"Value to negate, will become 0x" + toHex(value)])
							negptr = getShortestGadget(suggestions["neg "+fromreg])
							junksize = getJunk(interestinggadgets[negptr])
							putchain.append([negptr,"",junksize])
							movechain = getGadgetMoveRegToReg(fromreg,reg,suggestions,interestinggadgets)
							for movesteps in movechain:
								putchain.append([movesteps[0],movesteps[1],movesteps[2]])
							gadgetfound = True
							break
		if not gadgetfound:
			# can we do this using add/sub via another register ?
			for movetype in suggestions:
				if movetype.startswith("move") and movetype.endswith("-> " + reg):
					fromreg = movetype.split(" ")[1]
					if "pop "+ fromreg in suggestions and "add value to " + fromreg in suggestions:
						# check each value & see if delta meets pointer criteria
						#dbg.log("move %s into %s" % (fromreg,reg))
						for addinstr in suggestions["add value to " + fromreg]:
							if not gadgetfound:
								theinstr = interestinggadgets[addinstr][3:len(interestinggadgets[addinstr])]
								#dbg.log("%s" % theinstr)
								instrparts = theinstr.split("#")
								totalvalue = 0
								#gadget might contain multiple add/sub instructions
								for indivinstr in instrparts:
									instrvalueparts = indivinstr.split(',')
									if len(instrvalueparts) > 1:
										# only look at real values
										if isHexValue(instrvalueparts[1].rstrip()):
											thisval = hexStrToInt(instrvalueparts[1])
											if instrvalueparts[0].lstrip().startswith("ADD"):
												totalvalue += thisval
											if instrvalueparts[0].lstrip().startswith("SUB"):
												totalvalue -= thisval
								# subtract totalvalue from target value
								if totalvalue > 0:
									deltaval = value - totalvalue
									if deltaval < 0:
										deltaval = 0xffffffff + deltaval + 1
									deltavalhex = toHex(deltaval)
									if meetsCriteria(MnPointer(deltaval),criteria):
										#dbg.log("   Instruction : %s, Delta : %s, To pop in reg : %s" % (theinstr,toHex(totalvalue),deltavalhex),highlight=1)
										popptr = getShortestGadget(suggestions["pop "+fromreg])
										junksize = getJunk(interestinggadgets[popptr])-4
										putchain.append([popptr,"",junksize])
										putchain.append([deltaval,"put delta into " + fromreg + " (-> put 0x" + toHex(value) + " into " + reg + ")",0])
										junksize = getJunk(interestinggadgets[addinstr])
										putchain.append([addinstr,"",junksize])
										movptr = getShortestGadget(suggestions["move "+fromreg + " -> " + reg])
										junksize = getJunk(interestinggadgets[movptr])
										putchain.append([movptr,"",junksize])
										gadgetfound = True
									
		if not gadgetfound:
			if "pop " + reg in suggestions and "neg "+reg in suggestions and "dec "+reg in suggestions:
				toinc = 0
				while not meetsCriteria(MnPointer(negvalue-toinc),criteria):
					toinc += 1
					if toinc > 250:
						break
				if toinc <= 250:
					popptr = getShortestGadget(suggestions["pop "+reg])
					junksize = getJunk(interestinggadgets[popptr])-4
					putchain.append([popptr,"",junksize])
					putchain.append([negvalue-toinc,"Value to negate, destination value : 0x" + toHex(value),0])
					negptr = getShortestGadget(suggestions["neg "+reg])
					cnt = 0
					decptr = getShortestGadget(suggestions["dec "+reg])
					junksize = getJunk(interestinggadgets[negptr])
					putchain.append([negptr,"",junksize])
					junksize = getJunk(interestinggadgets[decptr])
					while cnt < toinc:
						putchain.append([decptr,"",junksize])
						cnt += 1
					gadgetfound = True
				
			if not gadgetfound:
				for movetype in suggestions:
					if movetype.startswith("move") and movetype.endswith("-> " + reg):
						fromreg = movetype.split(" ")[1]
						if "pop " + fromreg in suggestions and "neg " + fromreg in suggestions and "dec "+fromreg in suggestions:
							toinc = 0							
							while not meetsCriteria(MnPointer(negvalue-toinc),criteria):
								toinc += 1
								if toinc > 250:
									break
							if toinc <= 250:
								popptr = getShortestGadget(suggestions["pop "+fromreg])
								junksize = getJunk(interestinggadgets[popptr])-4
								putchain.append([popptr,"",junksize])
								putchain.append([negvalue-toinc,"Value to negate, destination value : 0x" + toHex(value),0])
								negptr = getShortestGadget(suggestions["neg "+fromreg])
								junksize = getJunk(interestinggadgets[negptr])
								cnt = 0
								decptr = getShortestGadget(suggestions["dec "+fromreg])
								putchain.append([negptr,"",junksize])
								junksize = getJunk(interestinggadgets[decptr])
								while cnt < toinc:
									putchain.append([decptr,"",junksize])
									cnt += 1
								movechain = getGadgetMoveRegToReg(fromreg,reg,suggestions,interestinggadgets)
								for movesteps in movechain:
									putchain.append([movesteps[0],movesteps[1],movesteps[2]])
								gadgetfound = True
								break
							
			if not gadgetfound and "pop " + reg in suggestions and "neg "+reg in suggestions and "inc "+reg in suggestions:
				toinc = 0
				while not meetsCriteria(MnPointer(negvalue-toinc),criteria):
					toinc -= 1
					if toinc < -250:
						break
				if toinc > -250:
					popptr = getShortestGadget(suggestions["pop "+reg])
					junksize = getJunk(interestinggadgets[popptr])-4
					putchain.append([popptr,"",junksize])
					putchain.append([negvalue-toinc,"Value to negate, destination value : 0x" + toHex(value),0])
					negptr = getShortestGadget(suggestions["neg "+reg])
					junksize = getJunk(interestinggadgets[negptr])
					putchain.append([negptr,"",junksize])				
					incptr = getShortestGadget(suggestions["inc "+reg])
					junksize = getJunk(interestinggadgets[incptr])
					while toinc < 0:
						putchain.append([incptr,"",junksize])
						toinc += 1
					gadgetfound = True
				
			if not gadgetfound:
				for movetype in suggestions:
					if movetype.startswith("move") and movetype.endswith("-> " + reg):
						fromreg = movetype.split(" ")[1]
						if "pop " + fromreg in suggestions and "neg " + fromreg in suggestions and "inc "+fromreg in suggestions:
							toinc = 0							
							while not meetsCriteria(MnPointer(negvalue-toinc),criteria):
								toinc -= 1	
								if toinc < -250:
									break
							if toinc > -250:
								popptr = getShortestGadget(suggestions["pop "+fromreg])
								junksize = getJunk(interestinggadgets[popptr])-4
								putchain.append([popptr,""])
								putchain.append([negvalue-toinc,"Value to negate, destination value : 0x" + toHex(value)])
								negptr = getShortestGadget(suggestions["neg "+fromreg])
								junksize = getJunk(interestinggadgets[negptr])
								putchain.append([negptr,"",junksize])							
								decptr = getShortestGadget(suggestions["inc "+fromreg])
								junksize = getJunk(interestinggadgets[incptr])
								while toinc < 0 :
									putchain.append([incptr,"",junksize])
									toinc += 1
								movechain = getGadgetMoveRegToReg(fromreg,reg,suggestions,interestinggadgets)
								for movesteps in movechain:
									putchain.append([movesteps[0],movesteps[1],movesteps[2]])
								gadgetfound = True
								break
							
		if not gadgetfound and "add value to " + reg in suggestions and "pop " + reg in suggestions:
			addtypes = ["ADD","ADC","XOR", "SUB"]
			for addtype in addtypes:
				for ptrs in suggestions["add value to " + reg]:
					thisinstr = interestinggadgets[ptrs]
					thisparts = thisinstr.split("#")
					addinstr = thisparts[1].lstrip().split(",")
					if thisparts[1].startswith(addtype):
						if addtype == "ADD" or addtype == "ADC":
							addvalue = hexStrToInt(addinstr[1])
							delta = value - addvalue
							if delta < 0:
								delta = 0xffffffff + delta + 1
						if addtype == "XOR":
							delta = hexStrToInt(addinstr[1]) ^ value
						if addtype == "SUB":
							addvalue = hexStrToInt(addinstr[1])
							delta = value + addvalue
							if delta < 0:
								delta = 0xffffffff + delta + 1							
						if meetsCriteria(MnPointer(delta),criteria):
							popptr = getShortestGadget(suggestions["pop "+reg])
							junksize = getJunk(interestinggadgets[popptr])-4
							putchain.append([popptr,"",junksize])
							putchain.append([delta,"Diff to desired value",0])
							junksize = getJunk(interestinggadgets[ptrs])
							putchain.append([ptrs,"",junksize])
							gadgetfound = True
							break
							
		if not gadgetfound:
			for movetype in suggestions:
				if movetype.startswith("move") and movetype.endswith("-> " + reg):
					fromreg = movetype.split(" ")[1]		
					if "add value to " + fromreg in suggestions and "pop " + fromreg in suggestions:
						addtypes = ["ADD","ADC","XOR","SUB"]
						for addtype in addtypes:
							for ptrs in suggestions["add value to " + fromreg]:
								thisinstr = interestinggadgets[ptrs]
								thisparts = thisinstr.split("#")
								addinstr = thisparts[1].lstrip().split(",")
								if thisparts[1].startswith(addtype):
									if addtype == "ADD" or addtype == "ADC":
										addvalue = hexStrToInt(addinstr[1])
										delta = value - addvalue
										if delta < 0:
											delta = 0xffffffff + delta + 1
									if addtype == "XOR":
										delta = hexStrToInt(addinstr[1]) ^ value
									if addtype == "SUB":
										addvalue = hexStrToInt(addinstr[1])
										delta = value + addvalue
										if delta < 0:
											delta = 0xffffffff + delta + 1												
									#dbg.log("0x%s : %s, delta : 0x%s" % (toHex(ptrs),thisinstr,toHex(delta)))
									if meetsCriteria(MnPointer(delta),criteria):
										popptr = getShortestGadget(suggestions["pop "+fromreg])
										junksize = getJunk(interestinggadgets[popptr])-4
										putchain.append([popptr,"",junksize])
										putchain.append([delta,"Diff to desired value",0])
										junksize = getJunk(interestinggadgets[ptrs])
										putchain.append([ptrs,"",junksize])
										movechain = getGadgetMoveRegToReg(fromreg,reg,suggestions,interestinggadgets)
										for movesteps in movechain:
											putchain.append([movesteps[0],movesteps[1],movesteps[2]])
										gadgetfound = True
										break
		if not gadgetfound and "inc " + reg in suggestions and value <= 64:
			cnt = 0
			# can we clear the reg ?
			clearsteps = clearReg(reg,suggestions,interestinggadgets)
			for cstep in clearsteps:
				putchain.append([cstep[0],cstep[1],cstep[2]])			
			# inc
			incptr = getShortestGadget(suggestions["inc "+reg])
			junksize = getJunk(interestinggadgets[incptr])
			while cnt < value:
				putchain.append([incptr,"",junksize])
				cnt += 1
			gadgetfound = True
		if not gadgetfound:
			putchain.append([0,"[-] Unable to find gadget to put " + toHex(value) + " into " + reg,0])
	return putchain

def getGadgetMoveRegToReg(fromreg,toreg,suggestions,interestinggadgets):
	movechain = []
	movetype = "move " + fromreg + " -> " + toreg
	if movetype in suggestions:
		moveptr = getShortestGadget(suggestions[movetype])
		moveinstr = interestinggadgets[moveptr].lstrip()
		if moveinstr.startswith("# XOR") or moveinstr.startswith("# OR") or moveinstr.startswith("# AD"):
			clearchain = clearReg(toreg,suggestions,interestinggadgets)
			for cc in clearchain:
				movechain.append([cc[0],cc[1],cc[2]])
		junksize = getJunk(interestinggadgets[moveptr])		
		movechain.append([moveptr,"",junksize])
	else:
		movetype1 = "xor " + fromreg + " -> " + toreg
		movetype2 = "xor " + toreg + " -> " + fromreg
		if movetype1 in suggestions and movetype2 in suggestions:
			moveptr1 = getShortestGadget(suggestions[movetype1])
			junksize = getJunk(interestinggadgets[moveptr1])
			movechain.append([moveptr1,"",junksize])
			moveptr2 = getShortestGadget(suggestions[movetype2])
			junksize = getJunk(interestinggadgets[moveptr2])
			movechain.append([moveptr2,"",junksize])
	return movechain

def clearReg(reg,suggestions,interestinggadgets):
	clearchain = []
	clearfound = False
	if not "clear " + reg in suggestions:
		if not "inc " + reg in suggestions or not "pop " + reg in suggestions:
			# maybe it will work using a move from another register
			for inctype in suggestions:
				if inctype.startswith("inc"):
					increg = inctype.split(" ")[1]
					iptr = getShortestGadget(suggestions["inc " + increg])
					for movetype in suggestions:
						if movetype == "move " + increg + " -> " + reg and "pop " + increg in suggestions:
							moveptr = getShortestGadget(suggestions[movetype])
							moveinstr = interestinggadgets[moveptr].lstrip()
							if not(moveinstr.startswith("# XOR") or moveinstr.startswith("# OR") or moveinstr.startswith("# AD")):
								#kewl
								pptr = getShortestGadget(suggestions["pop " + increg])
								junksize = getJunk(interestinggadgets[pptr])-4
								clearchain.append([pptr,"",junksize])
								clearchain.append([0xffffffff," ",0])
								junksize = getJunk(interestinggadgets[iptr])
								clearchain.append([iptr,"",junksize])
								junksize = getJunk(interestinggadgets[moveptr])
								clearchain.append([moveptr,"",junksize])
								clearfound = True
								break
			if not clearfound:				
				clearchain.append([0,"[-] Unable to find a gadget to clear " + reg,0])
		else:
			#pop FFFFFFFF into reg, then do inc reg => 0
			pptr = getShortestGadget(suggestions["pop " + reg])
			junksize = getJunk(interestinggadgets[pptr])-4
			clearchain.append([pptr,"",junksize])
			clearchain.append([0xffffffff," ",0])
			iptr = getShortestGadget(suggestions["inc " + reg])
			junksize = getJunk(interestinggadgets[iptr])
			clearchain.append([iptr,"",junksize])
	else:
		shortest_clear = getShortestGadget(suggestions["clear " + reg])
		junksize = getJunk(interestinggadgets[shortest_clear])
		clearchain.append([shortest_clear,"",junksize])
	return clearchain
	
def getGadgetValueToReg(reg,value,suggestions,interestinggadgets):
	negfound = False
	blocktxt = ""
	blocktxt2 = ""	
	tonegate = 4294967296 - value
	nregs = ["eax","ebx","ecx","edx","edi"]
	junksize = 0
	junk2size = 0
	negateline = "      0x" + toHex(tonegate)+",  # value to negate, target value : 0x" + toHex(value) + ", target reg : " + reg +"\n"
	if "neg " + reg in suggestions:
		negfound = True
		negptr = getShortestGadget(suggestions["neg " + reg])
		if "pop "+reg in suggestions:
			pptr = getShortestGadget(suggestions["pop " + reg])
			blocktxt2 += "      0x" + toHex(pptr)+",  "+interestinggadgets[pptr].strip()+" ("+MnPointer(pptr).belongsTo()+")\n"					
			blocktxt2 += negateline
			junk2size = getJunk(interestinggadgets[pptr])-4
		else:
			blocktxt2 += "      0x????????,#  find a way to pop the next value into " + reg + "\n"					
			blocktxt2 += negateline			
		blocktxt2 += "      0x" + toHex(negptr)+",  "+interestinggadgets[negptr].strip()+" ("+MnPointer(negptr).belongsTo()+")\n"
		junksize = getJunk(interestinggadgets[negptr])-4
		
	if not negfound:
		nregs.remove(reg)
		for thisreg in nregs:
			if "neg "+ thisreg in suggestions and not negfound:
				blocktxt2 = ""
				junk2size = 0
				negfound = True
				#get pop first
				if "pop "+thisreg in suggestions:
					pptr = getShortestGadget(suggestions["pop " + thisreg])
					blocktxt2 += "      0x" + toHex(pptr)+",  "+interestinggadgets[pptr].strip()+" ("+MnPointer(pptr).belongsTo()+")\n"					
					blocktxt2 += negateline
					junk2size = getJunk(interestinggadgets[pptr])-4
				else:
					blocktxt2 += "      0x????????,#  find a way to pop the next value into "+thisreg+"\n"					
					blocktxt2 += negateline				
				negptr = getShortestGadget(suggestions["neg " + thisreg])
				blocktxt2 += "      0x" + toHex(negptr)+",  "+interestinggadgets[negptr].strip()+" ("+MnPointer(negptr).belongsTo()+")\n"
				junk2size = junk2size + getJunk(interestinggadgets[negptr])-4				
				#now move it to reg
				if "move " + thisreg + " -> " + reg in suggestions:
					bptr = getShortestGadget(suggestions["move " + thisreg + " -> " + reg])
					if interestinggadgets[bptr].strip().startswith("# ADD"):
						if not "clear " + reg in suggestions:
							# other way to clear reg, using pop + inc ?
							if not "inc " + reg in suggestions or not "pop " + reg in suggestions:
								blocktxt2 += "      0x????????,  # find pointer to clear " + reg+"\n"
							else:
								#pop FFFFFFFF into reg, then do inc reg => 0
								pptr = getShortestGadget(suggestions["pop " + reg])
								blocktxt2 += "      0x" + toHex(pptr)+",  "+interestinggadgets[pptr].strip()+" ("+MnPointer(pptr).belongsTo()+")\n"
								blocktxt2 += "      0xffffffff,  # pop value into " + reg + "\n"
								blocktxt2 += createJunk(getJunk(interestinggadgets[pptr])-4)
								iptr = getShortestGadget(suggestions["inc " + reg])
								blocktxt2 += "      0x" + toHex(iptr)+",  "+interestinggadgets[iptr].strip()+" ("+MnPointer(pptr).belongsTo()+")\n"								
								junksize += getJunk(interestinggadgets[iptr])
						else:
							clearptr = getShortestGadget(suggestions["empty " + reg])
							blocktxt2 += "      0x" + toHex(clearptr)+",  "+interestinggadgets[clearptr].strip()+" ("+MnPointer(clearptr).belongsTo()+")\n"	
							junk2size = junk2size + getJunk(interestinggadgets[clearptr])-4
					blocktxt2 += "      0x" + toHex(bptr)+",  "+interestinggadgets[bptr].strip()+" ("+MnPointer(bptr).belongsTo()+")\n"
					junk2size = junk2size + getJunk(interestinggadgets[bptr])-4
				else:
					negfound = False
	if negfound: 
		blocktxt += blocktxt2
	else:
		blocktxt = ""
	junksize = junksize + junk2size
	return blocktxt,junksize

def getOffset(instructions):
	offset = 0
	instrparts = instructions.split("#")
	retpart = instrparts[len(instrparts)-1].strip()
	retparts = retpart.split(" ")
	if len(retparts) > 1:
		offset = hexStrToInt(retparts[1])
	return offset
	
def getJunk(instructions):
	junkpop = instructions.count("POP ") * 4
	junkpush = instructions.count("PUSH ") * -4
	junkpushad = instructions.count("PUSHAD ") * -32
	junkpopad = instructions.count("POPAD") * 32
	junkinc = instructions.count("INC ESP") * 1
	junkdec = instructions.count("DEC ESP") * -1
	junkesp = 0
	if instructions.find("ADD ESP,") > -1:
		instparts = instructions.split("#")
		for part in instparts:
			thisinstr = part.strip()
			if thisinstr.startswith("ADD ESP,"):
				value = thisinstr.split(",")
				junkesp += hexStrToInt(value[1])
	if instructions.find("SUB ESP,") > -1:
		instparts = instructions.split("#")
		for part in instparts:
			thisinstr = part.strip()
			if thisinstr.startswith("SUB ESP,"):
				value = thisinstr.split(",")
				junkesp -= hexStrToInt(value[1])
	junk = junkpop + junkpush + junkpopad + junkpushad + junkesp
	return junk

def createJunk(size,message="filler (compensate)",alignsize=0):
	bytecnt = 0
	dword = 0
	junktxt = ""
	while bytecnt < size:
		dword = 0
		junktxt += "      0x"
		while dword < 4 and bytecnt < size :
			junktxt += "41"
			dword += 1
			bytecnt += 1
		junktxt += ","
		junktxt += toSize("",alignsize + 4 - dword)
		junktxt += "  # "+message+"\n"
	return junktxt

	
def getShortestGadget(chaintypedict):
	shortest = 100
	shortestptr = 0
	shortestinstr = "A" * 1000
	thischaindict = chaintypedict.copy()
	#shuffle dict so returning ptrs would be different each time
	while thischaindict:
		typeptr, thisinstr = random.choice(thischaindict.items())
		if thisinstr.startswith("# XOR") or thisinstr.startswith("# OR") or thisinstr.startswith("# AD"):
			thisinstr += "     "	# make sure we don prefer MOV or XCHG
		thiscount = thisinstr.count("#")
		thischaindict.pop(typeptr)
		if thiscount < shortest:
			shortest = thiscount
			shortestptr = typeptr
			shortestinstr = thisinstr
		else:
			if thiscount == shortest:
				if len(thisinstr) < len(shortestinstr):
					shortest = thiscount
					shortestptr = typeptr
					shortestinstr = thisinstr
	return shortestptr

def isInterestingGadget(instructions):
	if isAsciiString(instructions):
		interesting =	[
						"POP E", "XCHG E", "LEA E", "PUSH E", "XOR E", "AND E", "NEG E", 
						"OR E", "ADD E", "SUB E", "INC E", "DEC E", "POPAD", "PUSHAD",
						"SUB A", "ADD A", "NOP", "ADC E",
						"SUB BH", "SUB BL", "ADD BH", "ADD BL", 
						"SUB CH", "SUB CL", "ADD CH", "ADD CL",
						"SUB DH", "SUB DL", "ADD DH", "ADD DL",
						"MOV E", "CLC", "CLD", "FS:", "FPA", "TEST "
						]
		notinteresting = [ "MOV ESP,EBP", "LEA ESP"	]
		subregs = ["EAX","ECX","EDX","EBX","EBP","ESI","EDI"]
		regs = dbglib.Registers32BitsOrder
		individual = instructions.split("#")
		cnt = 0
		allgood = True
		toskip = False
		while (cnt < len(individual)-1) and allgood:	# do not check last one, which is the ending instruction
			thisinstr = individual[cnt].strip().upper()
			if thisinstr != "":
				toskip = False
				foundinstruction = False
				for notinterest in notinteresting:
					if thisinstr.find(notinterest) > -1:
						toskip= True 
				if not toskip:
					for interest in interesting:
						if thisinstr.find(interest) > -1:
							foundinstruction = True
					if not foundinstruction:
						#check the conditional instructions
						if thisinstr.find("MOV DWORD PTR DS:[E") > -1:
							thisinstrparts = thisinstr.split(",")
							if len(thisinstrparts) > 1:
								if thisinstrparts[1] in regs:
									foundinstruction = True
						# other exceptions - don't combine ADD BYTE or ADD DWORD with XCHG EAX,ESI - EAX may not be writeable
						#if instructions.strip().startswith("# XCHG") and (thisinstr.find("ADD DWORD") > -1 or thisinstr.find("ADD BYTE") > -1) and not instructions.strip().startswith("# XCHG EAX,ESI") :
							# allow - tricky case, but sometimes needed
						#	foundinstruction = True
					allgood = foundinstruction
				else:
					allgood = False
			cnt += 1
		return allgood
	return False
	
def isInterestingJopGadget(instructions):
	interesting =	[
					"POP E", "XCHG E", "LEA E", "PUSH E", "XOR E", "AND E", "NEG E", 
					"OR E", "ADD E", "SUB E", "INC E", "DEC E", "POPAD", "PUSHAD",
					"SUB A", "ADD A", "NOP", "ADC E",
					"SUB BH", "SUB BL", "ADD BH", "ADD BL", 
					"SUB CH", "SUB CL", "ADD CH", "ADD CL",
					"SUB DH", "SUB DL", "ADD DH", "ADD DL",
					"MOV E", "CLC", "CLD", "FS:", "FPA"
					]
	notinteresting = [ "MOV ESP,EBP", "LEA ESP"	]
	regs = dbglib.Registers32BitsOrder
	individual = instructions.split("#")
	cnt = 0
	allgood = True
	popfound = False
	toskip = False
	# what is the jmp instruction ?
	lastinstruction = individual[len(individual)-1].replace("[","").replace("+"," ").replace("]","").strip()
	
	jmp = lastinstruction.split(' ')[1].strip().upper().replace(" ","")
	
	regs = ["EAX","EBX","ECX","EDX","ESI","EDI","EBP","ESP"]
	regs.remove(jmp)
	if jmp != "ESP":
		if instructions.find("POP "+jmp) > -1:
			popfound=True
		else:
			for reg in regs:
				poploc = instructions.find("POP "+reg)
				if (poploc > -1):
					if (instructions.find("MOV "+reg+","+jmp) > poploc) or (instructions.find("XCHG "+reg+","+jmp) > poploc) or (instructions.find("XCHG "+jmp+","+reg) > poploc):
						popfound = True
		allgood = popfound
	return allgood

def readGadgetsFromFile(filename):
	"""
	Reads a mona/msf generated rop file 
	
	Arguments :
	filename - the full path + filename of the source file
	
	Return :
	dictionary containing the gadgets (grouped by ending type)
	"""
	
	readopcodes = {}
	
	srcfile = open(filename,"rb")
	content = srcfile.readlines()
	srcfile.close()
	msffiledetected = False
	#what kind of file do we have
	for thisLine in content:
		if thisLine.find("mod:") > -1 and thisLine.find("ver:") > -1 and thisLine.find("VA") > -1:
			msffiledetected = True
			break
	if msffiledetected:
		dbg.log("[+] Importing MSF ROP file...")
		addrline = 0
		ending = ""
		thisinstr = ""
		thisptr = ""
		for thisLine in content:
			if thisLine.find("[addr:") == 0:
				thisLineparts = thisLine.split("]")
				if addrline == 0:	
					thisptr = hexStrToInt(thisLineparts[0].replace("[addr: ",""))
				thisLineparts = thisLine.split("  ")
				thisinstrpart = thisLineparts[len(thisLineparts)-1].upper().strip()
				if thisinstrpart != "":
					thisinstr += " # " + thisinstrpart
					ending = thisinstrpart
				addrline += 1
			else:
				addrline = 0
				if thisptr != "" and ending != "" and thisinstr != "":
					if not ending in readopcodes:
						readopcodes[ending] = [thisptr,thisinstr]
					else:
						readopcodes[ending] += ([thisptr,thisinstr])
				thisptr = ""
				ending = ""
				thisinstr = ""
		
	else:
		dbg.log("[+] Importing Mona legacy ROP file...")
		for thisLine in content:
			if isAsciiString(thisLine.replace("\r","").replace("\n","")):
				refpointer,instr = splitToPtrInstr(thisLine)
				if refpointer != -1:
					#get ending
					instrparts = instr.split("#")
					ending = instrparts[len(instrparts)-1]
					if not ending in readopcodes:
						readopcodes[ending] = [refpointer,instr]
					else:
						readopcodes[ending] += ([refpointer,instr])
	return readopcodes
	
def isGoodGadgetPtr(gadget,criteria):
	if gadget in CritCache:
		return CritCache[gadget]
	else:
		gadgetptr = MnPointer(gadget)
		status = meetsCriteria(gadgetptr,criteria)
		CritCache[gadget] = status
		return status
		
def getStackPivotDistance(gadget,distance=0):
	offset = 0
	distance_str = str(distance).lower()
	mindistance = 0
	maxdistance = 0

	if "," not in distance_str:
		# only mindistance
		maxdistance = 99999999
		mindistance = to_int(distance_str)
	else:
		mindistance, maxdistance = distance_str.split(",")
		mindistance = to_int(mindistance)
		maxdistance = to_int(maxdistance)

	gadgets = filter(lambda x: x.strip(), gadget.split(" # "))

	for g in gadgets:
		if "ADD ESP," in g:
			offset += hexStrToInt(g.split(",")[1])
		elif "SUB ESP," in g:
			offset += hexStrToInt(g.split(",")[1])
		elif "INC ESP" in g:
			offset += 1
		elif "DEC ESP" in g:
			offset -= 1
		elif "POP " in g:
			offset += 4
		elif "PUSH " in g:
			offset -= 4
		elif "POPAD" in g:
			offset += 32
		elif "PUSHAD" in g:
			offset -= 32
		elif ("DWORD PTR" in g or "[" in g) and "FS" not in g:
			return 0

	if mindistance <= offset and offset <= maxdistance:
		return offset
	else:
		return 0
		
def isGoodGadgetInstr(instruction):
	if isAsciiString(instruction):
		forbidden = [
					"???", "LEAVE", "JMP ", "CALL ", "JB ", "JL ", "JE ", "JNZ ", 
					"JGE ", "JNS ","SAL ", "LOOP", "LOCK", "BOUND", "SAR", "IN ", 
					"OUT ", "RCL", "RCR", "ROL", "ROR", "SHL", "SHR", "INT", "JECX",
					"JNP", "JPO", "JPE", "JCXZ", "JA", "JB", "JNA", "JNB", "JC", "JNC",
					"JG", "JLE", "MOVS", "CMPS", "SCAS", "LODS", "STOS", "REP", "REPE",
					"REPZ", "REPNE", "REPNZ", "LDS", "FST", "FIST", "FMUL", "FDIVR",
					"FSTP", "FST", "FLD", "FDIV", "FXCH", "JS ", "FIDIVR", "SBB",
					"SALC", "ENTER", "CWDE", "FCOM", "LAHF", "DIV", "JO", "OUT", "IRET",
					"FILD", "RETF","HALT","HLT","AAM","FINIT","INT3"
					]
		for instr in forbidden:
			if instruction.upper().find(instr) > -1:
				return False
		return True
	return False
	
def isGoodJopGadgetInstr(instruction):
	if isAsciiString(instruction):
		forbidden = [
					"???", "LEAVE", "RETN", "CALL ", "JB ", "JL ", "JE ", "JNZ ", 
					"JGE ", "JNS ","SAL ", "LOOP", "LOCK", "BOUND", "SAR", "IN ", 
					"OUT ", "RCL", "RCR", "ROL", "ROR", "SHL", "SHR", "INT", "JECX",
					"JNP", "JPO", "JPE", "JCXZ", "JA", "JB", "JNA", "JNB", "JC", "JNC",
					"JG", "JLE", "MOVS", "CMPS", "SCAS", "LODS", "STOS", "REP", "REPE",
					"REPZ", "REPNE", "REPNZ", "LDS", "FST", "FIST", "FMUL", "FDIVR",
					"FSTP", "FST", "FLD", "FDIV", "FXCH", "JS ", "FIDIVR", "SBB",
					"SALC", "ENTER", "CWDE", "FCOM", "LAHF", "DIV", "JO", "OUT", "IRET",
					"FILD", "RETF","HALT","HLT","AAM","FINIT"
					]
		for instr in forbidden:
			if instruction.upper().find(instr) > -1:
				return False
		return True	
	return False

def isGadgetEnding(instruction,endings,verbosity=False):
	for ending in endings:
		if instruction.lower().find(ending.lower()) > -1:
			return True
	return False

def getRopSuggestion(ropchains,allchains):
	suggestions={}
	# pushad
	# ======================
	regs = ["EAX","EBX","ECX","EDX","EBP","ESI","EDI"]
	pushad_allowed = [ "INC ","DEC ","OR ","XOR ","LEA ","ADD ","SUB ", "PUSHAD", "RETN ", "NOP", "POP ","PUSH EAX","PUSH EDI","ADC ","FPATAN","MOV E" , "TEST ", "CMP "]
	for r in regs:
		pushad_allowed.append("MOV "+r+",DWORD PTR DS:[ESP")	#stack
		pushad_allowed.append("MOV "+r+",DWORD PTR SS:[ESP")	#stack
		pushad_allowed.append("MOV "+r+",DWORD PTR DS:[ESI")	#virtualprotect
		pushad_allowed.append("MOV "+r+",DWORD PTR SS:[ESI")	#virtualprotect
		pushad_allowed.append("MOV "+r+",DWORD PTR DS:[EBP")	#stack
		pushad_allowed.append("MOV "+r+",DWORD PTR SS:[EBP")	#stack
		for r2 in regs:
			pushad_allowed.append("MOV "+r+","+r2)
			pushad_allowed.append("XCHG "+r+","+r2)
			pushad_allowed.append("LEA "+r+","+r2)
	pushad_notallowed = ["POP ESP","POPAD","PUSH ESP","MOV ESP","ADD ESP", "INC ESP","DEC ESP","XOR ESP","LEA ESP","SS:","DS:"]
	for gadget in ropchains:
		gadgetinstructions = ropchains[gadget].strip()
		if gadgetinstructions.find("PUSHAD") == 2:
			# does chain only contain allowed instructions
			# one pop is allowed, as long as it's not pop esp
			# push edi and push eax are allowed too (ropnop)
			if gadgetinstructions.count("POP ") < 2 and suggestedGadgetCheck(gadgetinstructions,pushad_allowed,pushad_notallowed):
				toadd={}
				toadd[gadget] = gadgetinstructions
				if not "pushad" in suggestions:
					suggestions["pushad"] = toadd
				else:
					suggestions["pushad"] = mergeOpcodes(suggestions["pushad"],toadd)
	# pick up a pointer
	# =========================
	pickedupin = []
	resulthash = ""
	allowedpickup = True
	for r in regs:
		for r2 in regs:
			pickup_allowed = ["NOP","RETN ","INC ","DEC ","OR ","XOR ","MOV ","LEA ","ADD ","SUB ","POP","ADC ","FPATAN", "TEST ", "CMP "]
			pickup_target = []
			pickup_notallowed = []
			pickup_allowed.append("MOV "+r+",DWORD PTR SS:["+r2+"]")
			pickup_allowed.append("MOV "+r+",DWORD PTR DS:["+r2+"]")
			pickup_target.append("MOV "+r+",DWORD PTR SS:["+r2+"]")
			pickup_target.append("MOV "+r+",DWORD PTR DS:["+r2+"]")
			pickup_notallowed = ["POP "+r, "MOV "+r+",E", "LEA "+r+",E", "MOV ESP", "XOR ESP", "LEA ESP", "MOV DWORD PTR", "DEC ESP"]
			for gadget in ropchains:
				gadgetinstructions = ropchains[gadget].strip()	
				allowedpickup = False
				for allowed in pickup_target:
					if gadgetinstructions.find(allowed) == 2 and gadgetinstructions.count("DWORD PTR") == 1:
						allowedpickup = True
						break
				if allowedpickup:
					if suggestedGadgetCheck(gadgetinstructions,pickup_allowed,pickup_notallowed):
						toadd={}
						toadd[gadget] = gadgetinstructions
						resulthash = "pickup pointer into "+r.lower()
						if not resulthash in suggestions:
							suggestions[resulthash] = toadd
						else:
							suggestions[resulthash] = mergeOpcodes(suggestions[resulthash],toadd)
						if not r in pickedupin:
							pickedupin.append(r)
	if len(pickedupin) == 0:
		for r in regs:
			for r2 in regs:
				pickup_allowed = ["NOP","RETN ","INC ","DEC ","OR ","XOR ","MOV ","LEA ","ADD ","SUB ","POP", "ADC ","FPATAN", "TEST ", "CMP "]
				pickup_target = []
				pickup_notallowed = []
				pickup_allowed.append("MOV "+r+",DWORD PTR SS:["+r2+"+")
				pickup_allowed.append("MOV "+r+",DWORD PTR DS:["+r2+"+")
				pickup_target.append("MOV "+r+",DWORD PTR SS:["+r2+"+")
				pickup_target.append("MOV "+r+",DWORD PTR DS:["+r2+"+")
				pickup_notallowed = ["POP "+r, "MOV "+r+",E", "LEA "+r+",E", "MOV ESP", "XOR ESP", "LEA ESP", "MOV DWORD PTR"]
				for gadget in ropchains:
					gadgetinstructions = ropchains[gadget].strip()	
					allowedpickup = False
					for allowed in pickup_target:
						if gadgetinstructions.find(allowed) == 2 and gadgetinstructions.count("DWORD PTR") == 1:
							allowedpickup = True
							break
					if allowedpickup:
						if suggestedGadgetCheck(gadgetinstructions,pickup_allowed,pickup_notallowed):
							toadd={}
							toadd[gadget] = gadgetinstructions
							resulthash = "pickup pointer into "+r.lower()
							if not resulthash in suggestions:
								suggestions[resulthash] = toadd
							else:
								suggestions[resulthash] = mergeOpcodes(suggestions[resulthash],toadd)
							if not r in pickedupin:
								pickedupin.append(r)
	# move pointer into another pointer
	# =================================
	for reg in regs:	#from
		for reg2 in regs:	#to
			if reg != reg2:
				moveptr_allowed = ["NOP","RETN","POP ","INC ","DEC ","OR ","XOR ","ADD ","PUSH ","AND ", "XCHG ", "ADC ","FPATAN", "TEST ", "CMP "]
				moveptr_notallowed = ["POP "+reg2,"MOV "+reg2+",","XCHG "+reg2+",","XOR "+reg2,"LEA "+reg2+",","AND "+reg2,"DS:","SS:","PUSHAD","POPAD", "DEC ESP"]
				suggestions = mergeOpcodes(suggestions,getRegToReg("MOVE",reg,reg2,ropchains,moveptr_allowed,moveptr_notallowed))
				# if we didn't find any, expand the search
				if not ("move " + reg + " -> " + reg2).lower() in suggestions:
					moveptr_allowed = ["NOP","RETN","POP ","INC ","DEC ","OR ","XOR ","ADD ","PUSH ","AND ", "XCHG ", "ADC ","FPATAN", "TEST ", "CMP "]
					moveptr_notallowed = ["POP "+reg2,"MOV "+reg2+",","XCHG "+reg2+",","XOR "+reg2,"LEA "+reg2+",","AND "+reg2,"PUSHAD","POPAD", "DEC ESP"]
					suggestions = mergeOpcodes(suggestions,getRegToReg("MOVE",reg,reg2,ropchains,moveptr_allowed,moveptr_notallowed))
				
		reg2 = "ESP"	#special case
		if reg != reg2:
			moveptr_allowed = ["NOP","RETN","POP ","INC ","DEC ","OR ","XOR ","ADD ","PUSH ","AND ", "MOV ", "XCHG ", "ADC ", "TEST ", "CMP "]
			moveptr_notallowed = ["ADD "+reg2, "ADC "+reg2, "POP "+reg2,"MOV "+reg2+",","XCHG "+reg2+",","XOR "+reg2,"LEA "+reg2+",","AND "+reg2,"DS:","SS:","PUSHAD","POPAD", "DEC ESP"]
			suggestions = mergeOpcodes(suggestions,getRegToReg("MOVE",reg,reg2,ropchains,moveptr_allowed,moveptr_notallowed))
			
	# xor pointer into another pointer
	# =================================
	for reg in regs:	#from
		for reg2 in regs:	#to
			if reg != reg2:
				xorptr_allowed = ["NOP","RETN","POP ","INC ","DEC ","OR ","XOR ","ADD ","PUSH ","AND ", "XCHG ", "ADC ","FPATAN", "TEST ", "CMP "]
				xorptr_notallowed = ["POP "+reg2,"MOV "+reg2+",","XCHG "+reg2+",","XOR "+reg2,"LEA "+reg2+",","AND "+reg2,"DS:","SS:","PUSHAD","POPAD", "DEC ESP"]
				suggestions = mergeOpcodes(suggestions,getRegToReg("XOR",reg,reg2,ropchains,xorptr_allowed,xorptr_notallowed))

	# get stack pointer
	# =================
	for reg in regs:
		moveptr_allowed = ["NOP","RETN","POP ","INC ","DEC ","OR ","XOR ","ADD ","PUSH ","AND ","MOV ", "ADC ","FPATAN", "TEST ", "CMP "]
		moveptr_notallowed = ["POP ESP","MOV ESP,","XCHG ESP,","XOR ESP","LEA ESP,","AND ESP", "ADD ESP", "],","SUB ESP","OR ESP"]
		moveptr_notallowed.append("POP "+reg)
		moveptr_notallowed.append("MOV "+reg)
		moveptr_notallowed.append("XCHG "+reg)
		moveptr_notallowed.append("XOR "+reg)
		moveptr_notallowed.append("LEA "+reg)
		moveptr_notallowed.append("AND "+reg)
		suggestions = mergeOpcodes(suggestions,getRegToReg("MOVE","ESP",reg,allchains,moveptr_allowed,moveptr_notallowed))
	# add something to register
	# =========================
	for reg in regs:	#from
		for reg2 in regs:	#to
			if reg != reg2:
				moveptr_allowed = ["NOP","RETN","POP ","INC ","DEC ","OR ","XOR ","ADD ","PUSH ","AND ", "ADC ","FPATAN", "TEST ", "CMP "]
				moveptr_notallowed = ["POP "+reg2,"MOV "+reg2+",","XCHG "+reg2+",","XOR "+reg2,"LEA "+reg2+",","AND "+reg2,"DS:","SS:", "DEC ESP"]
				suggestions = mergeOpcodes(suggestions,getRegToReg("ADD",reg,reg2,ropchains,moveptr_allowed,moveptr_notallowed))
	# add value to register
	# =========================
	for reg in regs:	#to
		moveptr_allowed = ["NOP","RETN","POP ","INC ","DEC ","OR ","XOR ","ADD ","PUSH ","AND ", "ADC ", "SUB ","FPATAN", "TEST ", "CMP "]
		moveptr_notallowed = ["POP "+reg,"MOV "+reg+",","XCHG "+reg+",","XOR "+reg,"LEA "+reg+",","DS:","SS:", "DEC ESP"]
		suggestions = mergeOpcodes(suggestions,getRegToReg("ADDVAL",reg,reg,ropchains,moveptr_allowed,moveptr_notallowed))	

	#inc reg
	# =======
	for reg in regs:
		moveptr_allowed = ["NOP","RETN","POP ","INC " + reg,"DEC ","OR ","XOR ","ADD ","PUSH ","AND ", "ADC ", "SUB ","FPATAN", "TEST ", "CMP "]
		moveptr_notallowed = ["POP "+reg,"MOV "+reg+",","XCHG "+reg+",","XOR "+reg,"LEA "+reg+",","DS:","SS:", "DEC ESP", "DEC "+reg]
		suggestions = mergeOpcodes(suggestions,getRegToReg("INC",reg,reg,ropchains,moveptr_allowed,moveptr_notallowed))
		
	#dec reg
	# =======
	for reg in regs:
		moveptr_allowed = ["NOP","RETN","POP ","DEC " + reg,"INC ","OR ","XOR ","ADD ","PUSH ","AND ", "ADC ", "SUB ","FPATAN", "TEST ", "CMP "]
		moveptr_notallowed = ["POP "+reg,"MOV "+reg+",","XCHG "+reg+",","XOR "+reg,"LEA "+reg+",","DS:","SS:", "DEC ESP", "INC "+reg]
		suggestions = mergeOpcodes(suggestions,getRegToReg("DEC",reg,reg,ropchains,moveptr_allowed,moveptr_notallowed))	
	#popad reg
	# =======
	popad_allowed = ["POPAD","RETN","INC ","DEC ","OR ","XOR ","ADD ","AND ", "ADC ", "SUB ","FPATAN","POP ", "TEST ", "CMP "]
	popad_notallowed = ["POP ESP","PUSH ESP","MOV ESP","ADD ESP", "INC ESP","DEC ESP","XOR ESP","LEA ESP","SS:","DS:"]
	for gadget in ropchains:
		gadgetinstructions = ropchains[gadget].strip()
		if gadgetinstructions.find("POPAD") == 2:
			if suggestedGadgetCheck(gadgetinstructions,popad_allowed,popad_notallowed):
				toadd={}
				toadd[gadget] = gadgetinstructions
				if not "popad" in suggestions:
					suggestions["popad"] = toadd
				else:
					suggestions["popad"] = mergeOpcodes(suggestions["popad"],toadd)				
	# pop
	# ===
	for reg in regs:
		pop_allowed = "POP "+reg+" # RETN"
		pop_notallowed = []
		for gadget in ropchains:
			gadgetinstructions = ropchains[gadget].strip()
			if gadgetinstructions.find(pop_allowed) == 2:
				resulthash = "pop "+reg.lower()
				toadd = {}
				toadd[gadget] = gadgetinstructions
				if not resulthash in suggestions:
					suggestions[resulthash] = toadd
				else:
					suggestions[resulthash] = mergeOpcodes(suggestions[resulthash],toadd)
					
	# check if we have a pop for each reg
	for reg in regs:
		r = reg.lower()
		if not "pop "+r in suggestions:
			pop_notallowed = ["MOV "+reg+",","XCHG "+reg+",","XOR "+reg,"LEA "+reg+",","DS:","SS:", "DEC ESP", "DEC "+reg, "INC " + reg,"PUSH ","XOR "+reg]
			for rchain in ropchains:
				rparts = ropchains[rchain].strip().split("#")
				chainok = False
				if rparts[1].strip() == "POP " + reg:
						chainok = True
				if chainok:
					for rpart in rparts:
						thisinstr = rpart.strip()
						for pna in pop_notallowed:
							if thisinstr.find(pna) > -1:
								chainok = False
								break
				if chainok:
					toadd = {}
					toadd[rchain] = thisinstr				
					if not "pop " + r in suggestions:
						suggestions["pop " + r] = toadd
					else:
						suggestions["pop " + r] = mergeOpcodes(suggestions["pop " + r],toadd)
	# neg
	# ===
	for reg in regs:
		neg_allowed = "NEG "+reg+" # RETN"
		neg_notallowed = []
		for gadget in ropchains:
			gadgetinstructions = ropchains[gadget].strip()
			if gadgetinstructions.find(neg_allowed) == 2:
				resulthash = "neg "+reg.lower()
				toadd = {}
				toadd[gadget] = gadgetinstructions
				if not resulthash in suggestions:
					suggestions[resulthash] = toadd
				else:
					suggestions[resulthash] = mergeOpcodes(suggestions[resulthash],toadd)		
	# empty
	# =====
	for reg in regs:
		empty_allowed = ["XOR "+reg+","+reg+" # RETN","MOV "+reg+",FFFFFFFF # INC "+reg+" # RETN", "SUB "+reg+","+reg+" # RETN", "PUSH 0 # POP "+reg + " # RETN", "IMUL "+reg+","+reg+",0 # RETN"]
		empty_notallowed = []
		for gadget in ropchains:
			gadgetinstructions = ropchains[gadget].strip()
			for empty in empty_allowed:
				if gadgetinstructions.find(empty) == 2:
					resulthash = "clear "+reg.lower()
					toadd = {}
					toadd[gadget] = gadgetinstructions
					if not resulthash in suggestions:
						suggestions[resulthash] = toadd
					else:
						suggestions[resulthash] = mergeOpcodes(suggestions[resulthash],toadd)						
	return suggestions

def getRegToReg(type,fromreg,toreg,ropchains,moveptr_allowed,moveptr_notallowed):
	moveptr = []
	instrwithout = ""
	toreg = toreg.upper()
	srcval = False
	resulthash = ""
	musthave = ""
	if type == "MOVE":
		moveptr.append("MOV "+toreg+","+fromreg)
		moveptr.append("LEA "+toreg+","+fromreg)
		#if not (fromreg == "ESP" or toreg == "ESP"):
		moveptr.append("XCHG "+fromreg+","+toreg)
		moveptr.append("XCHG "+toreg+","+fromreg)
		moveptr.append("PUSH "+fromreg)
		moveptr.append("ADD "+toreg+","+fromreg)
		moveptr.append("ADC "+toreg+","+fromreg)		
		moveptr.append("XOR "+toreg+","+fromreg)
	if type == "XOR":
		moveptr.append("XOR "+toreg+","+fromreg)		
	if type == "ADD":
		moveptr.append("ADD "+toreg+","+fromreg)
		moveptr.append("ADC "+toreg+","+fromreg)		
		moveptr.append("XOR "+toreg+","+fromreg)
	if type == "ADDVAL":
		moveptr.append("ADD "+toreg+",")
		moveptr.append("ADC "+toreg+",")		
		moveptr.append("XOR "+toreg+",")		
		moveptr.append("SUB "+toreg+",")	
		srcval = True
		resulthash = "add value to " + toreg
	if type == "INC":
		moveptr.append("INC "+toreg)
		resulthash = "inc " + toreg
	if type == "DEC":
		moveptr.append("DEC "+toreg)
		resulthash = "dec " + toreg		
	results = {}
	if resulthash == "":
		resulthash = type +" "+fromreg+" -> "+toreg
	resulthash = resulthash.lower()
	for tocheck in moveptr:
		origtocheck = tocheck
		for gadget in ropchains:
			gadgetinstructions = ropchains[gadget].strip()
			if gadgetinstructions.find(tocheck) == 2:
				moveon = True
				if srcval:
					#check if src is a value
					inparts = gadgetinstructions.split(",")
					if len(inparts) > 1:
						subinparts = inparts[1].split(" ")
						if isHexString(subinparts[0].strip()):
							tocheck = tocheck + subinparts[0].strip()
						else:
							moveon = False						
				if moveon:
					instrwithout = gadgetinstructions.replace(tocheck,"")
					if tocheck == "PUSH "+fromreg:
						popreg = instrwithout.find("POP "+toreg)
						popall = instrwithout.find("POP")
						#make sure pop matches push
						nrpush = gadgetinstructions.count("PUSH ")
						nrpop = gadgetinstructions.count("POP ")
						pushpopmatch = False
						if nrpop >= nrpush:
							pushes = []
							pops = []
							ropparts = gadgetinstructions.split(" # ")
							pushindex = 0
							popindex = 0
							cntpush = 0
							cntpop = nrpush
							for parts in ropparts:
								if parts.strip() != "":
									if parts.strip().find("PUSH ") > -1:
										pushes.append(parts)
										if parts.strip() == "PUSH "+fromreg:
											cntpush += 1
									if parts.strip().find("POP ") > -1:
										pops.append(parts)
										if parts.strip() == "POP "+toreg:
											cntpop -= 1
							if cntpush == cntpop:
								#dbg.log("%s : POPS : %d, PUSHES : %d, pushindex : %d, popindex : %d" % (gadgetinstructions,len(pops),len(pushes),pushindex,popindex))
								#dbg.log("push at %d, pop at %d" % (cntpush,cntpop))
								pushpopmatch = True
						if (popreg == popall) and instrwithout.count("POP "+toreg) == 1 and pushpopmatch:
							toadd={}
							toadd[gadget] = gadgetinstructions
							if not resulthash in results:
								results[resulthash] = toadd
							else:
								results[resulthash] = mergeOpcodes(results[resulthash],toadd)
					else:			
						if suggestedGadgetCheck(instrwithout,moveptr_allowed,moveptr_notallowed):
							toadd={}
							toadd[gadget] = gadgetinstructions
							if not resulthash in results:
								results[resulthash] = toadd
							else:
								results[resulthash] = mergeOpcodes(results[resulthash],toadd)
			tocheck = origtocheck
	return results
	
def suggestedGadgetCheck(instructions,allowed,notallowed):
	individual = instructions.split("#")
	cnt = 0
	allgood = True
	toskip = False
	while (cnt < len(individual)-1) and allgood:	# do not check last one, which is the ending instruction
		thisinstr = individual[cnt].upper()
		if thisinstr.strip() != "":
			toskip = False
			foundinstruction = False
			for notok in notallowed:
				if thisinstr.find(notok) > -1:
					toskip= True 
			if not toskip:
				for ok in allowed:
					if thisinstr.find(ok) > -1:
						foundinstruction = True
				allgood = foundinstruction
			else:
				allgood = False
		cnt += 1
	return allgood

def dumpMemoryToFile(address,size,filename):
	"""
	Dump 'size' bytes of memory to a file
	
	Arguments:
	address  - the address where to read
	size     - the number of bytes to read
	filename - the name of the file where to write the file
	
	Return:
	Boolean - True if the write succeeded
	"""

	WRITE_SIZE = 10000
	
	dbg.log("Dumping %d bytes from address 0x%08x to %s..."	% (size, address, filename))
	out = open(filename,'wb')
	
	# write by increments of 10000 bytes
	current = 0
	while current < size :
		bytesToWrite = size - current
		if ( bytesToWrite >= WRITE_SIZE):
			bytes = dbg.readMemory(address+current,WRITE_SIZE)
			out.write(bytes)
			current += WRITE_SIZE
		else:
			bytes = dbg.readMemory(address+current,bytesToWrite)
			out.write(bytes)
			current += bytesToWrite
	out.close()
	
	return True

def checkSEHOverwrite(address, nseh, seh):
	"""
	Checks if the current SEH record is overwritten
	with a cyclic pattern
	Input : address of SEH record, nseh value, seh value
	Returns : array.  Non empty array = SEH is overwritten
	Array contents :
	[0] : type  (normal, upper, lower, unicode)
	[1] : offset to nseh
	"""
	pattypes = ["normal","upper","lower","unicode"]
	overwritten = []
	global silent
	silent = True

	fullpattern = createPattern(50000,{})
	for pattype in pattypes:	
		regpattern = fullpattern
		hexpat = toHex(seh)
		hexpat = toAscii(hexpat[6]+hexpat[7])+toAscii(hexpat[4]+hexpat[5])+toAscii(hexpat[2]+hexpat[3])+toAscii(hexpat[0]+hexpat[1])
		factor = 1
		goback = 4
		if pattype == "upper":
			regpattern = regpattern.upper()
		if pattype == "lower":
			regpattern = regpattern.lower()
		if pattype == "unicode":
			hexpat = dbg.readMemory(address,8)
			hexpat = hexpat.replace('\x00','')
			goback = 2
		offset = regpattern.find(hexpat)-goback
		thissize = 0
		if offset > -1:		
			thepointer = MnPointer(address)
			if thepointer.isOnStack():
				thissize = getPatternLength(address+4,pattype)
				if thissize > 0:
					overwritten = [pattype,offset]
					break
	silent = False
	return overwritten


def goFindMSP(distance = 0,args = {}):
	"""
	Finds all references to cyclic pattern in memory
	
	Arguments:
	None
	
	Return:
	Dictonary with results of the search operation
	"""
	results = {}
	regs = dbg.getRegs()
	criteria = {}
	criteria["accesslevel"] = "*"
	
	tofile = ""
	
	global silent
	oldsilent = silent
	silent=True	
	
	fullpattern = createPattern(50000,args)
	factor = 1
	
	#are we attached to an application ?
	if dbg.getDebuggedPid() == 0:
		dbg.log("*** Attach to an application, and trigger a crash with a cyclic pattern ! ***",highlight=1)
		return	{}
	
	#1. find beging of cyclic pattern in memory ?

	patbegin = createPattern(6,args)
	
	silent=oldsilent
	pattypes = ["normal","unicode","lower","upper"]
	if not silent:
		dbg.log("[+] Looking for cyclic pattern in memory")
	tofile += "[+] Looking for cyclic pattern in memory\n"
	for pattype in pattypes:
		dbg.updateLog()
		searchPattern = []
		#create search pattern
		factor = 1
		if pattype == "normal":
			searchPattern.append([patbegin, patbegin])	
		if pattype == "unicode":
			patbegin_unicode = ""
			factor = 0.5
			for pbyte in patbegin:
				patbegin_unicode += pbyte + "\x00"
			searchPattern.append([patbegin_unicode, patbegin_unicode])	
		if pattype == "lower":
			searchPattern.append([patbegin.lower(), patbegin.lower()])	
		if pattype == "upper":
			searchPattern.append([patbegin.upper(), patbegin.upper()])	
		#search
		pointers = searchInRange(searchPattern,0,TOP_USERLAND,criteria)
		memory={}
		if len(pointers) > 0:
			for ptrtypes in pointers:
				for ptr in pointers[ptrtypes]:
					#get size
					thissize = getPatternLength(ptr,pattype,args)
					if thissize > 0:
						if not silent:
							dbg.log("    Cyclic pattern (%s) found at 0x%s (length %d bytes)" % (pattype,toHex(ptr),thissize))
						tofile += "    Cyclic pattern (%s) found at 0x%s (length %d bytes)\n" % (pattype,toHex(ptr),thissize)
						if not ptr in memory:
							memory[ptr] = ([thissize,pattype])
					#get distance from ESP
					if "ESP" in regs:
						thisesp = regs["ESP"]
						thisptr = MnPointer(ptr)
						if thisptr.isOnStack():
							if ptr > thisesp:
								if not silent:
									dbg.log("    -  Stack pivot between %d & %d bytes needed to land in this pattern" % (ptr-thisesp,ptr-thisesp+thissize))
								tofile += "    -  Stack pivot between %d & %d bytes needed to land in this pattern\n" % (ptr-thisesp,ptr-thisesp+thissize)
			if not "memory" in results:
				results["memory"] = memory
			
	#2. registers overwritten ?
	if not silent:
		dbg.log("[+] Examining registers")
	registers = {}
	registers_to = {}
	for reg in regs:
		for pattype in pattypes:
			dbg.updateLog()		
			regpattern = fullpattern
			hexpat = toHex(regs[reg])
			hexpatr = hexpat
			factor = 1
			hexpat = toAscii(hexpat[6]+hexpat[7])+toAscii(hexpat[4]+hexpat[5])+toAscii(hexpat[2]+hexpat[3])+toAscii(hexpat[0]+hexpat[1])
			hexpatrev = toAscii(hexpatr[0]+hexpatr[1])+toAscii(hexpatr[2]+hexpatr[3])+toAscii(hexpatr[4]+hexpatr[5])+toAscii(hexpatr[6]+hexpatr[7])	
			if pattype == "upper":
				regpattern = regpattern.upper()
			if pattype == "lower":
				regpattern = regpattern.lower()
			if pattype == "unicode":
				regpattern = toUnicode(regpattern)
				factor = 0.5
			offset = regpattern.find(hexpat)
			if offset > -1:
				if pattype == "unicode":
					offset = offset * factor
				if not silent:
					dbg.log("    %s contains %s pattern : 0x%s (offset %d)" % (reg,pattype,toHex(regs[reg]),offset))
				tofile += "    %s contains %s pattern : 0x%s (offset %d)\n" % (reg,pattype,toHex(regs[reg]),offset)
				if not reg in registers:
					registers[reg] = ([regs[reg],offset,pattype])
			else:
				# maybe it's reversed ?
				offset = regpattern.find(hexpatrev)
				if offset > -1:
					if pattype == "unicode":
						offset = offset * factor
					if not silent:
						dbg.log("    %s contains %s pattern (reversed) : 0x%s (offset %d)" % (reg,pattype,toHex(regs[reg]),offset))
					tofile += "    %s contains %s pattern (reversed) : 0x%s (offset %d)\n" % (reg,pattype,toHex(regs[reg]),offset)
					if not reg in registers:
						registers[reg] = ([regs[reg],offset,pattype])				
					
			# maybe register points into cyclic pattern
			mempat = ""
			try:
				mempat = dbg.readMemory(regs[reg],4)
			except:
				pass
			
			if mempat != "":
				if pattype == "normal":
					regpattern = fullpattern
				if pattype == "upper":
					regpattern = fullpattern.upper()
				if pattype == "lower":
					regpattern = fullpattern.lower()
				if pattype == "unicode":
					mempat = dbg.readMemory(regs[reg],8)
					mempat = mempat.replace('\x00','')
					
				offset = regpattern.find(mempat)
				
				if offset > -1:				
					thissize = getPatternLength(regs[reg],pattype,args)
					if thissize > 0:
						if not silent:
							dbg.log("    %s (0x%s) points at offset %d in %s pattern (length %d)" % (reg,toHex(regs[reg]),offset,pattype,thissize))
						tofile += "    %s (0x%s) points at offset %d in %s pattern (length %d)\n" % (reg,toHex(regs[reg]),offset,pattype,thissize)
						if not reg in registers_to:
							registers_to[reg] = ([regs[reg],offset,thissize,pattype])
						else:
							registers_to[reg] = ([regs[reg],offset,thissize,pattype])
				else:
					# reversed ?
					offset = regpattern.find(mempat[::-1])
					if offset > -1:				
						thissize = getPatternLength(regs[reg],pattype,args)
						if thissize > 0:
							if not silent:
								dbg.log("    %s (0x%s) points at offset %d in (reversed) %s pattern (length %d)" % (reg,toHex(regs[reg]),offset,pattype,thissize))
							tofile += "    %s (0x%s) points at offset %d in (reversed) %s pattern (length %d)\n" % (reg,toHex(regs[reg]),offset,pattype,thissize)
							if not reg in registers_to:
								registers_to[reg] = ([regs[reg],offset,thissize,pattype])
							else:
								registers_to[reg] = ([regs[reg],offset,thissize,pattype])					

							
	if not "registers" in results:
		results["registers"] = registers
	if not "registers_to" in results:
		results["registers_to"] = registers_to

	#3. SEH record overwritten ?
	seh = {}
	if not silent:
		dbg.log("[+] Examining SEH chain")
	tofile += "[+] Examining SEH chain\r\n"
	thissehchain=dbg.getSehChain()
	
	for chainentry in thissehchain:
		address = chainentry[0]
		sehandler = chainentry[1]
		nseh = 0
		nsehvalue = 0
		nsehascii = ""
		try:
			nsehascii = dbg.readMemory(address,4)
			nsehvalue = struct.unpack('<L',nsehascii)[0]
			nseh = "%08x" % nsehvalue
		except:
			nseh = 0
			sehandler = 0
		if nseh != 0 :
			for pattype in pattypes:
				dbg.updateLog()		
				regpattern = fullpattern
				hexpat = nsehascii
				factor = 1
				takeout = 4
				divide = 1
				if pattype == "upper":
					regpattern = regpattern.upper()
				if pattype == "lower":
					regpattern = regpattern.lower()
				if pattype == "unicode":
					#get next 4 bytes too
					nsehascii = dbg.readMemory(address,8)
					hexpat = nsehascii.replace('\x00','')
					takeout = 0
					divide = 2
				offset = regpattern.find(hexpat)
				thissize = 0
				if offset > -1:		
					thepointer = MnPointer(chainentry[0])
					if thepointer.isOnStack():
						thissize = getPatternLength(address+4,pattype)
						if thissize > 0:
							thissize = (thissize - takeout)/divide
							if not silent:
								dbg.log("    SEH record (nseh field) at 0x%s overwritten with %s pattern : 0x%s (offset %d), followed by %d bytes of cyclic data after the handler" % (toHex(chainentry[0]),pattype,nseh,offset,thissize))
							tofile += "    SEH record (nseh field) at 0x%s overwritten with %s pattern : 0x%s (offset %d), followed by %d bytes of cyclic data after the handler\n" % (toHex(chainentry[0]),pattype,nseh,offset,thissize)
							if not chainentry[0]+4 in seh:
								seh[chainentry[0]+4] = ([chainentry[1],offset,pattype,thissize])
							
							
	if not "seh" in results:
		results["seh"] = seh

	stack = {}	
	stackcontains = {}
	
	#4. walking stack
	if "ESP" in regs:	
		curresp = regs["ESP"]	
		if not silent:
			if distance == 0:
				extratxt = "(entire stack)"
			else:
				extratxt = "(+- "+str(distance)+" bytes)"
			dbg.log("[+] Examining stack %s - looking for cyclic pattern" % extratxt)
		tofile += "[+] Examining stack %s - looking for cyclic pattern\n" % extratxt
		
		# get stack this address belongs to
		stacks = getStacks()
		thisstackbase = 0
		thisstacktop = 0
		if distance < 1:
			for tstack in stacks:
				if (stacks[tstack][0] < curresp) and (curresp < stacks[tstack][1]):
					thisstackbase = stacks[tstack][0]
					thisstacktop = stacks[tstack][1]
		else:
			thisstackbase = curresp - distance
			thisstacktop = curresp + distance + 8
		stackcounter = thisstackbase
		sign=""

	
		if not silent:
			dbg.log("    Walking stack from 0x%s to 0x%s (0x%s bytes)" % (toHex(stackcounter),toHex(thisstacktop-4),toHex(thisstacktop-4-stackcounter)))
		tofile += "    Walking stack from 0x%s to 0x%s (0x%s bytes)\n" % (toHex(stackcounter),toHex(thisstacktop-4),toHex(thisstacktop-4-stackcounter))

		# stack contains part of a cyclic pattern ?
		while stackcounter < thisstacktop-4:
			espoffset = stackcounter - curresp
			stepsize = 4
			dbg.updateLog()	
			if espoffset > -1:
				sign="+"			
			else:
				sign="-"	
				
			cont = dbg.readMemory(stackcounter,4)
			
			if len(cont) == 4:
				contat = cont
				if contat != "":
		
					for pattype in pattypes:
						dbg.updateLog()
						regpattern = fullpattern
						
						hexpat = contat
					
						if pattype == "upper":
							regpattern = regpattern.upper()
						if pattype == "lower":
							regpattern = regpattern.lower()
						if pattype == "unicode":
							hexpat1 = dbg.readMemory(stackcounter,4)
							hexpat2 = dbg.readMemory(stackcounter+4,4)
							hexpat1 = hexpat1.replace('\x00','')
							hexpat2 = hexpat2.replace('\x00','')
							if hexpat1 == "" or hexpat2 == "":
								#no unicode
								hexpat = ""
								break
							else:
								hexpat = hexpat1 + hexpat2
						
						if len(hexpat) == 4:
							
							offset = regpattern.find(hexpat)
							
							currptr = stackcounter
							
							if offset > -1:				
								thissize = getPatternLength(currptr,pattype)
								offsetvalue = int(str(espoffset).replace("-",""))								
								if thissize > 0:
									stepsize = thissize
									if thissize/4*4 != thissize:
										stepsize = (thissize/4*4) + 4
									# align stack again
									if not silent:
										espoff = 0
										espsign = "+"
										if ((stackcounter + thissize) >= curresp):
											espoff = (stackcounter + thissize) - curresp
										else:
											espoff = curresp - (stackcounter + thissize)
											espsign = "-"											
										dbg.log("    0x%s : Contains %s cyclic pattern at ESP%s0x%s (%s%s) : offset %d, length %d (-> 0x%s : ESP%s0x%s)" % (toHex(stackcounter),pattype,sign,rmLeading(toHex(offsetvalue),"0"),sign,offsetvalue,offset,thissize,toHex(stackcounter+thissize-1),espsign,rmLeading(toHex(espoff),"0")))
									tofile += "    0x%s : Contains %s cyclic pattern at ESP%s0x%s (%s%s) : offset %d, length %d (-> 0x%s : ESP%s0x%s)\n" % (toHex(stackcounter),pattype,sign,rmLeading(toHex(offsetvalue),"0"),sign,offsetvalue,offset,thissize,toHex(stackcounter+thissize-1),espsign,rmLeading(toHex(espoff),"0"))
									if not currptr in stackcontains:
										stackcontains[currptr] = ([offsetvalue,sign,offset,thissize,pattype])
								else:
									#if we are close to ESP, change stepsize to 1
									if offsetvalue <= 256:
										stepsize = 1
			stackcounter += stepsize
			

			
		# stack has pointer into cyclic pattern ?
		if not silent:
			if distance == 0:
				extratxt = "(entire stack)"
			else:
				extratxt = "(+- "+str(distance)+" bytes)"
			dbg.log("[+] Examining stack %s - looking for pointers to cyclic pattern" % extratxt)	
		tofile += "[+] Examining stack %s - looking for pointers to cyclic pattern\n" % extratxt
		# get stack this address belongs to
		stacks = getStacks()
		thisstackbase = 0
		thisstacktop = 0
		if distance < 1:
			for tstack in stacks:
				if (stacks[tstack][0] < curresp) and (curresp < stacks[tstack][1]):
					thisstackbase = stacks[tstack][0]
					thisstacktop = stacks[tstack][1]
		else:
			thisstackbase = curresp - distance
			thisstacktop = curresp + distance + 8
		stackcounter = thisstackbase
		sign=""		
		
		if not silent:
			dbg.log("    Walking stack from 0x%s to 0x%s (0x%s bytes)" % (toHex(stackcounter),toHex(thisstacktop-4),toHex(thisstacktop-4-stackcounter)))
		tofile += "    Walking stack from 0x%s to 0x%s (0x%s bytes)\n" % (toHex(stackcounter),toHex(thisstacktop-4),toHex(thisstacktop-4-stackcounter))
		while stackcounter < thisstacktop-4:
			espoffset = stackcounter - curresp
			
			dbg.updateLog()	
			if espoffset > -1:
				sign="+"			
			else:
				sign="-"	
				
			cont = dbg.readMemory(stackcounter,4)
			
			if len(cont) == 4:
				cval=""				
				for sbytes in cont:
					tval = hex(ord(sbytes)).replace("0x","")
					if len(tval) < 2:
						tval="0"+tval
					cval = tval+cval
				try:				
					contat = dbg.readMemory(hexStrToInt(cval),4)
				except:
					contat = ""	
					
				if contat != "":
					for pattype in pattypes:
						dbg.updateLog()
						regpattern = fullpattern
						
						hexpat = contat
					
						if pattype == "upper":
							regpattern = regpattern.upper()
						if pattype == "lower":
							regpattern = regpattern.lower()
						if pattype == "unicode":
							hexpat1 = dbg.readMemory(stackcounter,4)
							hexpat2 = dbg.readMemory(stackcounter+4,4)
							hexpat1 = hexpat1.replace('\x00','')
							hexpat2 = hexpat2.replace('\x00','')
							if hexpat1 == "" or hexpat2 == "":
								#no unicode
								hexpat = ""
								break
							else:
								hexpat = hexpat1 + hexpat2
						
						if len(hexpat) == 4:
							offset = regpattern.find(hexpat)
							currptr = hexStrToInt(cval)
							
							if offset > -1:				
								thissize = getPatternLength(currptr,pattype)
								if thissize > 0:
									offsetvalue = int(str(espoffset).replace("-",""))
									if not silent:
										dbg.log("    0x%s : Pointer into %s cyclic pattern at ESP%s0x%s (%s%s) : 0x%s : offset %d, length %d" % (toHex(stackcounter),pattype,sign,rmLeading(toHex(offsetvalue),"0"),sign,offsetvalue,toHex(currptr),offset,thissize))
									tofile += "    0x%s : Pointer into %s cyclic pattern at ESP%s0x%s (%s%s) : 0x%s : offset %d, length %d\n" % (toHex(stackcounter),pattype,sign,rmLeading(toHex(offsetvalue),"0"),sign,offsetvalue,toHex(currptr),offset,thissize)
									if not currptr in stack:
										stack[currptr] = ([offsetvalue,sign,offset,thissize,pattype])					
							
			stackcounter += 4
	else:
		dbg.log("** Are you connected to an application ?",highlight=1)
		
	if not "stack" in results:
		results["stack"] = stack
	if not "stackcontains" in results:
		results["stackcontains"] = stack
		
	if tofile != "":
		objfindmspfile = MnLog("findmsp.txt")
		findmspfile = objfindmspfile.reset()
		objfindmspfile.write(tofile,findmspfile)
	return results
	
	
#-----------------------------------------------------------------------#
# convert arguments to criteria
#-----------------------------------------------------------------------#

def args2criteria(args,modulecriteria,criteria):

	thisversion,thisrevision = getVersionInfo(inspect.stack()[0][1])
	thisversion = thisversion.replace("'","")
	dbg.logLines("\n---------- Mona command started on %s (v%s, rev %s) ----------" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),thisversion,thisrevision))
	dbg.log("[+] Processing arguments and criteria")
	global ptr_to_get
	
	# meets access level ?
	criteria["accesslevel"] = "X"
	if "x" in args : 
		if not args["x"].upper() in ["*","R","RW","RX","RWX","W","WX","X"]:
			dbg.log("invalid access level : %s" % args["x"], highlight=1)
			criteria["accesslevel"] = ""
		else:
			criteria["accesslevel"] = args["x"].upper()
		
	dbg.log("    - Pointer access level : %s" % criteria["accesslevel"])
	
	# query OS modules ?
	if "o" in args and args["o"]:
		modulecriteria["os"] = False
		dbg.log("    - Ignoring OS modules")
	
	# allow nulls ?
	if "n" in args and args["n"]:
		criteria["nonull"] = True
		dbg.log("    - Ignoring pointers that have null bytes")
	
	# override list of modules to query ?
	if "m" in args:
		if type(args["m"]).__name__.lower() != "bool":
			modulecriteria["modules"] = args["m"]
			dbg.log("    - Only querying modules %s" % args["m"])
				
	# limit nr of pointers to search ?
	if "p" in args:
		if str(args["p"]).lower() != "true":
			ptr_to_get = int(args["p"].strip())
		if ptr_to_get > 0:	
			dbg.log("    - Maximum nr of pointers to return : %d" % ptr_to_get)
	
	# only want to see specific type of pointers ?
	if "cp" in args:
		ptrcriteria = args["cp"].split(",")
		for ptrcrit in ptrcriteria:
			ptrcrit=ptrcrit.strip("'")
			ptrcrit=ptrcrit.strip('"').lower().strip()
			criteria[ptrcrit] = True
		dbg.log("    - Pointer criteria : %s" % ptrcriteria)
	
	if "cbp" in args:
		dbg.log("    * Trying to use '-cbp' instead of '-cpb'?", highlight=True)
		if not "cpb" in args:
			dbg.log("    * I'll try to fix your typo myself, but please pay attention to the syntax next time", highlight=True)
			args["cpb"] = args["cbp"]
	
	if "cpb" in args:
		badchars = args["cpb"]
		badchars = badchars.replace("'","")
		badchars = badchars.replace('"',"")
		badchars = badchars.replace("\\x","")
		# see if we need to expand ..
		bpos = 0
		newbadchars = ""
		while bpos < len(badchars):
			curchar = badchars[bpos]+badchars[bpos+1]
			if curchar == "..":
				pos = bpos
				if pos > 1 and pos <= len(badchars)-4:
					# get byte before and after ..
					bytebefore = badchars[pos-2] + badchars[pos-1]
					byteafter = badchars[pos+2] + badchars[pos+3]
					bbefore = int(bytebefore,16)
					bafter = int(byteafter,16)
					insertbytes = ""
					bbefore += 1
					while bbefore < bafter:
						insertbytes += "%02x" % bbefore
						bbefore += 1
					newbadchars += insertbytes
			else:
				newbadchars += curchar
			bpos += 2
		badchars = newbadchars
		cnt = 0
		strb = ""
		while cnt < len(badchars):
			strb=strb+binascii.a2b_hex(badchars[cnt]+badchars[cnt+1])
			cnt=cnt+2
		criteria["badchars"] = strb
		dbg.log("    - Bad char filter will be applied to pointers : %s " % args["cpb"])
			
	if "cm" in args:
		modcriteria = args["cm"].split(",")
		for modcrit in modcriteria:
			modcrit=modcrit.strip("'")
			modcrit=modcrit.strip('"').lower().strip()
			#each criterium has 1 or 2 parts : criteria=value
			modcritparts = modcrit.split("=")
			try:
				if len(modcritparts) < 2:
					# set to True, no value given
					modulecriteria[modcritparts[0].strip()] = True
				else:
					# read the value
					modulecriteria[modcritparts[0].strip()] = (modcritparts[1].strip() == "true")
			except:
				continue
		if (inspect.stack()[1][3] == "procShowMODULES"):
			modcriteria = args["cm"].split(",")
			for modcrit in modcriteria:
				modcrit=modcrit.strip("'")
				modcrit=modcrit.strip('"').lower().strip()
				if modcrit.startswith("+"):
					modulecriteria[modcrit]=True
				else:
					modulecriteria[modcrit]=False
		dbg.log("    - Module criteria : %s" % modcriteria)

	return modulecriteria,criteria			
				
	
#manage breakpoint on selected exported/imported functions from selected modules
def doManageBpOnFunc(modulecriteria,criteria,funcfilter,mode="add",type="export"):	
	"""
	Sets a breakpoint on selected exported/imported functions from selected modules
	
	Arguments : 
	modulecriteria - Dictionary
	funcfilter - comma separated string indicating functions to set bp on
			must contains "*" to select all functions
	mode - "add" to create bp's, "del" to remove bp's
	
	Returns : nothing
	"""
	
	type = type.lower()
	
	namecrit = funcfilter.strip('"').strip("'").split(",")
	
	if mode == "add" or mode == "del" or mode == "list":
		if not silent:
			dbg.log("[+] Enumerating %sed functions" % type)
		modulestosearch = getModulesToQuery(modulecriteria)
		
		bpfuncs = {}
		
		for thismodule in modulestosearch:
			if not silent:
				dbg.log(" Querying module %s" % thismodule)
			# get all
			themod = dbg.getModule(thismodule)
			tmod = MnModule(thismodule)
			shortname = tmod.getShortName()
			syms = themod.getSymbols()
			# get funcs
			funcs = {}
			if type == "export":
				funcs = tmod.getEAT()
			else:
				funcs = tmod.getIAT()
			if not silent:
				dbg.log("   Total nr of %sed functions : %d" % (type,len(funcs)))
			for func in funcs:
				if meetsCriteria(MnPointer(func), criteria):
					funcname = funcs[func].lower()
					setbp = False
					if "*" in namecrit:
						setbp = True
					else:
						for crit in namecrit:
							crit = crit.lower()
							tcrit = crit.replace("*","")
							if (crit.startswith("*") and crit.endswith("*")) or (crit.find("*") == -1):
								if funcname.find(tcrit) > -1:
									setbp = True
							elif crit.startswith("*"):
								if funcname.endswith(tcrit):
									setbp = True
							elif crit.endswith("*"):
								if funcname.startswith(tcrit):
									setbp = True
					
					if setbp:
						if type == "export":
							if not func in bpfuncs:
								bpfuncs[func] = funcs[func]
						else:
							ptr = 0
							try:
								#read pointer of imported function
								ptr=struct.unpack('<L',dbg.readMemory(func,4))[0]
							except:
								pass
							if ptr > 0:
								if not ptr in bpfuncs:
									bpfuncs[ptr] = funcs[func]
			if __DEBUGGERAPP__ == "WinDBG":
				# let's do a few searches
				for crit in namecrit:
					if crit.find("*") == -1:
						crit = "*" + crit + "*"
					modsearch = "x %s!%s" % (shortname,crit)
					output = dbg.nativeCommand(modsearch)
					outputlines = output.split("\n")
					for line in outputlines:
						if line.replace(" ","") != "":
							linefields = line.split(" ")
							if len(linefields) > 1:
								ptr = hexStrToInt(linefields[0])
								cnt = 1
								while cnt < len(linefields)-1:
									if linefields[cnt] != "":
										funcname = linefields[cnt]
										break
									cnt += 1
								if not ptr in bpfuncs:
									bpfuncs[ptr] = funcname

		if not silent:
			dbg.log("[+] Total nr of breakpoints to process : %d" % len(bpfuncs))
		if len(bpfuncs) > 0:
			for funcptr in bpfuncs:
				if mode == "add":
					dbg.log("Set bp at 0x%s (%s in %s)" % (toHex(funcptr),bpfuncs[funcptr],MnPointer(funcptr).belongsTo()))
					try:
						dbg.setBreakpoint(funcptr)
					except:
						dbg.log("Failed setting bp at 0x%s" % toHex(funcptr))
				elif mode == "del":
					dbg.log("Remove bp at 0x%s (%s in %s)" % (toHex(funcptr),bpfuncs[funcptr],MnPointer(funcptr).belongsTo()))
					try:
						dbg.deleteBreakpoint(funcptr)
					except:
						dbg.log("Skipped removal of bp at 0x%s" % toHex(funcptr))
				elif mode == "list":
					dbg.log("Match found at 0x%s (%s in %s)" % (toHex(funcptr),bpfuncs[funcptr],MnPointer(funcptr).belongsTo()))
						
	return

#-----------------------------------------------------------------------#
# main
#-----------------------------------------------------------------------#	
				
def main(args):
	dbg.createLogWindow()
	global currentArgs
	currentArgs = copy.copy(args)
	try:
		starttime = datetime.datetime.now()
		ptr_counter = 0
		
		# initialize list of commands
		commands = {}
		
		# ----- HELP ----- #
		def getBanner():
			banners = {}
			bannertext = ""
			bannertext += "    |------------------------------------------------------------------|\n"
			bannertext += "    |                         __               __                      |\n"
			bannertext += "    |   _________  ________  / /___ _____     / /____  ____ _____ ___  |\n"
			bannertext += "    |  / ___/ __ \/ ___/ _ \/ / __ `/ __ \   / __/ _ \/ __ `/ __ `__ \ |\n"
			bannertext += "    | / /__/ /_/ / /  /  __/ / /_/ / / / /  / /_/  __/ /_/ / / / / / / |\n"
			bannertext += "    | \___/\____/_/   \___/_/\__,_/_/ /_/   \__/\___/\__,_/_/ /_/ /_/  |\n"
			bannertext += "    |                                                                  |\n"
			bannertext += "    |     https://www.corelan.be | https://www.corelan-training.com    |\n"
			bannertext += "    |------------------------------------------------------------------|\n"
			banners[0] = bannertext

			bannertext = ""
			bannertext += "    |------------------------------------------------------------------|\n"			
			bannertext += "    |        _ __ ___    ___   _ __    __ _     _ __   _   _           |\n"
			bannertext += "    |       | '_ ` _ \  / _ \ | '_ \  / _` |   | '_ \ | | | |          |\n"
			bannertext += "    |       | | | | | || (_) || | | || (_| | _ | |_) || |_| |          |\n"
			bannertext += "    |       |_| |_| |_| \___/ |_| |_| \__,_|(_)| .__/  \__, |          |\n"
			bannertext += "    |                                          |_|     |___/           |\n"
			bannertext += "    |                                                                  |\n"
			bannertext += "    |------------------------------------------------------------------|\n"	
			banners[1] = bannertext

			bannertext = ""
			bannertext += "    |------------------------------------------------------------------|\n"
			bannertext += "    |                                                                  |\n"
			bannertext += "    |    _____ ___  ____  ____  ____ _                                 |\n"
			bannertext += "    |    / __ `__ \/ __ \/ __ \/ __ `/  https://www.corelan.be         |\n"
			bannertext += "    |   / / / / / / /_/ / / / / /_/ /  https://www.corelan-training.com|\n"
			bannertext += "    |  /_/ /_/ /_/\____/_/ /_/\__,_/  #corelan (Freenode IRC)          |\n"
			bannertext += "    |                                                                  |\n"
			bannertext += "    |------------------------------------------------------------------|\n"
			banners[2] = bannertext

			bannertext = ""
			bannertext += "\n    .##.....##..#######..##....##....###........########..##....##\n"
			bannertext += "    .###...###.##.....##.###...##...##.##.......##.....##..##..##.\n"
			bannertext += "    .####.####.##.....##.####..##..##...##......##.....##...####..\n"
			bannertext += "    .##.###.##.##.....##.##.##.##.##.....##.....########.....##...\n"
			bannertext += "    .##.....##.##.....##.##..####.#########.....##...........##...\n"
			bannertext += "    .##.....##.##.....##.##...###.##.....##.###.##...........##...\n"
			bannertext += "    .##.....##..#######..##....##.##.....##.###.##...........##...\n\n"
			banners[3] = bannertext


			# pick random banner
			bannerlist = []
			for i in range (0, len(banners)):
				bannerlist.append(i)

			random.shuffle(bannerlist)
			return banners[bannerlist[0]]

		
		def procHelp(args):
			dbg.log("     'mona' - Exploit Development Swiss Army Knife - %s (%sbit)" % (__DEBUGGERAPP__,str(arch)))
			dbg.log("     Plugin version : %s r%s" % (__VERSION__,__REV__))
			dbg.log("     Python version : %s" % (getPythonVersion()))
			if __DEBUGGERAPP__ == "WinDBG":
				pykdversion = dbg.getPyKDVersionNr()
				dbg.log("     PyKD version %s" % pykdversion)
			dbg.log("     Written by Corelan - https://www.corelan.be")
			dbg.log("     Project page : https://github.com/corelan/mona")
			dbg.logLines(getBanner(),highlight=1)
			dbg.log("Global options :")
			dbg.log("----------------")
			dbg.log("You can use one or more of the following global options on any command that will perform")
			dbg.log("a search in one or more modules, returning a list of pointers :")
			dbg.log(" -n                     : Skip modules that start with a null byte. If this is too broad, use")
			dbg.log("                          option -cp nonull instead")
			dbg.log(" -o                     : Ignore OS modules")
			dbg.log(" -p <nr>                : Stop search after <nr> pointers.")
			dbg.log(" -m <module,module,...> : only query the given modules. Be sure what you are doing !")
			dbg.log("                          You can specify multiple modules (comma separated)")
			dbg.log("                          Tip : you can use -m *  to include all modules. All other module criteria will be ignored")
			dbg.log("                          Other wildcards : *blah.dll = ends with blah.dll, blah* = starts with blah,")
			dbg.log("                          blah or *blah* = contains blah")
			dbg.log(" -cm <crit,crit,...>    : Apply some additional criteria to the modules to query.")
			dbg.log("                          You can use one or more of the following criteria :")
			dbg.log("                          aslr,safeseh,rebase,nx,os")
			dbg.log("                          You can enable or disable a certain criterium by setting it to true or false")
			dbg.log("                          Example :  -cm aslr=true,safeseh=false")
			dbg.log("                          Suppose you want to search for p/p/r in aslr enabled modules, you could call")
			dbg.log("                          !mona seh -cm aslr")
			dbg.log(" -cp <crit,crit,...>    : Apply some criteria to the pointers to return")
			dbg.log("                          Available options are :")
			dbg.log("                          unicode,ascii,asciiprint,upper,lower,uppernum,lowernum,numeric,alphanum,nonull,startswithnull,unicoderev")
			dbg.log("                          Note : Multiple criteria will be evaluated using 'AND', except if you are looking for unicode + one crit")
			dbg.log(" -cpb '\\x00\\x01'        : Provide list with bad chars, applies to pointers")
			dbg.log("                          You can use .. to indicate a range of bytes (in between 2 bad chars)")
			dbg.log(" -x <access>            : Specify desired access level of the returning pointers. If not specified,")
			dbg.log("                          only executable pointers will be returned.")
			dbg.log("                          Access levels can be one of the following values : R,W,X,RW,RX,WX,RWX or *")
			
			if not args:
				args = []
			if len(args) > 1:
				thiscmd = args[1].lower().strip()
				if thiscmd in commands:
					dbg.log("")
					dbg.log("Usage of command '%s' :" % thiscmd)
					dbg.log("%s" % ("-" * (22 + len(thiscmd))))
					dbg.logLines(commands[thiscmd].usage)
					dbg.log("")
				else:
					aliasfound = False
					for cmd in commands:
						if commands[cmd].alias == thiscmd:
							dbg.log("")
							dbg.log("Usage of command '%s' :" % thiscmd)
							dbg.log("%s" % ("-" * (22 + len(thiscmd))))
							dbg.logLines(commands[cmd].usage)
							dbg.log("")
							aliasfound = True
					if not aliasfound:
						dbg.logLines("\nCommand %s does not exist. Run !mona to get a list of available commands\n" % thiscmd,highlight=1)
			else:
				dbg.logLines("\nUsage :")
				dbg.logLines("-------\n")
				dbg.log(" !mona <command> <parameter>")
				dbg.logLines("\nAvailable commands and parameters :\n")

				items = commands.items()
				items.sort(key = itemgetter(0))
				for item in items:
					if commands[item[0]].usage != "":
						aliastxt = ""
						if commands[item[0]].alias != "":
							aliastxt = " / " + commands[item[0]].alias
						dbg.logLines("%s | %s" % (item[0] + aliastxt + (" " * (20 - len(item[0]+aliastxt))), commands[item[0]].description))
				dbg.log("")
				dbg.log("Want more info about a given command ?  Run !mona help <command>",highlight=1)
				dbg.log("")
		
		commands["help"] = MnCommand("help", "show help", "!mona help [command]",procHelp)
		
		# ----- Config file management ----- #
		
		def procConfig(args):
			#did we specify -get, -set or -add?
			showerror = False
			if not "set" in args and not "get" in args and not "add" in args:
				showerror = True
				
			if "set" in args:
				if type(args["set"]).__name__.lower() == "bool":
					showerror = True
				else:
					#count nr of words
					params = args["set"].split(" ")
					if len(params) < 2:
						showerror = True
			if "add" in args:
				if type(args["add"]).__name__.lower() == "bool":
					showerror = True
				else:
					#count nr of words
					params = args["add"].split(" ")
					if len(params) < 2:
						showerror = True
			if "get" in args:
				if type(args["get"]).__name__.lower() == "bool":
					showerror = True
				else:
					#count nr of words
					params = args["get"].split(" ")
					if len(params) < 1:
						showerror = True
			if showerror:
				dbg.log("Usage :")
				dbg.logLines(configUsage,highlight=1)
				return
			else:
				if "get" in args:
					dbg.log("Reading value from configuration file")
					monaConfig = MnConfig()
					thevalue = monaConfig.get(args["get"])
					dbg.log("Parameter %s = %s" % (args["get"],thevalue))
				
				if "set" in args:
					dbg.log("Writing value to configuration file")
					monaConfig = MnConfig()
					value = args["set"].split(" ")
					configparam = value[0].strip()
					dbg.log("Old value of parameter %s = %s" % (configparam,monaConfig.get(configparam)))
					configvalue = args["set"][0+len(configparam):len(args["set"])]
					monaConfig.set(configparam,configvalue)
					dbg.log("New value of parameter %s = %s" % (configparam,configvalue))
				
				if "add" in args:
					dbg.log("Writing value to configuration file")
					monaConfig = MnConfig()
					value = args["add"].split(" ")
					configparam = value[0].strip()
					dbg.log("Old value of parameter %s = %s" % (configparam,monaConfig.get(configparam)))
					configvalue = monaConfig.get(configparam).strip() + "," + args["add"][0+len(configparam):len(args["add"])].strip()
					monaConfig.set(configparam,configvalue)
					dbg.log("New value of parameter %s = %s" % (configparam,configvalue))
				
		# ----- Jump to register ----- #
	
		def procFindJ(args):
			return procFindJMP(args)
		
		def procFindJMP(args):
			#default criteria
			modulecriteria={}
			modulecriteria["aslr"] = False
			modulecriteria["rebase"] = False
			
			if (inspect.stack()[1][3] == "procFindJ"):
				dbg.log(" ** Note : command 'j' has been replaced with 'jmp'. Now launching 'jmp' instead...",highlight=1)

			criteria={}
			all_opcodes={}
			
			global ptr_to_get
			ptr_to_get = -1
			
			distancestr = ""
			mindistance = 0
			maxdistance = 0
			
			#did user specify -r <reg> ?
			showerror = False
			if "r" in args:
				if type(args["r"]).__name__.lower() == "bool":
					showerror = True
				else:
					#valid register ?
					thisreg = args["r"].upper().strip()
					validregs = dbglib.Registers32BitsOrder
					if not thisreg in validregs:
						showerror = True
			else:
				showerror = True
				
			if "distance" in args:
				if type(args["distance"]).__name__.lower() == "bool":
					showerror = True
				else:
					distancestr = args["distance"]
					distanceparts = distancestr.split(",")
					for parts in distanceparts:
						valueparts = parts.split("=")
						if len(valueparts) > 1:
							if valueparts[0].lower() == "min":
								try:
									mindistance = int(valueparts[1])
								except:
									mindistance = 0		
							if valueparts[0].lower() == "max":
								try:
									maxdistance = int(valueparts[1])
								except:
									maxdistance = 0						
			
			if maxdistance < mindistance:
				tmp = maxdistance
				maxdistance = mindistance
				mindistance = tmp
			
			criteria["mindistance"] = mindistance
			criteria["maxdistance"] = maxdistance
			
			
			if showerror:
				dbg.log("Usage :")
				dbg.logLines(jmpUsage,highlight=1)
				return				
			else:
				modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
				# go for it !	
				all_opcodes=findJMP(modulecriteria,criteria,args["r"].lower().strip())
			
			# write to log
			logfile = MnLog("jmp.txt")
			thislog = logfile.reset()
			processResults(all_opcodes,logfile,thislog)
		
		# ----- Exception Handler Overwrites ----- #
		
					
		def procFindSEH(args):
			#default criteria
			modulecriteria={}
			modulecriteria["safeseh"] = False
			modulecriteria["aslr"] = False
			modulecriteria["rebase"] = False

			criteria = {}
			specialcases = {}
			all_opcodes = {}
			
			global ptr_to_get
			ptr_to_get = -1
			
			#what is the caller function (backwards compatibility with pvefindaddr)
			
			modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)

			if "rop" in args:
				criteria["rop"] = True
			
			if "all" in args:
				criteria["all"] = True
				specialcases["maponly"] = True
			else:
				criteria["all"] = False
				specialcases["maponly"] = False
			
			# go for it !	
			all_opcodes = findSEH(modulecriteria,criteria)
			#report findings to log
			logfile = MnLog("seh.txt")
			thislog = logfile.reset()
			processResults(all_opcodes,logfile,thislog,specialcases)
			
			
		# ----- MODULES ------ #
		def procShowMODULES(args):
			modulecriteria={}
			criteria={}
			
			modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
			modulestosearch = getModulesToQuery(modulecriteria)
			showModuleTable("",modulestosearch)

		# ----- ROP ----- #
		def procFindROPFUNC(args):
			#default criteria
			modulecriteria={}
			modulecriteria["aslr"] = False
			#modulecriteria["rebase"] = False
			modulecriteria["os"] = False
			criteria={}
			
			modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
			ropfuncs = {}
			ropfuncoffsets ={}
			ropfuncs,ropfuncoffsets = findROPFUNC(modulecriteria,criteria)
			#report findings to log
			dbg.log("[+] Processing pointers to interesting rop functions")
			logfile = MnLog("ropfunc.txt")
			thislog = logfile.reset()
			processResults(ropfuncs,logfile,thislog)
			global silent
			silent = True
			dbg.log("[+] Processing offsets to pointers to interesting rop functions")
			logfile = MnLog("ropfunc_offset.txt")
			thislog = logfile.reset()
			processResults(ropfuncoffsets,logfile,thislog)			
			
		def procStackPivots(args):
			procROP(args,"stackpivot")
			
		def procROP(args,mode="all"):
			#default criteria
			modulecriteria={}
			modulecriteria["aslr"] = False
			modulecriteria["rebase"] = False
			modulecriteria["os"] = False

			criteria={}
			
			modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
			
			# handle optional arguments
			
			depth = 6
			maxoffset = 40
			thedistance = 8
			split = False
			fast = False
			sortedprint = False
			endingstr = ""
			endings = []
			technique = ""            
			
			if "depth" in args:
				if type(args["depth"]).__name__.lower() != "bool":
					try:
						depth = int(args["depth"])
					except:
						pass
			
			if "offset" in args:
				if type(args["offset"]).__name__.lower() != "bool":
					try:
						maxoffset = int(args["offset"])
					except:
						pass
			
			if "distance" in args:
				if type(args["distance"]).__name__.lower() != "bool":
					try:
						thedistance = args["distance"]
					except:
						pass
			
			if "split" in args:
				if type(args["split"]).__name__.lower() == "bool":
					split = args["split"]

			if "s" in args:
				if type(args["s"]).__name__.lower() != "bool":
					technique = args["s"].replace("'","").replace('"',"").strip().lower()                   
					
			if "fast" in args:
				if type(args["fast"]).__name__.lower() == "bool":
					fast = args["fast"]
			
			if "end" in args:
				if type(args["end"]).__name__.lower() == "str":
					endingstr = args["end"].replace("'","").replace('"',"").strip()
					endings = endingstr.split("#")
					
			if "f" in args:
				if args["f"] != "":
					criteria["f"] = args["f"]
			
			if "sort" in args:
				sortedprint = True
			
			if "rva" in args:
				criteria["rva"] = True
			
			if mode == "stackpivot":
				fast = False
				endings = ""
				split = False
			else:
				mode = "all"
			
			findROPGADGETS(modulecriteria,criteria,endings,maxoffset,depth,split,thedistance,fast,mode,sortedprint,technique)
			

		def procJseh(args):
			results = []
			showred=0
			showall=False
			if "all" in args:
				showall = True
			nrfound = 0
			dbg.log("-----------------------------------------------------------------------")
			dbg.log("Search for jmp/call dword[ebp/esp+nn] (and other) combinations started ")
			dbg.log("-----------------------------------------------------------------------")
			opcodej=["\xff\x54\x24\x08", #call dword ptr [esp+08]
					"\xff\x64\x24\x08", #jmp dword ptr [esp+08]
					"\xff\x54\x24\x14", #call dword ptr [esp+14]
					"\xff\x54\x24\x14", #jmp dword ptr [esp+14]
					"\xff\x54\x24\x1c", #call dword ptr [esp+1c]
					"\xff\x54\x24\x1c", #jmp dword ptr [esp+1c]
					"\xff\x54\x24\x2c", #call dword ptr [esp+2c]
					"\xff\x54\x24\x2c", #jmp dword ptr [esp+2c]
					"\xff\x54\x24\x44", #call dword ptr [esp+44]
					"\xff\x54\x24\x44", #jmp dword ptr [esp+44]
					"\xff\x54\x24\x50", #call dword ptr [esp+50]
					"\xff\x54\x24\x50", #jmp dword ptr [esp+50]
					"\xff\x55\x0c",     #call dword ptr [ebp+0c]
					"\xff\x65\x0c",     #jmp dword ptr [ebp+0c]
					"\xff\x55\x24",     #call dword ptr [ebp+24]
					"\xff\x65\x24",     #jmp dword ptr [ebp+24]
					"\xff\x55\x30",     #call dword ptr [ebp+30]
					"\xff\x65\x30",     #jmp dword ptr [ebp+30]
					"\xff\x55\xfc",     #call dword ptr [ebp-04]
					"\xff\x65\xfc",     #jmp dword ptr [ebp-04]
					"\xff\x55\xf4",     #call dword ptr [ebp-0c]
					"\xff\x65\xf4",     #jmp dword ptr [ebp-0c]
					"\xff\x55\xe8",     #call dword ptr [ebp-18]
					"\xff\x65\xe8",     #jmp dword ptr [ebp-18]
					"\x83\xc4\x08\xc3", #add esp,8 + ret
					"\x83\xc4\x08\xc2"] #add esp,8 + ret X
			fakeptrcriteria = {}
			fakeptrcriteria["accesslevel"] = "*"
			for opjc in opcodej:
				addys = []
				addys = searchInRange( [[opjc, opjc]], 0, TOP_USERLAND, fakeptrcriteria)
				results += addys
				for ptrtypes in addys:
					for ad1 in addys[ptrtypes]:
						ptr = MnPointer(ad1)
						module = ptr.belongsTo()
						if not module:
							module=""
							page   = dbg.getMemoryPageByAddress( ad1 )
							access = page.getAccess( human = True )
							op = dbg.disasm( ad1 )
							opstring=op.getDisasm()
							dbg.log("Found %s at 0x%08x - Access: (%s) - Outside of a loaded module" % (opstring, ad1, access), address = ad1,highlight=1)
							nrfound+=1
						else:
							if showall:
								page   = dbg.getMemoryPageByAddress( ad1 )
								access = page.getAccess( human = True )
								op = dbg.disasm( ad1 )
								opstring=op.getDisasm()
								thismod = MnModule(module)
								if not thismod.isSafeSEH:
								#if ismodulenosafeseh(module[0])==1:
									extratext="=== Safeseh : NO ==="
									showred=1
								else:
									extratext="Safeseh protected"
									showred=0
								dbg.log("Found %s at 0x%08x (%s) - Access: (%s) - %s" % (opstring, ad1, module,access,extratext), address = ad1,highlight=showred)
								nrfound+=1
			dbg.log("Search complete")
			if results:
				dbg.log("Found %d address(es)" % nrfound)
				return "Found %d address(es) (Check the log Windows for details)" % nrfound
			else:
				dbg.log("No addresses found")
				return "Sorry, no addresses found"

			
		def procJOP(args,mode="all"):
			#default criteria
			modulecriteria={}
			modulecriteria["aslr"] = False
			modulecriteria["rebase"] = False
			modulecriteria["os"] = False

			criteria={}
			
			modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
			
			# handle optional arguments
			
			depth = 6
			
			if "depth" in args:
				if type(args["depth"]).__name__.lower() != "bool":
					try:
						depth = int(args["depth"])
					except:
						pass			
			findJOPGADGETS(modulecriteria,criteria,depth)			
			
			
		def procCreatePATTERN(args):
			size = 0
			pattern = ""
			if "?" in args and args["?"] != "":
				try:
					if "0x" in args["?"].lower():
						try:
							size = int(args["?"],16)
						except:
							size = 0
					else:
						size = int(args["?"])
				except:
					size = 0
			if size == 0:
				dbg.log("Please enter a valid size",highlight=1)
			else:
				pattern = createPattern(size,args)
				dbg.log("Creating cyclic pattern of %d bytes" % size)				
				dbg.log(pattern)
				global ignoremodules
				ignoremodules = True
				objpatternfile = MnLog("pattern.txt")
				patternfile = objpatternfile.reset()
				# ASCII
				objpatternfile.write("\nPattern of " + str(size) + " bytes :\n",patternfile)
				objpatternfile.write("-" * (19 + len(str(size))),patternfile)
				objpatternfile.write("\nASCII:",patternfile)
				objpatternfile.write("\n" + pattern,patternfile)
				# Hex
				patternhex = ""
				for patternchar in pattern:
					patternhex += str(hex(ord(patternchar))).replace("0x","\\x")
				objpatternfile.write("\n\nHEX:\n",patternfile)
				objpatternfile.write(patternhex,patternfile)
				# Javascript
				patternjs = str2js(pattern)
				objpatternfile.write("\n\nJAVASCRIPT (unescape() friendly):\n",patternfile)
				objpatternfile.write(patternjs,patternfile)
				if not silent:
					dbg.log("Note: don't copy this pattern from the log window, it might be truncated !",highlight=1)
					dbg.log("It's better to open %s and copy the pattern from the file" % patternfile,highlight=1)
				
				ignoremodules = False
			return


		def procOffsetPATTERN(args):
			egg = ""
			if "?" in args and args["?"] != "":
				try:
					egg = args["?"]
				except:
					egg = ""
			if egg == "":
				dbg.log("Please enter a valid target",highlight=1)
			else:
				findOffsetInPattern(egg,-1,args)
			return
		
		# ----- Comparing file output ----- #
		def procFileCOMPARE(args):
			modulecriteria={}
			criteria={}
			modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
			allfiles=[]
			tomatch=""
			checkstrict=True
			rangeval = 0
			fast = False
			if "ptronly" in args or "ptrsonly" in args:
				fast = True
			if "f" in args:
				if args["f"] != "":
					rawfilenames=args["f"].replace('"',"")
					allfiles = rawfilenames.split(',')
					dbg.log("[+] Number of files to be examined : %d " % len(allfiles))
			if "range" in args:
				if not type(args["range"]).__name__.lower() == "bool":
					strrange = args["range"].lower()
					if strrange.startswith("0x") and len(strrange) > 2 :
						rangeval = int(strrange,16)
					else:
						try:
							rangeval = int(args["range"])
						except:
							rangeval = 0
					if rangeval > 0:
						dbg.log("[+] Find overlap using pointer +/- range, value %d" % rangeval)
						dbg.log("    Note : this will significantly slow down the comparison process !")
				else:
					dbg.log("Please provide a numeric value ^(> 0) with option -range",highlight=1)
					return
			else:
				if "contains" in args:
					if type(args["contains"]).__name__.lower() == "str":
						tomatch = args["contains"].replace("'","").replace('"',"")
				if "nostrict" in args:
					if type(args["nostrict"]).__name__.lower() == "bool":
						checkstrict = not args["nostrict"]
						dbg.log("[+] Instructions must match in all files ? %s" % checkstrict)
			# maybe one of the arguments is a folder
			callfiles = allfiles
			allfiles = []
			for tfile in callfiles:
				if os.path.isdir(tfile):
					# folder, get all files from this folder
					for root,dirs,files in os.walk(tfile):
						for dfile in files:
							allfiles.append(os.path.join(root,dfile))
				else:
					allfiles.append(tfile)
			if len(allfiles) > 1:
				findFILECOMPARISON(modulecriteria,criteria,allfiles,tomatch,checkstrict,rangeval,fast)
			else:
				dbg.log("Please specify at least 2 filenames to compare",highlight=1)

		# ----- Find bytes in memory ----- #
		def procFind(args):
			modulecriteria={}
			criteria={}
			pattern = ""
			base = 0
			offset = 0
			top  = TOP_USERLAND
			consecutive = False
			ftype = ""
			
			level = 0
			offsetlevel = 0			
			
			if not "a" in args:
				args["a"] = "*"

			ptronly = False

			if "ptronly" in args or "ptrsonly" in args:
				ptronly = True	
			
			#search for all pointers by default
			if not "x" in args:
				args["x"] = "*"
			modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
			if criteria["accesslevel"] == "":
				return
			if not "s" in args:
				dbg.log("-s <search pattern (or filename)> is a mandatory argument",highlight=1)
				return
			pattern = args["s"]
			
			if "unicode" in args:
				criteria["unic"] = True

			if "b" in args:
				try:
					base = int(args["b"],16)
				except:
					dbg.log("invalid base address: %s" % args["b"],highlight=1)
					return
			if "t" in args:
				try:
					top = int(args["t"],16)
				except:
					dbg.log("invalid top address: %s" % args["t"],highlight=1)
					return
			if "offset" in args:
				if not args["offset"].__class__.__name__ == "bool":
					if "0x" in args["offset"].lower():
						try:
							offset = 0 - int(args["offset"],16)
						except:
							dbg.log("invalid offset value",highlight=1)
							return
					else:	
						try:
							offset = 0 - int(args["offset"])
						except:
							dbg.log("invalid offset value",highlight=1)
							return	
				else:
					dbg.log("invalid offset value",highlight=1)
					return
					
			if "level" in args:
				try:
					level = int(args["level"])
				except:
					dbg.log("invalid level value",highlight=1)
					return

			if "offsetlevel" in args:
				try:
					offsetlevel = int(args["offsetlevel"])
				except:
					dbg.log("invalid offsetlevel value",highlight=1)
					return						
					
			if "c" in args:
				dbg.log("    - Skipping consecutive pointers, showing size instead")			
				consecutive = True
				
			if "type" in args:
				if not args["type"] in ["bin","asc","ptr","instr","file"]:
					dbg.log("Invalid search type : %s" % args["type"], highlight=1)
					return
				ftype = args["type"] 
				if ftype == "file":
					filename = args["s"].replace('"',"").replace("'","")
					#see if we can read the file
					if not os.path.isfile(filename):
						dbg.log("Unable to find/read file %s" % filename,highlight=1)
						return
			rangep2p = 0

			
			if "p2p" in args or level > 0:
				dbg.log("    - Looking for pointers to pointers")
				criteria["p2p"] = True
				if "r" in args:	
					try:
						rangep2p = int(args["r"])
					except:
						pass
					if rangep2p > 0:
						dbg.log("    - Will search for close pointers (%d bytes backwards)" % rangep2p)
				if "p2p" in args:
					level = 1
			
			
			if level > 0:
				dbg.log("    - Recursive levels : %d" % level)
			

			allpointers = findPattern(modulecriteria,criteria,pattern,ftype,base,top,consecutive,rangep2p,level,offset,offsetlevel)
				
			logfile = MnLog("find.txt")
			thislog = logfile.reset()
			processResults(allpointers,logfile,thislog,{},ptronly)
			return
			
			
		# ---- Find instructions, wildcard search ----- #
		def procFindWild(args):
			modulecriteria={}
			criteria={}
			pattern = ""
			patterntype = ""
			base = 0
			top  = TOP_USERLAND
			
			modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)

			if not "s" in args:
				dbg.log("-s <search pattern (or filename)> is a mandatory argument",highlight=1)
				return
			pattern = args["s"]
			
			patterntypes = ["bin","str"]
			if "type" in args:
				if type(args["type"]).__name__.lower() != "bool":
					if args["type"] in patterntypes:
						patterntype = args["type"]
					else:
						dbg.log("-type argument only takes one of these values: %s" % patterntypes,highlight=1)
						return
				else:
					dbg.log("Please specify a valid value for -type. Valid values are %s" % patterntypes,highlight=1)
					return


			if patterntype == "":
				if "\\x" in pattern:
					patterntype = "bin"
				else:
					patterntype = "str"
			
			if "b" in args:
				base,addyok = getAddyArg(args["b"])
				if not addyok:
					dbg.log("invalid base address: %s" % args["b"],highlight=1)
					return

			if "t" in args:
				top,addyok = getAddyArg(args["t"])
				if not addyok:
					dbg.log("invalid top address: %s" % args["t"],highlight=1)
					return
					
			if "depth" in args:
				try:
					criteria["depth"] = int(args["depth"])
				except:
					dbg.log("invalid depth value",highlight=1)
					return	

			if "all" in args:
				criteria["all"] = True
				
			if "distance" in args:
				if type(args["distance"]).__name__.lower() == "bool":
					dbg.log("invalid distance value(s)",highlight=1)
				else:
					distancestr = args["distance"]
					distanceparts = distancestr.split(",")
					for parts in distanceparts:
						valueparts = parts.split("=")
						if len(valueparts) > 1:
							if valueparts[0].lower() == "min":
								try:
									mindistance = int(valueparts[1])
								except:
									mindistance = 0	
							if valueparts[0].lower() == "max":
								try:
									maxdistance = int(valueparts[1])
								except:
									maxdistance = 0	
			
				if maxdistance < mindistance:
					tmp = maxdistance
					maxdistance = mindistance
					mindistance = tmp
				
				criteria["mindistance"] = mindistance
				criteria["maxdistance"] = maxdistance
						
			allpointers = findPatternWild(modulecriteria,criteria,pattern,base,top,patterntype)
				
			logfile = MnLog("findwild.txt")
			thislog = logfile.reset()
			processResults(allpointers,logfile,thislog)		
			return
	
			
		# ----- assemble: assemble instructions to opcodes ----- #
		def procAssemble(args):
			opcodes = ""
			encoder = ""
			
			if not 's' in args:
				dbg.log("Mandatory argument -s <opcodes> missing", highlight=1)
				return
			opcodes = args['s']
			
			if 'e' in args:
				# TODO: implement encoder support
				dbg.log("Encoder support not yet implemented", highlight=1)
				return
				encoder = args['e'].lowercase()
				if encoder not in ["ascii"]:
					dbg.log("Invalid encoder : %s" % encoder, highlight=1)
					return
			
			assemble(opcodes,encoder)
			
		# ----- info: show information about an address ----- #
		def procInfo(args):
			if not "a" in args:
				dbg.log("Missing mandatory argument -a", highlight=1)
				return
			
			address,addyok = getAddyArg(args["a"])
			if not addyok:
				dbg.log("%s is an invalid address" % args["a"], highlight=1)
				return
			
			ptr = MnPointer(address)
			modname = ptr.belongsTo()
			modinfo = None
			if modname != "":
				modinfo = MnModule(modname)
			rebase = ""
			rva=0
			if modinfo :
				rva = address - modinfo.moduleBase
			procFlags(args)
			dbg.log("")			
			dbg.log("[+] Information about address 0x%s" % toHex(address))
			dbg.log("    %s" % ptr.__str__())
			thepage = dbg.getMemoryPageByAddress(address)
			dbg.log("    Address is part of page 0x%08x - 0x%08x" % (thepage.getBaseAddress(),thepage.getBaseAddress()+thepage.getSize()))
			section = ""
			try:
				section = thepage.getSection()
			except:
				section = ""
			if section != "":
				dbg.log("    Section : %s" % section)
			
			if ptr.isOnStack():
				stacks = getStacks()
				stackref = ""
				for tid in stacks:
					currstack = stacks[tid]
					if currstack[0] <= address and address <= currstack[1]:
						stackref = " (Thread 0x%08x, Stack Base : 0x%08x, Stack Top : 0x%08x)" % (tid,currstack[0],currstack[1])
						break
				dbg.log("    This address is in a stack segment %s" % stackref)
			if modinfo:
				dbg.log("    Address is part of a module:")
				dbg.log("    %s" % modinfo.__str__())
				if rva != 0:
					dbg.log("    Offset from module base: 0x%x" % rva)
					if modinfo:
						eatlist = modinfo.getEAT()
						if address in eatlist:
							dbg.log("    Address is start of function '%s' in %s" % (eatlist[address],modname))
						else:
							iatlist = modinfo.getIAT()
							if address in iatlist:
								iatentry = iatlist[address]
								dbg.log("    Address is part of IAT, and contains pointer to '%s'" % iatentry)				
			else:
				output = ""
				if ptr.isInHeap():
					dbg.log("    This address resides in the heap")
					dbg.log("")
					ptr.showHeapBlockInfo()
				else:
					dbg.log("    Module: None")					
			try:
				dbg.log("")
				dbg.log("[+] Disassembly:")
				op = dbg.disasm(address)
				opstring=getDisasmInstruction(op)
				dbg.log("    Instruction at %s : %s" % (toHex(address),opstring))
			except:
				pass
			if __DEBUGGERAPP__ == "WinDBG":
				dbg.log("")
				dbg.log("Output of !address 0x%08x:" % address)
				output = dbg.nativeCommand("!address 0x%08x" % address)
				dbg.logLines(output)
			dbg.log("")
		
		# ----- dump: Dump some memory to a file ----- #
		def procDump(args):
			
			filename = ""
			if "f" not in args:
				dbg.log("Missing mandatory argument -f filename", highlight=1)
				return
			filename = args["f"]
			
			address = None
			if "s" not in args:
				dbg.log("Missing mandatory argument -s address", highlight=1)
				return
			startaddress = str(args["s"]).replace("0x","").replace("0X","")
			if not isAddress(startaddress):
				dbg.log("You have specified an invalid start address", highlight=1)
				return
			address = addrToInt(startaddress)
			
			size = 0
			if "n" in args:
				size = int(args["n"])
			elif "e" in args:
				endaddress = str(args["e"]).replace("0x","").replace("0X","")
				if not isAddress(endaddress):
					dbg.log("You have specified an invalid end address", highlight=1)
					return
				end = addrToInt(endaddress)
				if end < address:
					dbg.log("end address %s is before start address %s" % (args["e"],args["s"]), highlight=1)
					return
				size = end - address
			else:
				dbg.log("you need to specify either the size of the copy with -n or the end address with -e ", highlight=1)
				return
			
			dumpMemoryToFile(address,size,filename)

		# ----- compare : Compare a file created by msfvenom/gdb/hex/xxd/hexdump/ollydbg or just a file with raw bytes with a copy in memory, indicate bad chars / corruption ----- #
		def procCompare(args):
			startpos = 0
			filename = ""
			skipmodules = False
			findunicode = False
			allregs = dbg.getRegs()
			if "f" in args:
				filename = args["f"].replace('"',"").replace("'","")
				#see if we can read the file
				if not os.path.isfile(filename):
					dbg.log("Unable to find/read file %s" % filename,highlight=1)
					return
			else:
				dbg.log("You must specify a valid filename using parameter -f", highlight=1)
				return
			if "a" in args:
				startpos,addyok = getAddyArg(args["a"])
				if not addyok:
					dbg.log("%s is an invalid address" % args["a"], highlight=1)
					return
			if "s" in args:
				skipmodules = True
			if "unicode" in args:
				findunicode = True
			if "t" in args:
				format = args["t"]
			else:
				format = None
			compareFormattedFileWithMemory(filename,format,startpos,skipmodules,findunicode)				
			
		# ----- offset: Calculate the offset between two addresses ----- #
		def procOffset(args):
			extratext1 = ""
			extratext2 = ""
			isReg_a1 = False
			isReg_a2 = False
			regs = dbg.getRegs()
			if "a1" not in args:
				dbg.log("Missing mandatory argument -a1 <address>", highlight=1)
				return
			a1 = args["a1"]
			if "a2" not in args:
				dbg.log("Missing mandatory argument -a2 <address>", highlight=1)
				return		
			a2 = args["a2"]


			a1,addyok = getAddyArg(args["a1"])
			if not addyok:			
				dbg.log("0x%08x is not a valid address" % a1, highlight=1)
				return

			a2,addyok = getAddyArg(args["a2"])
			if not addyok:			
				dbg.log("0x%08x is not a valid address" % a2, highlight=1)
				return

			diff = a2 - a1
			result=toHex(diff)
			negjmpbytes = ""
			if a1 > a2:
				ndiff = a1 - a2
				result=toHex(4294967296-ndiff) 
				negjmpbytes="\\x"+ result[6]+result[7]+"\\x"+result[4]+result[5]+"\\x"+result[2]+result[3]+"\\x"+result[0]+result[1]
				regaction="sub"
			dbg.log("Offset from 0x%08x to 0x%08x : %d (0x%s) bytes" % (a1,a2,diff,result))	
			if a1 > a2:
				dbg.log("Negative jmp offset : %s" % negjmpbytes)
			else:
				dbg.log("Jmp offset : %s" % negjmpbytes)		
			return		
				
		# ----- bp: Set a breakpoint on read/write/exe access ----- #
		def procBp(args):
			isReg_a = False
			regs = dbg.getRegs()
			thistype = ""
			
			if "a" not in args:
				dbg.log("Missing mandatory argument -a address", highlight=1)
				dbg.log("The address can be an absolute address, a register, or a modulename!functionname")
				return
			a = str(args["a"])

			for reg in regs:
				if reg.upper() == a.upper():
					a=toHex(regs[reg])					
					isReg_a = True
					break
			a = a.upper().replace("0X","").lower()
			
			if not isAddress(str(a)):
				# maybe it's a modulename!function
				if str(a).find("!") > -1:
					modparts = str(a).split("!")
					modname = modparts[0]
					if not modname.lower().endswith(".dll"):
						modname += ".dll" 
					themodule = MnModule(modname)											
					if themodule != None and len(modparts) > 1:
						eatlist = themodule.getEAT()
						funcname = modparts[1].lower()
						addyfound = False
						for eatentry in eatlist:
							if eatlist[eatentry].lower() == funcname:
								a = "%08x" % (eatentry)
								addyfound = True
								break
						if not addyfound:
							# maybe it's just a symbol, try to resolve
							if __DEBUGGERAPP__ == "WinDBG":
								symboladdress = dbg.resolveSymbol(a)
								if symboladdress != "" :
									a = symboladdress
									addyfound = True
						if not addyfound:
							dbg.log("Please specify a valid address/register/modulename!functionname (-a)", highlight=1)
							return								
					else:
						dbg.log("Please specify a valid address/register/modulename!functionname (-a)", highlight=1)
						return						
				else:
					dbg.log("Please specify a valid address/register/modulename!functionname (-a)", highlight=1)
					return
			
			valid_types = ["READ", "WRITE", "SFX", "EXEC"]

			if "t" not in args:
				dbg.log("Missing mandatory argument -t type", highlight=1)
				dbg.log("Valid types are: %s" % ", ".join(valid_types))
				return
			else:
				thistype = args["t"].upper()
				
			
			if not thistype in valid_types:
				dbg.log("Invalid type : %s" % thistype)
				return
			
			if thistype == "EXEC":
				thistype = "SFX"
			
			a = hexStrToInt(a)
			
			dbg.setMemBreakpoint(a,thistype[0])
			dbg.log("Breakpoint set on %s of 0x%s" % (thistype,toHex(a)),highlight=1)


		# ----- ct: calltrace ---- #
		def procCallTrace(args):
			modulecriteria={}
			criteria={}
			criteria["accesslevel"] = "X"
			modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
			modulestosearch = getModulesToQuery(modulecriteria)
			hooks = []
			rethooks = []
			showargs = 0
			hookrets = False
			if not "m" in args:
				dbg.log(" ** Please specify what module(s) you want to include in the trace, using argument -m **",highlight=1)
				return
			if "a" in args:
				if args["a"] != "":
					try:
						showargs = int(args["a"])
					except:
						showargs = 0
						
			if "r" in args:
				hookrets = True
			toignore = []
			limit_scope = True
			if not "all" in args:
				# fill up array
				toignore.append("PeekMessage")
				toignore.append("GetParent")
				toignore.append("GetFocus")
				toignore.append("EnterCritical")
				toignore.append("LeaveCritical")
				toignore.append("GetWindow")
				toignore.append("CallnextHook")
				toignore.append("TlsGetValue")
				toignore.append("DefWindowProc")
				toignore.append("SetTextColor")
				toignore.append("DrawText")
				toignore.append("TranslateAccel")
				toignore.append("TranslateMessage")
				toignore.append("DispatchMessage")
				toignore.append("isChild")
				toignore.append("GetSysColor")
				toignore.append("SetBkColor")
				toignore.append("GetDlgCtrl")
				toignore.append("CallWindowProc")
				toignore.append("HideCaret")
				toignore.append("MessageBeep")
				toignore.append("SetWindowText")
				toignore.append("GetDlgItem")
				toignore.append("SetFocus")
				toignore.append("SetCursor")
				toignore.append("LoadCursor")
				toignore.append("SetEvent")
				toignore.append("SetDlgItem")
				toignore.append("SetWindowPos")
				toignore.append("GetDC")
				toignore.append("ReleaseDC")
				toignore.append("GetDeviceCaps")
				toignore.append("GetClientRect")
				toignore.append("etLastError")
			else:
				limit_scope = False
			if len( modulestosearch) > 0:
				dbg.log("[+] Initializing log file")
				logfile = MnLog("calltrace.txt")
				thislog = logfile.reset()			
				dbg.log("[+] Number of CALL arguments to display : %d" % showargs)
				dbg.log("[+] Finding instructions & placing hooks")
				for thismod in modulestosearch:
					dbg.updateLog()
					objMod = dbg.getModule(thismod)
					if not objMod.isAnalysed:
						dbg.log("    Analysing code...")
						objMod.Analyse()
					themod = MnModule(thismod)
					modcodebase = themod.moduleCodebase
					modcodetop = themod.moduleCodetop		
					dbg.setStatusBar("Placing hooks in %s..." % thismod)
					dbg.log("    * %s (0x%08x - 0x%08x)" % (thismod,modcodebase,modcodetop))
					ccnt = 0
					rcnt = 0
					thisaddr = modcodebase
					allfuncs = dbg.getAllFunctions(modcodebase)
					for func in allfuncs:
						thisaddr = func
						thisfunc = dbg.getFunction(thisaddr)
						instrcnt = 0
						while thisfunc.hasAddress(thisaddr):
							try:
								if instrcnt == 0:
									thisopcode = dbg.disasm(thisaddr)
								else:
									thisopcode = dbg.disasmForward(thisaddr,1)
									thisaddr = thisopcode.getAddress()
								instruction = getDisasmInstruction(thisopcode)
								if instruction.startswith("CALL "):
									ignore_this_instruction = False
									for ignores in toignore:
										if instruction.lower().find(ignores.lower()) > -1:
											ignore_this_instruction = True
											break
									if not ignore_this_instruction:
										if not thisaddr in hooks:
											hooks.append(thisaddr)
											myhook = MnCallTraceHook(thisaddr,showargs,instruction,thislog)
											myhook.add("HOOK_CT_%s" % thisaddr , thisaddr)
									ccnt += 1
								if hookrets and instruction.startswith("RETN"):
									if not thisaddr in rethooks:
										rethooks.append(thisaddr)
										myhook = MnCallTraceHook(thisaddr,showargs,instruction,thislog)
										myhook.add("HOOK_CT_%s" % thisaddr , thisaddr)									
							except:
								#dbg.logLines(traceback.format_exc(),highlight=True)
								break
							instrcnt += 1
				dbg.log("[+] Total number of CALL hooks placed : %d" % len(hooks))
				if hookrets:
					dbg.log("[+] Total number of RETN hooks placed : %d" % len(rethooks))
			else:
				dbg.log("[!] No modules selected or found",highlight=1)
			return "Done"
			
		# ----- bu: set a deferred breakpoint ---- #
		def procBu(args):
			if not "a" in args:
				dbg.log("No targets defined. (-a)",highlight=1)
				return
			else:
				allargs = args["a"]
				bpargs = allargs.split(",")
				breakpoints = {}
				dbg.log("")
				dbg.log("Received %d addresses//functions to process" % len(bpargs))
				# set a breakpoint right away for addresses and functions that are mapped already
				for tbparg in bpargs:
					bparg = tbparg.replace(" ","")
					# address or module.function ?
					if bparg.find(".") > -1:
						functionaddress = dbg.getAddress(bparg)
						if functionaddress > 0:
							# module.function is already mapped, we can set a bp right away
							dbg.setBreakpoint(functionaddress)
							breakpoints[bparg] = True
							dbg.log("Breakpoint set at 0x%08x (%s), was already mapped" % (functionaddress,bparg), highlight=1)
						else:
							breakpoints[bparg] = False # no breakpoint set yet
					elif bparg.find("+") > -1:
						ptrparts = bparg.split("+")
						modname = ptrparts[0]
						if not modname.lower().endswith(".dll"):
							modname += ".dll" 
						themodule = getModuleObj(modname)												
						if themodule != None and len(ptrparts) > 1:
							address = themodule.getBase() + int(ptrparts[1],16)
							if address > 0:
								dbg.log("Breakpoint set at %s (0x%08x), was already mapped" % (bparg,address),highlight=1)
								dbg.setBreakpoint(address)
								breakpoints[bparg] = True
							else:
								breakpoints[bparg] = False
						else:
							breakpoints[bparg] = False
					if bparg.find(".") == -1 and bparg.find("+") == -1:
						# address, see if it is mapped, by reading one byte from that location
						address = -1
						try:
							address = int(bparg,16)
						except:
							pass
						thispage = dbg.getMemoryPageByAddress(address)
						if thispage != None:
							dbg.setBreakpoint(address)
							dbg.log("Breakpoint set at 0x%08x, was already mapped" % address, highlight=1)
							breakpoints[bparg] = True
						else:
							breakpoints[bparg] = False

				# get the correct addresses to put hook on
				loadlibraryA = dbg.getAddress("kernel32.LoadLibraryA")
				loadlibraryW = dbg.getAddress("kernel32.LoadLibraryW")

				if loadlibraryA > 0 and loadlibraryW > 0:
				
					# find end of function for each
					endAfound = False
					endWfound = False
					cnt = 1
					while not endAfound:
						objInstr = dbg.disasmForward(loadlibraryA, cnt)
						strInstr = getDisasmInstruction(objInstr)
						if strInstr.startswith("RETN"):
							endAfound = True
							loadlibraryA = objInstr.getAddress()
						cnt += 1
					
					cnt = 1
					while not endWfound:
						objInstr = dbg.disasmForward(loadlibraryW, cnt)
						strInstr = getDisasmInstruction(objInstr)
						if strInstr.startswith("RETN"):
							endWfound = True
							loadlibraryW = objInstr.getAddress()
						cnt += 1	
					
					# if addresses/functions are left, throw them into their own hooks,
					# one for each LoadLibrary type.
					hooksplaced = False
					for bptarget in breakpoints:
						if not breakpoints[bptarget]:
							myhookA = MnDeferredHook(loadlibraryA, bptarget)
							myhookA.add("HOOK_A_%s" % bptarget, loadlibraryA)
							myhookW = MnDeferredHook(loadlibraryW, bptarget)
							myhookW.add("HOOK_W_%s" % bptarget, loadlibraryW)
							dbg.log("Hooks for %s installed" % bptarget)
							hooksplaced = True
					if not hooksplaced:
						dbg.log("No hooks placed")
				else:
					dbg.log("** Unable to place hooks, make sure kernel32.dll is loaded",highlight=1)
				return "Done"							
			
		# ----- bf: Set a breakpoint on exported functions of a module ----- #
		def procBf(args):

			funcfilter = ""
			
			mode = ""
			
			type = "export"
			
			modes = ["add","del","list"]
			types = ["import","export","iat","eat"]
			
			modulecriteria={}
			criteria={}
			
			modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
		
			if "s" in args:
				try:
					funcfilter = args["s"].lower()
				except:
					dbg.log("No functions selected. (-s)",highlight=1)
					return
			else:
				dbg.log("No functions selected. (-s)",highlight=1)
				return

			if "t" in args:
				try:
					mode = args["t"].lower()
				except:
					pass

			if "f" in args:
				try:
					type = args["f"].lower()
				except:
					pass

			if not type in types:
				dbg.log("No valid function type selected (-f <import|export>)",highlight=1)
				return

			if not mode in modes or mode=="":
				dbg.log("No valid action defined. (-t add|del|list)")

			doManageBpOnFunc(modulecriteria,criteria,funcfilter,mode,type)
			
			return
		
		
		# ----- Show info about modules -------#
		def procModInfoS(args):
			modulecriteria = {}
			criteria = {}
			modulecriteria["safeseh"] = False
			dbg.log("Safeseh unprotected modules :")
			modulestosearch = getModulesToQuery(modulecriteria)
			showModuleTable("",modulestosearch)
			return
			
		def procModInfoSA(args):
			modulecriteria = {}
			criteria = {}
			modulecriteria["safeseh"] = False
			modulecriteria["aslr"] = False
			modulecriteria["rebase"] = False	
			dbg.log("Safeseh unprotected, no aslr & no rebase modules :")
			modulestosearch = getModulesToQuery(modulecriteria)
			showModuleTable("",modulestosearch)			
			return

		def procModInfoA(args):
			modulecriteria = {}
			criteria = {}
			modulecriteria["aslr"] = False
			modulecriteria["rebase"] = False	
			dbg.log("No aslr & no rebase modules :")			
			modulestosearch = getModulesToQuery(modulecriteria)
			showModuleTable("",modulestosearch)			
			return
			
		# ----- Print byte array ----- #
		
		def procByteArray(args):
			badchars = ""
			bytesperline = 32
			startval = 0
			endval = 255

			# kept for legacy
			if "r" in args:
				startval = 255
				endval = 0

			# handle start argument
			if "s" in args:
					startval = hex2int(cleanHex(args['s']))
			# handle end argument
			if "e" in args:
					endval = hex2int(cleanHex(args['e']))

			if "b" in args:
				dbg.log(" *** Note: parameter -b has been deprecated and replaced with -cpb ***")
				if type(args["b"]).__name__.lower() != "bool":
					if not "cpb" in args:
						args["cpb"] = args["b"]

			if "cpb" in args:	
				badchars = args["cpb"]
			badchars = cleanHex(badchars)

			# see if we need to expand ..
			bpos = 0
			newbadchars = ""
			while bpos < len(badchars):
				curchar = badchars[bpos]+badchars[bpos+1]
				if curchar == "..":
					pos = bpos
					if pos > 1 and pos <= len(badchars)-4:
						# get byte before and after ..
						bytebefore = badchars[pos-2] + badchars[pos-1]
						byteafter = badchars[pos+2] + badchars[pos+3]
						bbefore = int(bytebefore,16)
						bafter = int(byteafter,16)
						insertbytes = ""
						bbefore += 1
						while bbefore < bafter:
							insertbytes += "%02x" % bbefore
							bbefore += 1
						newbadchars += insertbytes
				else:
					newbadchars += curchar
				bpos += 2
			badchars = newbadchars

			cnt = 0
			strb = ""
			while cnt < len(badchars):
				strb=strb+binascii.a2b_hex(badchars[cnt]+badchars[cnt+1])
				cnt=cnt+2

			dbg.log("Generating table, excluding %d bad chars..." % len(strb))
			arraytable = []
			binarray = ""

			# handle range() last value
			if endval > startval:
				increment = 1
				endval += 1
			else:
				endval += -1
				increment = -1

			# create bytearray
			for thisval in range(startval,endval,increment):
				hexbyte = hex(thisval)[2:]
				binbyte = hex2bin(toHexByte(thisval))
				if len(hexbyte) == 1:
					hexbyte = "0" + hexbyte
				hexbyte2 = binascii.a2b_hex(hexbyte)
				if not hexbyte2 in strb:
					arraytable.append(hexbyte)
					binarray += binbyte

			dbg.log("Dumping table to file")
			output = ""
			cnt = 0
			outputline = '"'
			totalbytes = len(arraytable)
			tablecnt = 0
			while tablecnt < totalbytes:
				if (cnt < bytesperline):
					outputline += "\\x" + arraytable[tablecnt]
				else:
					outputline += '"\n'
					cnt = 0
					output += outputline
					outputline = '"\\x' + arraytable[tablecnt]
				tablecnt += 1
				cnt += 1
			if (cnt-1) < bytesperline:
				outputline += '"\n'
			output += outputline
			
			global ignoremodules
			ignoremodules = True
			arrayfilename="bytearray.txt"
			objarrayfile = MnLog(arrayfilename)
			arrayfile = objarrayfile.reset()
			binfilename = arrayfile.replace("bytearray.txt","bytearray.bin")
			objarrayfile.write(output,arrayfile)
			ignoremodules = False
			dbg.logLines(output)
			dbg.log("")
			binfile = open(binfilename,"wb")
			binfile.write(binarray)
			binfile.close()
			dbg.log("Done, wrote %d bytes to file %s" % (len(arraytable),arrayfile))
			dbg.log("Binary output saved in %s" % binfilename)
			return
			
			
			
			
		#----- Read binary file, print 'nice' header -----#
		def procPrintHeader(args):
			alltypes = ["ruby","rb","python","py"]
			thistype = "ruby"
			filename = ""
			typewrong = False
			stopnow = False
			if "f" in args:
				if type(args["f"]).__name__.lower() != "bool":	
					filename = args["f"]
			if "t" in args:
				if type(args["t"]).__name__.lower() != "bool":
					if args["t"] in alltypes:
						thistype = args["t"]
					else:
						typewrong = True
				else:
					typewrong = True

			if typewrong:
				dbg.log("Invalid type specified with option -t. Valid types are: %s" % alltypes,highlight=1)
				stopnow = True
			else:
				if thistype == "rb":
					thistype = "ruby"
				if thistype == "py":
					thistype = "python"

			if filename == "":
				dbg.log("Missing argument -f <source filename>",highlight=1)
				stopnow = True

			if stopnow:
				return

			filename = filename.replace("'","").replace('"',"")
			content = ""
			try:		
				file = open(filename,"rb")
				content = file.read()
				file.close()
			except:
				dbg.log("Unable to read file %s" % filename,highlight=1)
				return
			dbg.log("Read %d bytes from %s" % (len(content),filename))	
			dbg.log("Output type: %s" % thistype)
			cnt = 0
			linecnt = 0	
			
			output = ""
			thisline = ""			
			
			max = len(content)
			
			addchar = "<<"
			if thistype == "python":
				addchar = "+="
			
			# keep it easy, initialize header as an empty string
			output = "header = \"\"\n"

			while cnt < max:

				# first check for unicode
				if cnt < max-1:
					
					thisline = "header %s \"" % addchar	
					thiscnt = cnt
					while cnt < max-1 and isAscii2(ord(content[cnt])) and ord(content[cnt+1]) == 0:
						if content[cnt] == "\\":
							thisline += "\\"
						if content[cnt] == "\"":
							thisline += "\\"
						thisline += "%s\\x00" % content[cnt]
						cnt += 2
					if thiscnt != cnt:
						output += thisline + "\"" + "\n"
						linecnt += 1
						
				thisline = "header %s \"" % addchar
				thiscnt = cnt
				
				# ascii repetitions
				reps = 1
				startval = content[cnt]
				if isAscii(ord(content[cnt])):
					while cnt < max-1:
						if startval == content[cnt+1]:
							reps += 1
							cnt += 1	
						else:
							break
					if reps > 1:
						if startval == "\\":
							startval += "\\"
						if startval == "\"":
							startval = "\\" + "\""	
						output += thisline + startval + "\" * " + str(reps) + "\n"
						cnt += 1
						linecnt += 1
						continue
						

				thisline = "header %s \"" % addchar
				thiscnt = cnt
				
				# check for just ascii
				while cnt < max and isAscii2(ord(content[cnt])):
					if cnt < max-1 and ord(content[cnt+1]) == 0:
						break
					if content[cnt] == "\\":
						thisline += "\\"
					if content[cnt] == "\"":
						thisline += "\\"			
					thisline += content[cnt]
					cnt += 1
					
					
				if thiscnt != cnt:
					output += thisline + "\"" + "\n"
					linecnt += 1		
				
				#check others : repetitions
				if cnt < max:
					thisline = "header %s \"" % addchar
					thiscnt = cnt
					while cnt < max:
						if isAscii2(ord(content[cnt])):
							break
						if cnt < max-1 and isAscii2(ord(content[cnt])) and ord(content[cnt+1]) == 0:
							break
						#check repetitions
						reps = 1
						startval = ord(content[cnt])
						while cnt < max-1:
							if startval == ord(content[cnt+1]):
								reps += 1
								cnt += 1	
							else:
								break
						if reps > 1:
							if len(thisline) > 12:
								output += thisline + "\"" + "\n"
							thisline = "header %s \"\\x" % addchar 
							thisline += "%02x\" * %d" % (startval,reps)
							output += thisline + "\n"
							thisline = "header %s \"" % addchar
							linecnt += 1
						else:
							thisline += "\\x" + "%02x" % ord(content[cnt])	
						cnt += 1
					if thiscnt != cnt:
						if len(thisline) > 12:
							output += thisline + "\"" + "\n"
							linecnt += 1			

			global ignoremodules
			ignoremodules = True
			headerfilename="header.txt"
			objheaderfile = MnLog(headerfilename)
			headerfile = objheaderfile.reset()
			objheaderfile.write(output,headerfile)
			ignoremodules = False
			if not silent:
				dbg.log("-" * 30)
				dbg.logLines(output)
				dbg.log("-" * 30)			
			dbg.log("Wrote header to %s" % headerfile)
			return
		
		#----- Update -----#
		
		def procUpdate(args):
			"""
			Function to update mona and optionally windbglib to the latest version
			
			Arguments : none
			
			Returns : new version of mona/windbglib (if available)
			"""

			updateproto = "https"

			#debugger version	
			imversion = __IMM__
			#url
			dbg.setStatusBar("Running update process...")
			dbg.updateLog()
			updateurl = "https://github.com/corelan/mona/raw/master/mona.py"
			
			currentversion,currentrevision = getVersionInfo(inspect.stack()[0][1])
			u = ""
			try:
				u = urllib.urlretrieve(updateurl)
				newversion,newrevision = getVersionInfo(u[0])
				if newversion != "" and newrevision != "":
					dbg.log("[+] Version compare :")
					dbg.log("    Current Version : %s, Current Revision : %s" % (currentversion,currentrevision))
					dbg.log("    Latest Version : %s, Latest Revision : %s" % (newversion,newrevision))
				else:
					dbg.log("[-] Unable to check latest version (corrupted file ?), try again later",highlight=1)
					return
			except:
				dbg.log("[-] Unable to check latest version (download error). Try again later",highlight=1)
				dbg.log("    Meanwhile, please check/confirm that you're running a recent version of python 2.7 (2.7.14 or higher)", highlight=1)
				return
			#check versions
			doupdate = False
			if newversion != "" and newrevision != "":
				if currentversion != newversion:
					doupdate = True
				else:
					if int(currentrevision) < int(newrevision):
						doupdate = True
				
			if doupdate:
				dbg.log("[+] New version available",highlight=1)
				dbg.log("    Updating to %s r%s" % (newversion,newrevision),highlight=1)
				try:
					shutil.copyfile(u[0],inspect.stack()[0][1])
					dbg.log("    Done")					
				except:
					dbg.log("    ** Unable to update mona.py",highlight=1)
				currentversion,currentrevision = getVersionInfo(inspect.stack()[0][1])
				dbg.log("[+] Current version : %s r%s" % (currentversion,currentrevision))
			else:
				dbg.log("[+] You are running the latest version")

			# update windbglib if needed
			if __DEBUGGERAPP__ == "WinDBG":
				dbg.log("[+] Locating windbglib path")
				paths = sys.path
				filefound = False
				libfile = ""
				for ppath in paths:
					libfile = ppath + "\\windbglib.py"
					if os.path.isfile(libfile):
						filefound=True
						break
				if not filefound:
					dbg.log("    ** Unable to find windbglib.py ! **")
				else:
					dbg.log("[+] Checking if %s needs an update..." % libfile)
					updateurl = "https://github.com/corelan/windbglib/raw/master/windbglib.py"

					currentversion,currentrevision = getVersionInfo(libfile)
					u = ""
					try:
						u = urllib.urlretrieve(updateurl)
						newversion,newrevision = getVersionInfo(u[0])
						if newversion != "" and newrevision != "":
							dbg.log("[+] Version compare :")
							dbg.log("    Current Version : %s, Current Revision : %s" % (currentversion,currentrevision))
							dbg.log("    Latest Version : %s, Latest Revision : %s" % (newversion,newrevision))
						else:
							dbg.log("[-] Unable to check latest version (corrupted file ?), try again later",highlight=1)
							return
					except:
						dbg.log("[-] Unable to check latest version (download error). Try again later",highlight=1)
						dbg.log("    Meanwhile, please check/confirm that you're running a recent version of python 2.7 (2.7.14 or higher)", highlight=1)
						return

					#check versions
					doupdate = False
					if newversion != "" and newrevision != "":
						if currentversion != newversion:
							doupdate = True
						else:
							if int(currentrevision) < int(newrevision):
								doupdate = True
						
					if doupdate:
						dbg.log("[+] New version available",highlight=1)
						dbg.log("    Updating to %s r%s" % (newversion,newrevision),highlight=1) 
						try:
							shutil.copyfile(u[0],libfile)
							dbg.log("    Done")					
						except:
							dbg.log("    ** Unable to update windbglib.py",highlight=1)
						currentversion,currentrevision = getVersionInfo(libfile)
						dbg.log("[+] Current version : %s r%s" % (currentversion,currentrevision))
					else:
						dbg.log("[+] You are running the latest version")

			dbg.setStatusBar("Done.")
			return
			
		#----- GetPC -----#
		def procgetPC(args):
			r32 = ""
			output = ""
			if "r" in args:
				if type(args["r"]).__name__.lower() != "bool":	
					r32 = args["r"].lower()
						  
			if r32 == "" or not "r" in args:
				dbg.log("Missing argument -r <register>",highlight=1)
				return

			opcodes = {}
			opcodes["eax"] = "\\x58"
			opcodes["ecx"] = "\\x59"
			opcodes["edx"] = "\\x5a"
			opcodes["ebx"] = "\\x5b"				
			opcodes["esp"] = "\\x5c"
			opcodes["ebp"] = "\\x5d"
			opcodes["esi"] = "\\x5e"
			opcodes["edi"] = "\\x5f"

			calls = {}
			calls["eax"] = "\\xd0"
			calls["ecx"] = "\\xd1"
			calls["edx"] = "\\xd2"
			calls["ebx"] = "\\xd3"				
			calls["esp"] = "\\xd4"
			calls["ebp"] = "\\xd5"
			calls["esi"] = "\\xd6"
			calls["edi"] = "\\xd7"
			
			output  = "\n" + r32 + "|  jmp short back:\n\"\\xeb\\x03" + opcodes[r32] + "\\xff" + calls[r32] + "\\xe8\\xf8\\xff\\xff\\xff\"\n"
			output += r32 + "|  call + 4:\n\"\\xe8\\xff\\xff\\xff\\xff\\xc3" + opcodes[r32] + "\"\n"
			output += r32 + "|  fstenv:\n\"\\xd9\\xeb\\x9b\\xd9\\x74\\x24\\xf4" + opcodes[r32] + "\"\n"
                        
			global ignoremodules
			ignoremodules = True
			getpcfilename="getpc.txt"
			objgetpcfile = MnLog(getpcfilename)
			getpcfile = objgetpcfile.reset()
			objgetpcfile.write(output,getpcfile)
			ignoremodules = False
			dbg.logLines(output)
			dbg.log("")			
			dbg.log("Wrote to file %s" % getpcfile)
			return		

			
		#----- Egghunter -----#
		def procEgg(args):
			filename = ""
			egg = "w00t"
			usechecksum = False
			usewow64 = False
			useboth = False
			egg_size = 0
			win_ver = "10"
			win_vers = ["7","10"]
			checksumbyte = ""
			extratext = ""
			
			global silent
			oldsilent = silent
			silent = True			
			
			if "f" in args:
				if type(args["f"]).__name__.lower() != "bool":
					filename = args["f"]
			filename = filename.replace("'", "").replace("\"", "")					

			if "winver" in args:
				if str(args["winver"]) in win_vers:
					win_ver = str(args["winver"])
				else:
					dbg.log("[-] Didn't recognize windows version, using Win10 as the default", highlight=True)
			#Set egg
			if "t" in args:
				if type(args["t"]).__name__.lower() != "bool":
					egg = args["t"]

			if "wow64" in args:
				usewow64 = True


			# placeholder for later
			if "both" in args:
				useboth = True

			if len(egg) != 4:
				egg = 'w00t'
			dbg.log("[+] Egg set to %s" % egg)
			
			if "c" in args:
				if filename != "":
					usechecksum = True
					dbg.log("[+] Hunter will include checksum routine")
				else:
					dbg.log("Option -c only works in conjunction with -f <filename>",highlight=1)
					return
			
			startreg = ""
			if "startreg" in args:
				if isReg(args["startreg"]):
					startreg = args["startreg"].lower()
					dbg.log("[+] Egg will start search at %s" % startreg)
			
					
			depmethods = ["virtualprotect","copy","copy_size"]
			depreg = "esi"
			depsize = 0
			freeregs = [ "ebx","ecx","ebp","esi" ]
			
			regsx = {}
			# 0 : mov xX
			# 1 : push xX
			# 2 : mov xL
			# 3 : mov xH
			#
			regsx["eax"] = ["\x66\xb8","\x66\x50","\xb0","\xb4"]
			regsx["ebx"] = ["\x66\xbb","\x66\x53","\xb3","\xb7"]
			regsx["ecx"] = ["\x66\xb9","\x66\x51","\xb1","\xb5"]
			regsx["edx"] = ["\x66\xba","\x66\x52","\xb2","\xb6"]
			regsx["esi"] = ["\x66\xbe","\x66\x56"]
			regsx["edi"] = ["\x66\xbf","\x66\x57"]
			regsx["ebp"] = ["\x66\xbd","\x66\x55"]
			regsx["esp"] = ["\x66\xbc","\x66\x54"]
			
			addreg = {}
			addreg["eax"] = "\x83\xc0"
			addreg["ebx"] = "\x83\xc3"			
			addreg["ecx"] = "\x83\xc1"
			addreg["edx"] = "\x83\xc2"
			addreg["esi"] = "\x83\xc6"
			addreg["edi"] = "\x83\xc7"
			addreg["ebp"] = "\x83\xc5"			
			addreg["esp"] = "\x83\xc4"
			
			depdest = ""
			depmethod = ""
			
			getpointer = ""
			getsize = ""
			getpc = ""
			
			jmppayload = "\xff\xe7"	#jmp edi
			
			if "depmethod" in args:
				if args["depmethod"].lower() in depmethods:
					depmethod = args["depmethod"].lower()
					dbg.log("[+] Hunter will include routine to bypass DEP on found shellcode")
					# other DEP related arguments ?
					# depreg
					# depdest
					# depsize
				if "depreg" in args:
					if isReg(args["depreg"]):
						depreg = args["depreg"].lower()
				if "depdest" in args:
					if isReg(args["depdest"]):
						depdest = args["depdest"].lower()
				if "depsize" in args:
					try:
						depsize = int(args["depsize"])
					except:
						dbg.log(" ** Invalid depsize",highlight=1)
						return
			
			
			#read payload file
			data = ""
			if filename != "":
				try:
					f = open(filename, "rb")
					data = f.read()
					f.close()
					dbg.log("[+] Read payload file (%d bytes)" % len(data))
				except:
					dbg.log("Unable to read file %s" %filename, highlight=1)
					return

					
			#let's start		
			egghunter = ""

			if not usewow64:
				#Basic version of egghunter
				dbg.log("[+] Generating traditional 32bit egghunter code")
				egghunter = ""
				egghunter += (
					"\x66\x81\xca\xff\x0f"+	#or dx,0xfff
					"\x42"+					#INC EDX
					"\x52"					#push edx
					"\x6a\x02"				#push 2	(NtAccessCheckAndAuditAlarm syscall)
					"\x58"					#pop eax
					"\xcd\x2e"				#int 0x2e 
					"\x3c\x05"				#cmp al,5
					"\x5a"					#pop edx
					"\x74\xef"				#je "or dx,0xfff"
					"\xb8"+egg+				#mov eax, egg
					"\x8b\xfa"				#mov edi,edx
					"\xaf"					#scasd
					"\x75\xea"				#jne "inc edx"
					"\xaf"					#scasd
					"\x75\xe7"				#jne "inc edx"
				)
				incedxoffset = 5 # The offset in the egghunter to reach the #INC EDX
			if usewow64:
				dbg.log("[+] Generating egghunter for wow64, Windows %s" % win_ver)
				egghunter = ""
				if win_ver == "7":
					egghunter += (
						# 64 stub needed before loop
						"\x31\xdb"                                      #xor ebx,ebx
						"\x53"                                          #push ebx
						"\x53"                                          #push ebx
						"\x53"                                          #push ebx
						"\x53"                                          #push ebx
						"\xb3\xc0"                                      #mov bl,0xc0
		
						# 64 Loop
						"\x66\x81\xCA\xFF\x0F"                          #OR DX,0FFF
						"\x42"                                          #INC EDX
						"\x52"                                          #PUSH EDX
						"\x6A\x26"                                      #PUSH 26 
						"\x58"                                          #POP EAX
						"\x33\xC9"                                      #XOR ECX,ECX
						"\x8B\xD4"                                      #MOV EDX,ESP
						"\x64\xff\x13"                                  #CALL DWORD PTR FS:[ebx]
						"\x5e"                                          #POP ESI
						"\x5a"                                          #POP EDX
						"\x3C\x05"                                      #CMP AL,5
						"\x74\xe9"                                      #JE SHORT
						"\xB8"+egg+                                     #MOV EAX,74303077 w00t
						"\x8B\xFA"                                      #MOV EDI,EDX
						"\xAF"                                          #SCAS DWORD PTR ES:[EDI]
						"\x75\xe4"                                      #JNZ "inc edx"
						"\xAF"                                          #SCAS DWORD PTR ES:[EDI]
						"\x75\xe1"                                      #JNZ "inc edx"
						"")
					incedxoffset = 13 # The offset in the egghunter to reach the #INC EDX
				elif win_ver == "10":
					egghunter += (
					# _start:
					    # "\x8c\xcb"            #MOV EBX,CS
						# "\x80\xfb\x23"        #CMP BL,0x23
						"\x33\xD2"              #XOR EDX,EDX
					# invalid_page:
						"\x66\x81\xCA\xFF\x0F"  #OR DX,0FFF
					# valid_page:
						"\x33\xDB"              #XOR EBX,EBX
						"\x42"               	#INC EDX
						"\x53"               	#PUSH EBX
						"\x53"               	#PUSH EBX
						"\x52"               	#PUSH EDX
						"\x53"               	#PUSH EBX
						"\x53"               	#PUSH EBX
						"\x53"               	#PUSH EBX
						"\x6A\x29"            	#PUSH 29
						"\x58"               	#POP EAX
						"\xB3\xC0"            	#MOV BL,0C0
						"\x64\xFF\x13"          #CALL DWORD PTR FS:[EBX]
						"\x83\xC4\x0c"          #ADD ESP,0xc
						"\x5A"               	#POP EDX
						"\x83\xc4\x08"          #ADD ESP,0x8
						"\x3C\x05"            	#CMP AL,5
						"\x74\xDF"            	#JE SHORT invalid_page
						"\xB8" + egg +  		#MOV EAX,<tag>
						"\x8B\xFA"              #MOV EDI,EDX
						"\xAF"               	#SCAS DWORD PTR ES:[EDI]
						"\x75\xDA"            	#JNZ SHORT valid_page
						"\xAF"              	#SCAS DWORD PTR ES:[EDI]
						"\x75\xD7"    			#JNZ SHORT valid_page
						)
					incedxoffset = 9 # The offset in the egghunter to reach the #INC EDX
			if usechecksum:
				dbg.log("[+] Generating checksum routine")
				extratext = "+ checksum routine"
				egg_size = ""
				if len(data) < 256:
					cmp_reg = "\x80\xf9"	#cmp cl,value
					egg_size = hex2bin("%02x" % len(data))
					offset1 = "\xf7"
				elif len(data) < 65536:
					cmp_reg = "\x66\x81\xf9"	#cmp cx,value
					#avoid nulls
					egg_size_normal = "%04X" % len(data)
					while egg_size_normal[0:2] == "00" or egg_size_normal[2:4] == "00":
						data += "\x90"
						egg_size_normal = "%04X" % len(data)
					egg_size = hex2bin(egg_size_normal[2:4]) + hex2bin(egg_size_normal[0:2])
					offset1 = "\xf5"
				else:
					dbg.log("Cannot use checksum code with this payload size (way too big)",highlight=1)
					return
					
				sum = 0
				for byte in data:
					sum += ord(byte)
				sumstr= toHex(sum)
				checksumbyte = sumstr[len(sumstr)-2:len(sumstr)]

				sizeOfjnzincedx = 2 # The number of bytes needed for the the jnz "inc edx" instruction below
				sizeOfChecksumRoutine = 15 # The number of static bytes in the checksum routine below
				offset2 = shortJump(sizeOfjnzincedx, - (len(egghunter) - incedxoffset + sizeOfChecksumRoutine + len(cmp_reg) + len(egg_size)))
				egghunter += (
					"\x51"						#push ecx
					"\x31\xc9"					#xor ecx,ecx
					"\x31\xc0"					#xor eax,eax
					"\x02\x04\x0f"				#add al,byte [edi+ecx]
					"\x41"+						#inc ecx
					cmp_reg + egg_size +    	#cmp cx/cl, value
					"\x75" + offset1 +			#jnz "add al,byte [edi+ecx]
					"\x3a\x04\x39" +			#cmp al,byte [edi+ecx]
					"\x59" +					#pop ecx
					"\x75" + offset2			#jnz "inc edx"
				)		

			#dep bypass ?
			if depmethod != "":
				dbg.log("[+] Generating dep bypass routine")
			
				if not depreg in freeregs:
					getpointer += "mov " + freeregs[0] +"," + depreg + "#"
					depreg = freeregs[0]
				
				freeregs.remove(depreg)
				if depmethod == "copy" or depmethod == "copy_size":
					if depdest != "":
						if not depdest in freeregs:
							getpointer += "mov " + freeregs[0] + "," + depdest + "#"
							depdest = freeregs[0]
					else:
						getpc = "\xd9\xee"			# fldz
						getpc += "\xd9\x74\xe4\xf4"	# fstenv [esp-0c]
						depdest = freeregs[0]
						getpc += hex2bin(assemble("pop "+depdest))
					
					freeregs.remove(depdest)
				
				sizereg = freeregs[0]
				
				if depsize == 0:
					# set depsize to payload * 2 if we are using a file
					depsize = len(data) * 2
					if depmethod == "copy_size":
						depsize = len(data)
					
				if depsize == 0:
					dbg.log("** Please specify a valid -depsize when you are not using -f **",highlight=1)
					return
				else:
					if depsize <= 127:
						#simply push it to the stack
						getsize = "\x6a" + hex2bin("\\x" + toHexByte(depsize))
					else:
						#can we do it with 16bit reg, no nulls ?
						if depsize <= 65535:
							sizeparam = toHex(depsize)[4:8]
							getsize = hex2bin(assemble("xor "+sizereg+","+sizereg))
							if not (sizeparam[0:2] == "00" or sizeparam[2:4] == "00"):
								#no nulls, hooray, write to xX
								getsize += regsx[sizereg][0]+hex2bin("\\x" + sizeparam[2:4] + "\\x" + sizeparam[0:2])
							else:
								# write the non null if we can
								if len(regsx[sizereg]) > 2:
									if not (sizeparam[0:2] == "00"):
										# write to xH
										getsize += regsx[sizereg][3] + hex2bin("\\x" + sizeparam[0:2])
									if not (sizeparam[2:4] == "00"):
										# write to xL
										getsize += regsx[sizereg][2] + hex2bin("\\x" + sizeparam[2:4])
								else:
									#we have to write the full value to sizereg
									blockcnt = 0
									vpsize = 0
									blocksize = depsize
									while blocksize >= 127:
										blocksize = blocksize / 2
										blockcnt += 1
									if blockcnt > 0:
										getsize += addreg[sizereg] + hex2bin("\\x" + toHexByte(blocksize))
										vpsize = blocksize
										depblockcnt = 0
										while depblockcnt < blockcnt:
											getsize += hex2bin(assemble("add "+sizereg+","+sizereg))
											vpsize += vpsize
											depblockcnt += 1
										delta = depsize - vpsize
										if delta > 0:
											getsize += addreg[sizereg] + hex2bin("\\x" + toHexByte(delta))
									else:
										getsize += addreg[sizereg] + hex2bin("\\x" + toHexByte(depsize))
								# finally push
							getsize += hex2bin(assemble("push "+ sizereg))
								
						else:
							dbg.log("** Shellcode size (depsize) is too big",highlight=1)
							return
						
				#finish it off
				if depmethod == "virtualprotect":
					jmppayload = "\x54\x6a\x40"
					jmppayload += getsize
					jmppayload += hex2bin(assemble("#push edi#push edi#push "+depreg+"#ret"))
				elif depmethod == "copy":
					jmppayload = hex2bin(assemble("push edi\push "+depdest+"#push "+depdest+"#push "+depreg+"#mov edi,"+depdest+"#ret"))
				elif depmethod == "copy_size":
					jmppayload += getsize
					jmppayload += hex2bin(assemble("push edi#push "+depdest+"#push " + depdest + "#push "+depreg+"#mov edi,"+depdest+"#ret"))
				
		
			#jmp to payload
			egghunter += getpc
			egghunter += jmppayload
			
			startat = ""
			skip = ""
			
			#start at a certain reg ?
			if startreg != "":
				if startreg != "edx":
					startat = hex2bin(assemble("mov edx," + startreg))
				skip = "\xeb\x05"
			
			egghunter = skip + egghunter
			#pickup pointer for DEP bypass ?
			egghunter = hex2bin(assemble(getpointer)) + egghunter
			
			egghunter = startat + egghunter
			
			silent = oldsilent			
			
			#Convert binary to printable hex format
			egghunter_hex = toniceHex(egghunter.strip().replace(" ",""),16)
					
			global ignoremodules
			ignoremodules = True
			hunterfilename="egghunter.txt"
			objegghunterfile = MnLog(hunterfilename)
			egghunterfile = objegghunterfile.reset()						

			dbg.log("[+] Egghunter %s (%d bytes): " % (extratext,len(egghunter.strip().replace(" ",""))))
			dbg.logLines("%s" % egghunter_hex)
		
			objegghunterfile.write("Egghunter " + extratext + ", tag " + egg + " : ",egghunterfile)
			objegghunterfile.write(egghunter_hex,egghunterfile)			

			if filename == "":
				objegghunterfile.write("Put this tag in front of your shellcode : " + egg + egg,egghunterfile)
			else:
				dbg.log("[+] Shellcode, with tag : ")			
				block = "\"" + egg + egg + "\"\n"
				cnt = 0
				flip = 1
				thisline = "\""
				while cnt < len(data):
					thisline += "\\x%s" % toHexByte(ord(data[cnt]))				
					if (flip == 32) or (cnt == len(data)-1):
						if cnt == len(data)-1 and checksumbyte != "":
							thisline += "\\x%s" % checksumbyte					
						thisline += "\""
						flip = 0
						block += thisline 
						block += "\n"
						thisline = "\""
					cnt += 1
					flip += 1
				dbg.logLines(block)	
				objegghunterfile.write("\nShellcode, with tag :\n",egghunterfile)
				objegghunterfile.write(block,egghunterfile)	
		
			ignoremodules = False
					
			return
		
		#----- Find MSP ------ #
		
		def procFindMSP(args):
			distance = 0
			
			if "distance" in args:
				try:
					distance = int(args["distance"])
				except:
					distance = 0
			if distance < 0:
				dbg.log("** Please provide a positive number as distance",highlight=1)
				return
			mspresults = {}
			mspresults = goFindMSP(distance,args)
			return
			
		def procSuggest(args):
			modulecriteria={}
			criteria={}
			modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
			isEIP = False
			isSEH = False
			isEIPUnicode = False
			isSEHUnicode = False
			initialoffsetSEH = 0
			initialoffsetEIP = 0
			shellcodesizeSEH = 0
			shellcodesizeEIP = 0
			nullsallowed = True
			
			global ignoremodules
			global noheader
			global ptr_to_get
			global silent
			global ptr_counter
			
			targetstr = ""
			exploitstr = ""
			originalauthor = ""
			url = ""
			
			#are we attached to an application ?
			if dbg.getDebuggedPid() == 0:
				dbg.log("** You don't seem to be attached to an application ! **",highlight=1)
				return

			exploittype = ""
			skeletonarg = ""
			usecliargs = False
			validstypes ={}
			validstypes["tcpclient"] = "network client (tcp)"
			validstypes["udpclient"] = "network client (udp)"
			validstypes["fileformat"] = "fileformat"
			exploittypes = [ "fileformat","network client (tcp)","network client (udp)" ]
			if __DEBUGGERAPP__ == "WinDBG" or "t" in args:
				if "t" in args:
					if type(args["t"]).__name__.lower() != "bool":
						skeltype = args["t"].lower()
						skelparts = skeltype.split(":")
						if skelparts[0] in validstypes:
							exploittype = validstypes[skelparts[0]]
							if len(skelparts) > 1:
								skeletonarg = skelparts[1]
							else:
								dbg.log(" ** Please specify the skeleton type AND an argument. **")
								return
							usecliargs = True
						else:
							dbg.log(" ** Please specify a valid skeleton type and an argument. **")
							return							
					else:
						dbg.log(" ** Please specify a skeletontype using -t **",highlight=1)
						return
				else:
					dbg.log(" ** Please specify a skeletontype using -t **",highlight=1)
					return

			mspresults = {}
			mspresults = goFindMSP(100,args)

			#create metasploit skeleton file
			exploitfilename="exploit.rb"
			objexploitfile = MnLog(exploitfilename)

			#ptr_to_get = 5				
			noheader = True
			ignoremodules = True
			exploitfile = objexploitfile.reset()			
			ignoremodules = False
			noheader = False
			
			dbg.log(" ")
			dbg.log("[+] Preparing payload...")
			dbg.log(" ")			
			dbg.updateLog()
			#what options do we have ?
			# 0 : pointer
			# 1 : offset
			# 2 : type
			
			if "registers" in mspresults:
				for reg in mspresults["registers"]:
					if reg.upper() == "EIP":
						isEIP = True
						eipval = mspresults["registers"][reg][0]
						ptrx = MnPointer(eipval)
						initialoffsetEIP = mspresults["registers"][reg][1]
						
			# 0 : pointer
			# 1 : offset
			# 2 : type
			# 3 : size
			if "seh" in mspresults:
				if len(mspresults["seh"]) > 0:
					isSEH = True
					for seh in mspresults["seh"]:
						if mspresults["seh"][seh][2] == "unicode":
							isSEHUnicode = True
						if not isSEHUnicode:
							initialoffsetSEH = mspresults["seh"][seh][1]
						else:
							initialoffsetSEH = mspresults["seh"][seh][1]
						shellcodesizeSEH = mspresults["seh"][seh][3]
						
			if isSEH:
				ignoremodules = True
				noheader = True
				exploitfilename_seh="exploit_seh.rb"
				objexploitfile_seh = MnLog(exploitfilename_seh)
				exploitfile_seh = objexploitfile_seh.reset()				
				ignoremodules = False
				noheader = False

			# start building exploit structure
			
			if not isEIP and not isSEH:
				dbg.log(" ** Unable to suggest anything useful. You don't seem to control EIP or SEH ** ",highlight=1)
				return

			# ask for type of module
			if not usecliargs:
				dbg.log(" ** Please select a skeleton exploit type from the dropdown list **",highlight=1)
				exploittype = dbg.comboBox("Select msf exploit skeleton to build :", exploittypes).lower().strip()

			if not exploittype in exploittypes:
				dbg.log("Boo - invalid exploit type, try again !",highlight=1)
				return


			portnr = 0
			extension = ""
			if exploittype.find("network") > -1:
				if usecliargs:
					portnr = skeletonarg
				else:
					portnr = dbg.inputBox("Remote port number : ")
				try:
					portnr = int(portnr)
				except:
					portnr = 0

			if exploittype.find("fileformat") > -1:
				if usecliargs:
					extension = skeletonarg
				else:
					extension = dbg.inputBox("File extension :")
			
			extension = extension.replace("'","").replace('"',"").replace("\n","").replace("\r","")
			
			if not extension.startswith("."):
				extension = "." + extension	
				
				
			dbg.createLogWindow()
			dbg.updateLog()
			url = ""
			
			badchars = ""
			if "badchars" in criteria:
				badchars = criteria["badchars"]
				
			if "nonull" in criteria:
				if not '\x00' in badchars:
					badchars += '\x00'
			
			skeletonheader,skeletoninit,skeletoninit2 = getSkeletonHeader(exploittype,portnr,extension,url,badchars)
			
			regsto = ""			

			if isEIP:
				dbg.log("[+] Attempting to create payload for saved return pointer overwrite...")
				#where can we jump to - get the register that has the largest buffer size
				largestreg = ""
				largestsize = 0
				offsetreg = 0
				regptr = 0
				# register_to
				# 0 : pointer
				# 1 : offset
				# 2 : size
				# 3 : type
				eipcriteria = criteria
				modulecriteria["aslr"] = False
				modulecriteria["rebase"] = False
				modulecriteria["os"] = False
				jmp_pointers = {}
				jmppointer = 0
				instrinfo = ""

				if isEIPUnicode:
					eipcriteria["unicode"] = True
					eipcriteria["nonull"] = False
					
				if "registers_to" in mspresults:
					for reg in mspresults["registers_to"]:
						regsto += reg+","
						thissize = mspresults["registers_to"][reg][2]
						thisreg = reg
						thisoffset = mspresults["registers_to"][reg][1]
						thisregptr = mspresults["registers_to"][reg][0]
						if thisoffset < initialoffsetEIP:
							#fix the size, which will end at offset to EIP
							thissize = initialoffsetEIP - thisoffset
						if thissize > largestsize:								
							# can we find a jmp to that reg ?
							silent = True
							ptr_counter = 0
							ptr_to_get = 1								
							jmp_pointers = findJMP(modulecriteria,eipcriteria,reg.lower())
							if len( jmp_pointers ) == 0:
								ptr_counter = 0
								ptr_to_get = 1								
								modulecriteria["os"] = True
								jmp_pointers = findJMP(modulecriteria,eipcriteria,reg.lower())
							modulecriteria["os"] = False
							if len( jmp_pointers ) > 0:
								largestsize = thissize 
								largestreg = thisreg
								offsetreg = thisoffset
								regptr = thisregptr
							silent = False
				regsto = regsto.rstrip(",")
				
				
				if largestreg == "":
					dbg.log("    Payload is referenced by at least one register (%s), but I couldn't seem to find" % regsto,highlight=1)
					dbg.log("    a way to jump to that register",highlight=1)
				else:
					#build exploit
					for ptrtype in jmp_pointers:
						jmppointer = jmp_pointers[ptrtype][0]
						instrinfo = ptrtype
						break
					ptrx = MnPointer(jmppointer)
					modname = ptrx.belongsTo()
					targetstr = "      'Targets'    =>\n"
					targetstr += "        [\n"
					targetstr += "          [ '<fill in the OS/app version here>',\n"
					targetstr += "            {\n"
					if not isEIPUnicode:
						targetstr += "              'Ret'     =>  0x" + toHex(jmppointer) + ", # " + instrinfo + " - " + modname + "\n"
						targetstr += "              'Offset'  =>  " + str(initialoffsetEIP) + "\n"
					else:
						origptr = toHex(jmppointer)
						#real unicode ?
						unicodeptr = ""
						transforminfo = ""
						if origptr[0] == "0" and origptr[1] == "0" and origptr[4] == "0" and origptr[5] == "0":					
							unicodeptr = "\"\\x" + origptr[6] + origptr[7] + "\\x" + origptr[2] + origptr[3] + "\""
						else:
							#transform
							transform = UnicodeTransformInfo(origptr)
							transformparts = transform.split(",")
							transformsubparts = transformparts[0].split(" ")
							origptr = transformsubparts[len(transformsubparts)-1]
							transforminfo = " #unicode transformed to 0x" + toHex(jmppointer)
							unicodeptr = "\"\\x" + origptr[6] + origptr[7] + "\\x" + origptr[2] + origptr[3] + "\""
						targetstr += "              'Ret'     =>  " + unicodeptr + "," + transforminfo + "# " + instrinfo + " - " + modname + "\n"
						targetstr += "              'Offset'  =>  " + str(initialoffsetEIP) + "  #Unicode\n"	
					
					targetstr += "            }\n"
					targetstr += "          ],\n"
					targetstr += "        ],\n"

					exploitstr = "  def exploit\n\n"
					if exploittype.find("network") > -1:
						if exploittype.find("tcp") > -1:
							exploitstr += "\n    connect\n\n"
						elif exploittype.find("udp") > -1:
							exploitstr += "\n    connect_udp\n\n"
					
					if initialoffsetEIP < offsetreg:
						# eip is before shellcode
						exploitstr += "    buffer =  rand_text(target['Offset'])  \n"
						if not isEIPUnicode:
							exploitstr += "    buffer << [target.ret].pack('V')  \n"
						else:
							exploitstr += "    buffer << target['Ret']  #Unicode friendly jump\n\n"
						if offsetreg > initialoffsetEIP+2:
							if not isEIPUnicode:
								if (offsetreg - initialoffsetEIP - 4) > 0:
									exploitstr += "    buffer << rand_text(" + str(offsetreg - initialoffsetEIP - 4) + ")  #junk\n"
							else:
								if ((offsetreg - initialoffsetEIP - 4)/2) > 0:
									exploitstr += "    buffer << rand_text(" + str((offsetreg - initialoffsetEIP - 4)/2) + ")  #unicode junk\n"
						stackadjust = 0
						if largestreg.upper() == "ESP":
							if not isEIPUnicode:
								exploitstr += "    buffer << Metasm::Shellcode.assemble(Metasm::Ia32.new, 'add esp,-1500').encode_string # avoid GetPC shellcode corruption\n"
								stackadjust = 6
								exploitstr += "    buffer << payload.encoded  #max " + str(largestsize - stackadjust) + " bytes\n"
						if isEIPUnicode:
							exploitstr += "    # Metasploit requires double encoding for unicode : Use alpha_xxxx encoder in the payload section\n"
							exploitstr += "    # and then manually encode with unicode inside the exploit section :\n\n"
							exploitstr += "    enc = framework.encoders.create('x86/unicode_mixed')\n\n"
							exploitstr += "    register_to_align_to = '" + largestreg.upper() + "'\n\n"
							if largestreg.upper() == "ESP":
								exploitstr += "    # Note : since you are using ESP as bufferregister, make sure EBP points to a writeable address !\n"
								exploitstr += "    # or patch the unicode decoder yourself\n"
							exploitstr += "    enc.datastore.import_options_from_hash({ 'BufferRegister' => register_to_align_to })\n\n"
							exploitstr += "    unicodepayload = enc.encode(payload.encoded, nil, nil, platform)\n\n"
							exploitstr += "    buffer << unicodepayload"
								
					else:
						# EIP -> jump to location before EIP
						beforeEIP = initialoffsetEIP - offsetreg
						if beforeEIP > 0:
							if offsetreg > 0:
								exploitstr += "    buffer = rand_text(" + str(offsetreg)+")  #offset to " + largestreg+"\n"
								exploitstr += "    buffer << payload.encoded  #max " + str(initialoffsetEIP - offsetreg) + " bytes\n"
								exploitstr += "    buffer << rand_text(target['Offset'] - payload.encoded.length)\n"
								exploitstr += "    buffer << [target.ret].pack('V')  \n"
							else:
								exploitstr += "    buffer = payload.encoded  #max " + str(initialoffsetEIP - offsetreg) + " bytes\n"
								exploitstr += "    buffer << rand_text(target['Offset'] - payload.encoded.length)\n"
								exploitstr += "    buffer << [target.ret].pack('V')  \n"

					if exploittype.find("network") > -1:
						exploitstr += "\n    print_status(\"Trying target #{target.name}...\")\n"
						if exploittype.find("tcp") > -1:
							exploitstr += "    sock.put(buffer)\n"
							exploitstr += "\n    handler\n"
						elif exploittype.find("udp") > -1:
							exploitstr += "    udp_sock.put(buffer)\n"
							exploitstr += "\n    handler(udp_sock)\n"
					if exploittype == "fileformat":
						exploitstr += "\n    file_create(buffer)\n\n"
					
					if exploittype.find("network") > -1:
						exploitstr += "    disconnect\n\n"
					exploitstr += "  end\n"					
					dbg.log("Metasploit 'Targets' section :")
					dbg.log("------------------------------")
					dbg.logLines(targetstr.replace("  ","    "))
					dbg.log("")
					dbg.log("Metasploit 'exploit' function :")
					dbg.log("--------------------------------")
					dbg.logLines(exploitstr.replace("  ","    "))
					
					#write skeleton
					objexploitfile.write(skeletonheader+"\n",exploitfile)
					objexploitfile.write(skeletoninit+"\n",exploitfile)
					objexploitfile.write(targetstr,exploitfile)
					objexploitfile.write(skeletoninit2,exploitfile)		
					objexploitfile.write(exploitstr,exploitfile)
					objexploitfile.write("end",exploitfile)					
					
			
			if isSEH:
				dbg.log("[+] Attempting to create payload for SEH record overwrite...")
				sehcriteria = criteria
				modulecriteria["safeseh"] = False
				modulecriteria["rebase"] = False
				modulecriteria["aslr"] = False
				modulecriteria["os"] = False
				sehptr = 0
				instrinfo = ""
				if isSEHUnicode:
					sehcriteria["unicode"] = True
					if "nonull" in sehcriteria:
						sehcriteria.pop("nonull")
				modulecriteria["safeseh"] = False
				#get SEH pointers
				silent = True
				ptr_counter = 0
				ptr_to_get = 1					
				seh_pointers = findSEH(modulecriteria,sehcriteria)
				jmpback = False
				silent = False
				if not isSEHUnicode:
					#did we find a pointer ?
					if len(seh_pointers) == 0:
						#did we try to avoid nulls ?
						dbg.log("[+] No non-null pointers found, trying 'jump back' layout now...")
						if "nonull" in sehcriteria:
							if sehcriteria["nonull"] == True:
								sehcriteria.pop("nonull")
								silent = True
								ptr_counter = 0
								ptr_to_get = 1									
								seh_pointers = findSEH(modulecriteria,sehcriteria)
								silent = False
								jmpback = True
					if len(seh_pointers) != 0:
						for ptrtypes in seh_pointers:
							sehptr = seh_pointers[ptrtypes][0]
							instrinfo = ptrtypes
							break
				else:
					if len(seh_pointers) == 0:
						sehptr = 0
					else:
						for ptrtypes in seh_pointers:
							sehptr = seh_pointers[ptrtypes][0]
							instrinfo = ptrtypes
							break
						
				if sehptr != 0:
					ptrx = MnPointer(sehptr)
					modname = ptrx.belongsTo()
					mixin = ""
					if not jmpback:
						mixin += "#Don't forget to include the SEH mixin !\n"
						mixin += "include Msf::Exploit::Seh\n\n"
						skeletonheader += "  include Msf::Exploit::Seh\n"

					targetstr = "      'Targets'    =>\n"
					targetstr += "        [\n"
					targetstr += "          [ '<fill in the OS/app version here>',\n"
					targetstr += "            {\n"
					if not isSEHUnicode:
						targetstr += "              'Ret'     =>  0x" + toHex(sehptr) + ", # " + instrinfo + " - " + modname + "\n"
						targetstr += "              'Offset'  =>  " + str(initialoffsetSEH) + "\n"							
					else:
						origptr = toHex(sehptr)
						#real unicode ?
						unicodeptr = ""
						transforminfo = ""
						if origptr[0] == "0" and origptr[1] == "0" and origptr[4] == "0" and origptr[5] == "0":					
							unicodeptr = "\"\\x" + origptr[6] + origptr[7] + "\\x" + origptr[2] + origptr[3] + "\""
						else:
							#transform
							transform = UnicodeTransformInfo(origptr)
							transformparts = transform.split(",")
							transformsubparts = transformparts[0].split(" ")
							origptr = transformsubparts[len(transformsubparts)-1]
							transforminfo = " #unicode transformed to 0x" + toHex(sehptr)
							unicodeptr = "\"\\x" + origptr[6] + origptr[7] + "\\x" + origptr[2] + origptr[3] + "\""
						targetstr += "              'Ret'     =>  " + unicodeptr + "," + transforminfo + " # " + instrinfo + " - " + modname + "\n"
						targetstr += "              'Offset'  =>  " + str(initialoffsetSEH) + "  #Unicode\n"						
					targetstr += "            }\n"
					targetstr += "          ],\n"
					targetstr += "        ],\n"

					exploitstr = "  def exploit\n\n"
					if exploittype.find("network") > -1:
						exploitstr += "\n    connect\n\n"
					
					if not isSEHUnicode:
						if not jmpback:
							exploitstr += "    buffer = rand_text(target['Offset'])  #junk\n"
							exploitstr += "    buffer << generate_seh_record(target.ret)\n"
							exploitstr += "    buffer << payload.encoded  #" + str(shellcodesizeSEH) +" bytes of space\n"
							exploitstr += "    # more junk may be needed to trigger the exception\n"
						else:
							exploitstr += "    jmp_back = Rex::Arch::X86.jmp_short(-payload.encoded.length-5)\n\n"
							exploitstr += "    buffer = rand_text(target['Offset'] - payload.encoded.length - jmp_back.length)  #junk\n"
							exploitstr += "    buffer << payload.encoded\n"
							exploitstr += "    buffer << jmp_back  #jump back to start of payload.encoded\n"
							exploitstr += "    buffer << '\\xeb\\xf9\\x41\\x41'  #nseh, jump back to jmp_back\n"
							exploitstr += "    buffer << [target.ret].pack('V')  #seh\n"
					else:
						exploitstr += "    nseh = <insert 2 bytes that will acts as nseh walkover>\n"
						exploitstr += "    align = <insert routine to align a register to begin of payload and jump to it>\n\n"
						exploitstr += "    padding = <insert bytes to fill space between alignment code and payload>\n\n"
						exploitstr += "    # Metasploit requires double encoding for unicode : Use alpha_xxxx encoder in the payload section\n"
						exploitstr += "    # and then manually encode with unicode inside the exploit section :\n\n"
						exploitstr += "    enc = framework.encoders.create('x86/unicode_mixed')\n\n"
						exploitstr += "    register_to_align_to = <fill in the register name you will align to>\n\n"
						exploitstr += "    enc.datastore.import_options_from_hash({ 'BufferRegister' => register_to_align_to })\n\n"
						exploitstr += "    unicodepayload = enc.encode(payload.encoded, nil, nil, platform)\n\n"
						exploitstr += "    buffer = rand_text(target['Offset'])  #unicode junk\n"
						exploitstr += "    buffer << nseh  #Unicode walkover friendly dword\n"
						exploitstr += "    buffer << target['Ret']  #Unicode friendly p/p/r\n"
						exploitstr += "    buffer << align\n"
						exploitstr += "    buffer << padding\n"
						exploitstr += "    buffer << unicodepayload\n"
						
					if exploittype.find("network") > -1:
						exploitstr += "\n    print_status(\"Trying target #{target.name}...\")\n"					
						exploitstr += "    sock.put(buffer)\n\n"
						exploitstr += "    handler\n"
					if exploittype == "fileformat":
						exploitstr += "\n    file_create(buffer)\n\n"						
					if exploittype.find("network") > -1:
						exploitstr += "    disconnect\n\n"						
						
					exploitstr += "  end\n"
					if mixin != "":
						dbg.log("Metasploit 'include' section :")
						dbg.log("------------------------------")
						dbg.logLines(mixin)
					dbg.log("Metasploit 'Targets' section :")
					dbg.log("------------------------------")
					dbg.logLines(targetstr.replace("  ","    "))
					dbg.log("")
					dbg.log("Metasploit 'exploit' function :")
					dbg.log("--------------------------------")
					dbg.logLines(exploitstr.replace("  ","    "))
					
					
					#write skeleton
					objexploitfile_seh.write(skeletonheader+"\n",exploitfile_seh)
					objexploitfile_seh.write(skeletoninit+"\n",exploitfile_seh)
					objexploitfile_seh.write(targetstr,exploitfile_seh)
					objexploitfile_seh.write(skeletoninit2,exploitfile_seh)		
					objexploitfile_seh.write(exploitstr,exploitfile_seh)
					objexploitfile_seh.write("end",exploitfile_seh)					
					
				else:
					dbg.log("    Unable to suggest a buffer layout because I couldn't find any good pointers",highlight=1)
			
			return	

		#-----stacks-----#
		def procStacks(args):
			stacks = getStacks()
			if len(stacks) > 0:
				dbg.log("Stacks :")
				dbg.log("--------")
				for threadid in stacks:
					dbg.log("Thread %s : Stack : 0x%s - 0x%s (size : 0x%s)" % (str(threadid),toHex(stacks[threadid][0]),toHex(stacks[threadid][1]),toHex(stacks[threadid][1]-stacks[threadid][0])))
			else:
				dbg.log("No threads/stacks found !",highlight=1)
			return

		#------heapstuff-----#
			
		def procHeap(args):
		
			os = dbg.getOsVersion()
			heapkey = 0

			#first, print list of heaps
			allheaps = []
			try:
				allheaps = dbg.getHeapsAddress()
			except:
				allheaps = []
			dbg.log("Peb : 0x%08x, NtGlobalFlag : 0x%08x" % (dbg.getPEBAddress(),getNtGlobalFlag()))
			dbg.log("Heaps:")
			dbg.log("------")
			if len(allheaps) > 0:
				for heap in allheaps:
					segments = getSegmentList(heap)
					segmentlist = []
					for segment in segments:
						segmentlist.append(segment)
					if not win7mode:
						segmentlist.sort()
					segmentinfo = ""
					for segment in segmentlist:
						segmentinfo = segmentinfo + "0x%08x" % segment + ","
					segmentinfo = segmentinfo.strip(",")
					segmentinfo = " : " + segmentinfo
					defheap = ""
					lfhheap = ""
					keyinfo = ""
					if heap == getDefaultProcessHeap():
						defheap = "* Default process heap"
					if win7mode:
						iHeap = MnHeap(heap)
						if iHeap.usesLFH():
							lfhheapaddress = iHeap.getLFHAddress()
							lfhheap = "[LFH enabled, _LFH_HEAP at 0x%08x]" % lfhheapaddress
						if iHeap.getEncodingKey() > 0:
							keyinfo = "Encoding key: 0x%08x" % iHeap.getEncodingKey()
					dbg.log("0x%08x (%d segment(s)%s) %s %s %s" % (heap,len(segments),segmentinfo,defheap,lfhheap,keyinfo))
			else:
				dbg.log(" ** No heaps found")
			dbg.log("")

			heapbase = 0
			searchtype = ""
			searchtypes = ["lal","lfh","all","segments", "chunks", "layout", "fea", "bea"]
			error = False
			filterafter = ""
			
			showdata = False
			findvtablesize = True
			expand = False

			minstringlength = 32
			
			if len(allheaps) > 0:
				if "h" in args and type(args["h"]).__name__.lower() != "bool":
					hbase = args["h"].replace("0x","").replace("0X","")
					if not (isAddress(hbase) or hbase.lower() == "default"):
						dbg.log("%s is an invalid address" % args["h"], highlight=1)
						return
					else:
						if hbase.lower() == "default":
							heapbase = getDefaultProcessHeap()
						else:
							heapbase = hexStrToInt(hbase)
			
				if "t" in args:
					if type(args["t"]).__name__.lower() != "bool":
						searchtype = args["t"].lower().replace('"','').replace("'","")
						if searchtype == "blocks":
							dbg.log("** Note : type 'blocks' has been replaced with 'chunks'",highlight=1)
							dbg.log("")
							searchtype = "chunks"
						if not searchtype in searchtypes:
							searchtype = ""
					else:
						searchtype = ""

				if "after" in args:
					if type(args["after"]).__name__.lower() != "bool":
						filterafter = args["after"].replace('"','').replace("'","")
						
				if "v" in args:
					showdata = True
					
				if "expand" in args:
					expand = True
					
				if "fast" in args:
					findvtablesize = False 
					showdata = False
				
				if searchtype == "" and not "stat" in args:
					dbg.log("Please specify a valid searchtype -t",highlight=1)
					dbg.log("Valid values are :",highlight=1)
					for val in searchtypes:
						if val != "blocks":	
							dbg.log("   %s" % val,highlight=1)
					error = True

				if "h" in args and heapbase == 0:
					dbg.log("Please specify a valid heap base address -h",highlight=1)
					error = True

				if "size" in args:
					if type(args["size"]).__name__.lower() != "bool":
						size = args["size"].lower()
						if size.startswith("0x"):
							minstringlength = hexStrToInt(size)
						else:
							minstringlength = int(size)
					else:
						dbg.log("Please provide a valid size -size",highlight=1)
						error = True

				if "clearcache" in args:
					dbg.forgetKnowledge("vtableCache")
					dbg.log("[+] vtableCache cleared.")
			
			else:
				dbg.log("No heaps found",highlight=1)
				return
			
			heap_to_query = []
			heapfound = False
			
			if "h" in args:
				for heap in allheaps:
					if heapbase == heap:
						heapfound = True
						heap_to_query = [heapbase]
				if not heapfound:
					error = True
					dbg.log("0x%08x is not a valid heap base address" % heapbase,highlight=1)
			else:
				#show all heaps
				for heap in allheaps:
					heap_to_query.append(heap)
			
			if error:
				return
			else:
				statinfo = {}
				logfile_b = ""
				thislog_b = ""
				logfile_l = ""
				logfile_l = ""

				if searchtype == "chunks" or searchtype == "all":
					logfile_b = MnLog("heapchunks.txt")
					thislog_b = logfile_b.reset()

				if searchtype == "layout" or searchtype == "all":
					logfile_l = MnLog("heaplayout.txt")
					thislog_l = logfile_l.reset()

				for heapbase in heap_to_query:
					mHeap = MnHeap(heapbase)
					heapbase_extra = ""
					frontendinfo = []
					frontendheapptr = 0
					frontendheaptype = 0
					if win7mode:
						heapkey = mHeap.getEncodingKey()
						if mHeap.usesLFH():
							frontendheaptype = 0x2
							heapbase_extra = " [LFH] "
							frontendheapptr = mHeap.getLFHAddress()
					frontendinfo = [frontendheaptype,frontendheapptr]
						
					dbg.log("")
					dbg.log("[+] Processing heap 0x%08x%s" % (heapbase,heapbase_extra))

					if searchtype == "fea":
						if win7mode:
							searchtype = "lfh"
						else:
							searchtype = "lal"
					if searchtype == "bea":
							searchtype = "freelist"

					# LookAsideList
					if searchtype == "lal" or (searchtype == "all" and not win7mode):
						lalindex = 0
						if win7mode:
							dbg.log(" !! This version of the OS doesn't have a LookAside List !!")
						else:
							dbg.log("[+] FrontEnd Allocator : LookAsideList")
							dbg.log("[+] Getting LookAsideList for heap 0x%08x" % heapbase)
							# do we have a LAL for this heap ?
							FrontEndHeap = mHeap.getFrontEndHeap()
							if FrontEndHeap > 0:
								dbg.log("    FrontEndHeap: 0x%08x" % FrontEndHeap)
								fea_lal = mHeap.getLookAsideList()
								dbg.log("    Nr of (non-empty) LookAside Lists : %d" % len(fea_lal))
								dbg.log("")
								for lal_table_entry in sorted(fea_lal.keys()):
									expectedsize = lal_table_entry * 8
									nr_of_chunks = len(fea_lal[lal_table_entry])
									lalhead = struct.unpack('<L',dbg.readMemory(FrontEndHeap + (0x30 * lal_table_entry),4))[0]
									dbg.log("LAL [%d] @0x%08x, Expected Chunksize 0x%x (%d), Flink : 0x%08x" % (lal_table_entry,FrontEndHeap + (0x30 * lal_table_entry),expectedsize,expectedsize,lalhead))
									mHeap.showLookAsideHead(lal_table_entry)
									dbg.log("  %d chunks:" % nr_of_chunks)
									for chunkindex in fea_lal[lal_table_entry]:
										lalchunk = fea_lal[lal_table_entry][chunkindex]
										chunksize = lalchunk.size * 8
										flag = getHeapFlag(lalchunk.flag)
										data = ""
										if showdata:
											data = bin2hex(dbg.readMemory(lalchunk.userptr,16))
										dbg.log("     ChunkPtr: 0x%08x, UserPtr: 0x%08x, Flink: 0x%08x, ChunkSize: 0x%x, UserSize: 0x%x, Userspace: 0x%x (%s) %s" % (lalchunk.chunkptr, lalchunk.userptr,lalchunk.flink,chunksize,lalchunk.usersize,lalchunk.usersize+lalchunk.remaining,flag,data))
										if chunksize != expectedsize:
											dbg.log("               ^^ ** Warning - unexpected size value, header corrupted ? **",highlight=True)
									dbg.log("")
							else:
								dbg.log("[+] No LookAsideList found for this heap")
								dbg.log("")

					if searchtype == "lfh" or (searchtype == "all" and win7mode):
						dbg.log("[+] FrontEnd Allocator : Low Fragmentation Heap")
						dbg.log("     ** Not implemented yet **")
						
					if searchtype == "freelist" or (searchtype == "all" and not win7mode):
						flindex = 0
						dbg.log("[+] BackEnd Allocator : FreeLists")
						dbg.log("[+] Getting FreeLists for heap 0x%08x" % heapbase)
						thisfreelist = mHeap.getFreeList()
						thisfreelistinusebitmap = mHeap.getFreeListInUseBitmap()
						bitmapstr = ""
						for bit in thisfreelistinusebitmap:
							bitmapstr += str(bit)
						dbg.log("[+] FreeListsInUseBitmap:")
						printDataArray(bitmapstr,32,prefix="    ")
						# make sure the freelist is printed in the correct order
						flindex = 0
						while flindex < 128:
							if flindex in thisfreelist:
								freelist_addy = heapbase + 0x178 + (8 * flindex)
								expectedsize = ">1016"
								expectedsize2 = ">0x%x" % 1016
								if flindex != 0:
									expectedsize2 = str(8 * flindex)
									expectedsize = "0x%x" % (8 * flindex)			
								dbg.log("[+] FreeList[%02d] at 0x%08x, Expected size: %s (%s)" % (flindex,freelist_addy,expectedsize,expectedsize2))
								flindicator = 0
								for flentry in thisfreelist[flindex]:
									freelist_chunk = thisfreelist[flindex][flentry]
									chunksize = freelist_chunk.size * 8
									dbg.log("     ChunkPtr: 0x%08x, Header: 0x%x bytes, UserPtr: 0x%08x, Flink: 0x%08x, Blink: 0x%08x, ChunkSize: 0x%x (%d), Usersize: 0x%x (%d) " % (freelist_chunk.chunkptr, freelist_chunk.headersize, freelist_chunk.userptr,freelist_chunk.flink,freelist_chunk.blink,chunksize,chunksize,freelist_chunk.usersize,freelist_chunk.usersize))
									if flindex != 0 and chunksize != (8*flindex):
										dbg.log("     ** Header may be corrupted! **", highlight = True)
									flindicator = 1
								if flindex > 1 and int(bitmapstr[flindex]) != flindicator:
									dbg.log("     ** FreeListsInUseBitmap mismatch for index %d! **" % flindex, highlight = True)
							flindex += 1

					if searchtype == "layout" or searchtype == "all":
						segments = getSegmentsForHeap(heapbase)

						sortedsegments = []
						global vtableCache
						# read vtableCache from knowledge
						vtableCache = dbg.getKnowledge("vtableCache")
						if vtableCache is None:
							vtableCache = {}

						for seg in segments:
							sortedsegments.append(seg)
						if not win7mode:
							sortedsegments.sort()
						segmentcnt = 0
						minstringlen = minstringlength
						blockmem = []
						nr_filter_matches = 0

						vablocks = []
						# VirtualAllocdBlocks
						vachunks = mHeap.getVirtualAllocdBlocks()
						infoblocks = {}
						infoblocks["segments"] = sortedsegments
						if expand:
							infoblocks["virtualallocdblocks"] = [vachunks]

						for infotype in infoblocks:
							heapdata = infoblocks[infotype]
							for thisdata in heapdata:
								if infotype == "segments":
									seg = thisdata
									segmentcnt += 1
									segstart = segments[seg][0]
									segend = segments[seg][1]
									FirstEntry = segments[seg][2]
									LastValidEntry = segments[seg][3]								
									datablocks = walkSegment(FirstEntry,LastValidEntry,heapbase)
									tolog = "----- Heap 0x%08x%s, Segment 0x%08x - 0x%08x (%d/%d) -----" % (heapbase,heapbase_extra,segstart,segend,segmentcnt,len(sortedsegments))

								if infotype == "virtualallocdblocks":
									datablocks = heapdata[0]
									tolog = "----- Heap 0x%08x%s, VirtualAllocdBlocks : %d" % (heapbase,heapbase_extra,len(datablocks))

								logfile_l.write(" ",thislog_l)								
								dbg.log(tolog)
								logfile_l.write(tolog,thislog_l)

								sortedblocks = []
								for block in datablocks:
									sortedblocks.append(block)
								sortedblocks.sort()								

								# for each block, try to get info
								# object ?
								# BSTR ?
								# str ?
								for block in sortedblocks:
									showinlog = False
									thischunk = datablocks[block]
									unused = thischunk.unused
									headersize = thischunk.headersize
									flags = getHeapFlag(thischunk.flag)
									userptr = block + headersize
									psize = thischunk.prevsize * 8
									blocksize = thischunk.size * 8
									selfsize = blocksize
									usersize = selfsize - unused				
									usersize = blocksize - unused
									extratxt = ""	
									if infotype == "virtualallocdblocks":
										selfsize = thischunk.commitsize * 8
										blocksize = selfsize
										usersize = selfsize - unused
										nextblock = thischunk.flink
									# read block into memory
									blockmem = dbg.readMemory(block,blocksize)

									# first, find all strings (ascii, unicode and BSTR)
									asciistrings = {}
									unicodestrings = {}
									bstr = {}
									objects = {}
									asciistrings = getAllStringOffsets(blockmem,minstringlen)

									# determine remaining subsets of the original block
									remaining = {}
									curpos = 0
									for stringpos in asciistrings:
										if stringpos > curpos:
											remaining[curpos] = stringpos - curpos
											curpos = asciistrings[stringpos]
									if curpos < blocksize:
										remaining[curpos] = blocksize

									# search for unicode in remaining subsets only - tx for the regex help Turboland !
									for remstart in remaining:
										remend = remaining[remstart]
										thisunicodestrings = getAllUnicodeStringOffsets(blockmem[remstart:remend],minstringlen,remstart)
										# append results to master list
										for tus in thisunicodestrings:
											unicodestrings[tus] = thisunicodestrings[tus]

									# check each unicode, maybe it's a BSTR
									tomove = []
									for unicodeoffset in unicodestrings:
										delta = unicodeoffset
										size = (unicodestrings[unicodeoffset] - unicodeoffset)/2
										if delta >= 4:
											maybesize = struct.unpack('<L',blockmem[delta-3:delta+1])[0] # it's an offset, remember ?
											if maybesize == (size*2):
												tomove.append(unicodeoffset)
												bstr[unicodeoffset] = unicodestrings[unicodeoffset]
									for todel in tomove:
										del unicodestrings[todel]

									# get objects too
									# find all unique objects
									# again, just store offset
									objects = {}
									orderedobj = []
									if __DEBUGGERAPP__ == "WinDBG":
										nrlines = int(float(blocksize) / 4)
										cmd2run = "dds 0x%08x L 0x%x" % ((block + headersize),nrlines)
										output = dbg.nativeCommand(cmd2run)
										outputlines = output.split("\n")
										for line in outputlines:
											if line.find("::") > -1 and line.find("vftable") > -1:
												parts = line.split(" ")
												objconstr = ""
												if len(parts) > 3:
													objectptr = hexStrToInt(parts[0])
													cnt = 2
													objectinfo = ""
													while cnt < len(parts):
														objectinfo += parts[cnt] + " "
														cnt += 1
													parts2 = line.split("::")
													parts2name = ""
													pcnt = 0
													while pcnt < len(parts2)-1:
														parts2name = parts2name + "::" + parts2[pcnt]
														pcnt += 1
													parts3 = parts2name.split(" ")
													if len(parts3) > 3:
														objconstr = parts3[3]
													if not objectptr in objects:
														objects[objectptr-block] = [objectinfo,objconstr]
													objsize = 0
													if findvtablesize:
														if not objconstr in vtableCache:
															cmd2run = "u %s::CreateElement L 12" % objconstr
															objoutput = dbg.nativeCommand(cmd2run)
															if not "HeapAlloc" in objoutput:
																cmd2run = "x %s::operator*" % objconstr
																oplist = dbg.nativeCommand(cmd2run)
																oplines = oplist.split("\n")
																oppat = "%s::operator" % objconstr
																for opline in oplines:
																	if oppat in opline and not "del" in opline:
																		lineparts = opline.split(" ")
																		cmd2run = "uf %s" % lineparts[0]
																		objoutput = dbg.nativeCommand(cmd2run)
																		break
															if "HeapAlloc" in objoutput:
																objlines = objoutput.split("\n")
																lineindex = 0
																for objline in objlines:
																	if "HeapAlloc" in objline:
																		if lineindex >= 3:
																			sizeline = objlines[lineindex-3]
																			if "push" in sizeline:
																				sizelineparts = sizeline.split("push")
																				if len(sizelineparts) > 1:
																					sizevalue = sizelineparts[len(sizelineparts)-1].replace(" ","").replace("h","")
																					try:
																						objsize = hexStrToInt(sizevalue)
																						# adjust allocation granulariy
																						remainsize = objsize - ((objsize / 8) * 8)
																						while remainsize != 0:
																							objsize += 1
																							remainsize = objsize - ((objsize / 8) * 8)
																					except:
																						#print traceback.format_exc()
																						objsize = 0
																				break
																	lineindex += 1
															vtableCache[objconstr] = objsize
														else:
															objsize = vtableCache[objconstr]

									# remove object entries that belong to the same object
									allobjects = []
									objectstodelete = []
									for optr in objects:
										allobjects.append(optr)
									allobjects.sort()
									skipuntil = 0
									for optr in allobjects:
										if optr < skipuntil:
											objectstodelete.append(optr)
										else:
											objname = objects[optr][1]
											objsize = 0
											try:
												objsize = vtableCache[objname]
											except:
												objsize = 0
											skipuntil = optr + objsize
									# remove vtable lines that are too close to each other
									minvtabledistance = 0x0c
									prevvname = ""
									prevptr = 0
									thisvname = ""
									for optr in allobjects:
										thisvname = objects[optr][1]
										if thisvname == prevvname and (optr - prevptr) <= minvtabledistance:
											if not optr in objectstodelete:
												objectstodelete.append(optr)
										else:
											prevptr = optr
											prevvname = thisvname


									for vtableptr in objectstodelete:
										del objects[vtableptr]

									for obj in objects:
										orderedobj.append(obj)

									for ascstring in asciistrings:
										orderedobj.append(ascstring)

									for unicodestring in unicodestrings:
										orderedobj.append(unicodestring)

									for bstrobj in bstr:
										orderedobj.append(bstrobj)

									orderedobj.sort()

									# print out details for this chunk
									chunkprefix = ""
									fieldname1 = "Usersize"
									fieldname2 = "ChunkSize"
									if infotype == "virtualallocdblocks":
										chunkprefix = "VA "
										fieldname1 = "CommitSize"
									tolog = "%sChunk 0x%08x (%s 0x%x, %s 0x%x) : %s" % (chunkprefix,block,fieldname1,usersize,fieldname2,usersize+unused,flags)
									if showdata:
										dbg.log(tolog)
									logfile_l.write(tolog,thislog_l)

									previousptr = block
									previoussize = 0
									showinlog = False
									for ptr in orderedobj:
										ptrtype = ""
										ptrinfo = ""
										data = ""
										alldata = ""
										blockinfo = ""
										ptrbytes = 0
										endptr = 0
										datasize = 0
										ptrchars = 0
										infoptr = block + ptr
										endptr = 0
										if ptr in asciistrings:
											ptrtype = "String"
											dataend = asciistrings[ptr]
											data = blockmem[ptr:dataend]
											alldata = data
											ptrbytes = len(data)
											ptrchars = ptrbytes
											datasize = ptrbytes
											if ptrchars > 100:
												data = data[0:100]+"..."
											blockinfo = "%s (Data : 0x%x/%d bytes, 0x%x/%d chars) : %s" % (ptrtype,ptrbytes,ptrbytes,ptrchars,ptrchars,data)
											infoptr = block + ptr
											endptr = infoptr + ptrchars -  1  # need -1
										elif ptr in bstr:
											ptrtype = "BSTR"
											dataend = bstr[ptr]
											data = blockmem[ptr:dataend].replace("\x00","")
											alldata = data
											ptrchars = len(data)
											ptrbytes = ptrchars*2
											datasize = ptrbytes+6
											infoptr = block + ptr - 3
											if ptrchars > 100:
												data = data[0:100]+"..."
											blockinfo = "%s 0x%x/%d bytes (Data : 0x%x/%d bytes, 0x%x/%d chars) : %s" % (ptrtype,ptrbytes+6,ptrbytes+6,ptrbytes,ptrbytes,ptrchars,ptrchars,data)
											endptr = infoptr + ptrbytes + 6
										elif ptr in unicodestrings:
											ptrtype = "Unicode"
											dataend = unicodestrings[ptr]
											data = blockmem[ptr:dataend].replace("\x00","")
											alldata = ""
											ptrchars = len(data)
											ptrbytes = ptrchars * 2
											datasize = ptrbytes
											if ptrchars > 100:
												data = data[0:100]+"..."
											blockinfo = "%s (0x%x/%d bytes, 0x%x/%d chars) : %s" % (ptrtype,ptrbytes,ptrbytes,ptrchars,ptrchars,data)
											endptr = infoptr + ptrbytes + 2
										elif ptr in objects:
											ptrtype = "Object"
											data = objects[ptr][0]
											vtablename = objects[ptr][1]
											datasize = 0
											if vtablename in vtableCache:
												datasize = vtableCache[vtablename]
											alldata = data
											if datasize > 0:
												blockinfo = "%s (0x%x bytes): %s" % (ptrtype,datasize,data)
											else:
												blockinfo = "%s : %s" % (ptrtype,data)
											endptr = infoptr + datasize

										# calculate delta
										slackspace = infoptr - previousptr
										if endptr > 0 and not ptrtype=="Object":
											if slackspace >= 0:
												tolog = "  +%04x @ %08x->%08x : %s" % (slackspace,infoptr,endptr,blockinfo)
											else:
												tolog = "       @ %08x->%08x : %s" % (infoptr,endptr,blockinfo)
										else:
											if slackspace >= 0:
												if endptr != infoptr:
													tolog = "  +%04x @ %08x->%08x : %s" % (slackspace,infoptr,endptr,blockinfo)
												else:
													tolog = "  +%04x @ %08x           : %s" % (slackspace,infoptr,blockinfo)
											else:
												tolog = "        @ %08x           : %s" % (infoptr,blockinfo)

										if filterafter == "" or (filterafter != "" and filterafter in alldata):
											showinlog = True  # keep this for the entire block
											if (filterafter != ""):
												nr_filter_matches += 1
										if showinlog:
											if showdata:
												dbg.log(tolog)
											logfile_l.write(tolog,thislog_l)
										
										previousptr = endptr
										previoussize = datasize

						# save vtableCache again
						if filterafter != "":
							tolog = "Nr of filter matches: %d" % nr_filter_matches
							if showdata:
								dbg.log("")
								dbg.log(tolog)
							logfile_l.write("",thislog_l)
							logfile_l.write(tolog,thislog_l)
						dbg.addKnowledge("vtableCache",vtableCache)


					if searchtype in ["segments","all","chunks"] or "stat" in args:
						segments = getSegmentsForHeap(heapbase)
						dbg.log("Segment List for heap 0x%08x:" % (heapbase))
						dbg.log("---------------------------------")
						sortedsegments = []
						for seg in segments:
							sortedsegments.append(seg)
						if not win7mode:
							sortedsegments.sort()
						vablocks = []
						# VirtualAllocdBlocks
						vachunks = mHeap.getVirtualAllocdBlocks()
						infoblocks = {}
						infoblocks["segments"] = sortedsegments
						if searchtype in ["all","chunks"]:
							infoblocks["virtualallocdblocks"] = [vachunks]

						for infotype in infoblocks:
							heapdata = infoblocks[infotype]
							for thisdata in heapdata:
								tolog = ""
								if infotype == "segments":
									# 0 : segmentstart
									# 1 : segmentend
									# 2 : firstentry
									# 3 : lastentry
									seg = thisdata
									segstart = segments[seg][0]
									segend = segments[seg][1]
									segsize = segend-segstart
									FirstEntry = segments[seg][2]
									LastValidEntry = segments[seg][3]
									tolog = "Segment 0x%08x - 0x%08x (FirstEntry: 0x%08x - LastValidEntry: 0x%08x): 0x%08x bytes" % (segstart,segend,FirstEntry,LastValidEntry, segsize)
								if infotype == "virtualallocdblocks":
									vablocks = heapdata
									tolog = "Heap : 0x%08x%s : VirtualAllocdBlocks : %d " % (heapbase,heapbase_extra,len(vachunks))
								#dbg.log("")
								dbg.log(tolog)
								if searchtype == "chunks" or "stat" in args:
									try:
										logfile_b.write("Heap: 0x%08x%s" % (heapbase,heapbase_extra),thislog_b)
										#logfile_b.write("",thislog_b)
										logfile_b.write(tolog,thislog_b)
									except:
										pass
									if infotype == "segments":
										datablocks = walkSegment(FirstEntry,LastValidEntry,heapbase)
									else:
										datablocks = heapdata[0]
									tolog = "    Nr of chunks : %d " % len(datablocks)
									dbg.log(tolog)
									try:
										logfile_b.write(tolog,thislog_b)
									except:

										pass
									if len(datablocks) > 0:
										tolog = "    _HEAP_ENTRY  psize   size  unused  UserPtr   UserSize"
										dbg.log(tolog)
										try:
											logfile_b.write(tolog,thislog_b)
										except:
											pass
										sortedblocks = []
										for block in datablocks:
											sortedblocks.append(block)
										sortedblocks.sort()
										nextblock = 0
										segstatinfo = {}
										for block in sortedblocks:
											showinlog = False
											thischunk = datablocks[block]
											unused = thischunk.unused
											headersize = thischunk.headersize
											flagtxt = getHeapFlag(thischunk.flag)
											if not infotype == "virtualallocdblocks" and "virtallocd" in flagtxt.lower():
												flagtxt += " (LFH)"
												flagtxt = flagtxt.replace("Virtallocd","Internal")
											userptr = block + headersize
											psize = thischunk.prevsize * 8
											blocksize = thischunk.size * 8
											selfsize = blocksize
											usersize = selfsize - unused				
											usersize = blocksize - unused
											extratxt = ""	
											if infotype == "virtualallocdblocks":
												nextblock = thischunk.flink
												extratxt = " (0x%x bytes committed)" % (thischunk.commitsize * 8)
											else:
												nextblock = block + blocksize

											if not "stat" in args:
												tolog = "       %08x  %05x  %05x   %05x  %08x  %08x (%d) (%s) %s" % (block,psize,selfsize,unused,block+headersize,usersize,usersize,flagtxt,extratxt)
												dbg.log(tolog)
												logfile_b.write(tolog,thislog_b)
											else:
												if not usersize in segstatinfo:
													segstatinfo[usersize] = 1
												else: 
													segstatinfo[usersize] += 1
										
										if nextblock > 0 and nextblock < LastValidEntry:
											if not "stat" in args:
												nextblock -= headersize
												restbytes = LastValidEntry - nextblock
												tolog = "       0x%08x - 0x%08x (end of segment) : 0x%x (%d) uncommitted bytes" % (nextblock,LastValidEntry,restbytes,restbytes)
												dbg.log(tolog)
												logfile_b.write(tolog,thislog_b)
										if "stat" in args:
											statinfo[segstart] = segstatinfo
											# show statistics
											orderedsizes = []
											totalalloc = 0
											for thissize in segstatinfo:
												orderedsizes.append(thissize)
												totalalloc += segstatinfo[thissize] 
											orderedsizes.sort(reverse=True)
											tolog = "    Segment Statistics:"
											dbg.log(tolog)
											try:
												logfile_b.write(tolog,thislog_b)
											except:
												pass
											for thissize in orderedsizes:
												nrblocks = segstatinfo[thissize]
												percentage = (float(nrblocks) / float(totalalloc)) * 100
												tolog = "    Size : 0x%x (%d) : %d chunks (%.2f %%)" % (thissize,thissize,nrblocks,percentage)

												dbg.log(tolog)
												try:
													logfile_b.write(tolog,thislog_b)
												except:
													pass
											tolog = "    Total chunks : %d" % totalalloc
											dbg.log(tolog)
											try:
												logfile_b.write(tolog,thislog_b)
											except:
												pass
											tolog = ""
											try:
												logfile_b.write(tolog,thislog_b)
											except:
												pass
											dbg.log("")
										dbg.log("")


				if "stat" in args and len(statinfo) > 0:
					tolog = "Global statistics"
					dbg.log(tolog)
					try:
						logfile_b.write(tolog,thislog_b)
					except:
						pass
					globalstats = {}
					allalloc = 0
					for seginfo in statinfo:
						segmentstats = statinfo[seginfo]
						for size in segmentstats:
							allalloc += segmentstats[size]
							if not size in globalstats:
								globalstats[size] = segmentstats[size]
							else:
								globalstats[size] += segmentstats[size]
					orderedstats = []
					for size in globalstats:
						orderedstats.append(size)
					orderedstats.sort(reverse=True)
					for thissize in orderedstats:
						nrblocks = globalstats[thissize]
						percentage = (float(nrblocks) / float(allalloc)) * 100
						tolog = "  Size : 0x%x (%d) : %d chunks (%.2f %%)" % (thissize,thissize,nrblocks,percentage)
						dbg.log(tolog)
						try:
							logfile_b.write(tolog,thislog_b)
						except:
							pass
					tolog = "  Total chunks : %d" % allalloc
					dbg.log(tolog)
					try:
						logfile_b.write(tolog,thislog_b)
					except:
						pass
			#dbg.log("%s" % "*" * 90)					
					
			return
		
		def procGetIAT(args):
			return procGetxAT(args,"iat")

		def procGetEAT(args):
			return procGetxAT(args,"eat")

		def procFwptr(args):
			modulecriteria = {}
			criteria = {}			
			modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
			modulestosearch = getModulesToQuery(modulecriteria)
			allpages = dbg.getMemoryPages()
			orderedpages = []
			for page in allpages.keys():
				orderedpages.append(page)
			orderedpages.sort()
			pagestoquery = {}
			fwptrs = {}

			objwptr = MnLog("wptr.txt")
			wptrfile = objwptr.reset()

			setbps = False
			dopatch = False
			dofreelist = False

			if "bp" in args:
				setbps = True

			if "patch" in args:
				dopatch = True

			if "freelist" in args:
				dofreelist = True

			chunksize = 0
			offset = 0

			if "chunksize" in args:
				if type(args["chunksize"]).__name__.lower() != "bool":
					try:
						if str(args["chunksize"]).lower().startswith("0x"):
							chunksize = int(args["chunksize"],16)
						else:
							chunksize = int(args["chunksize"])
					except:
						chunksize = 0
				if chunksize == 0 or chunksize > 0xffff:
					dbg.log("[!] Invalid chunksize specified")
					if chunksize > 0xffff:
						dbg.log("[!] Chunksize must be <= 0xffff")
						chunksize == 0
						return
				else:
					dbg.log("[+] Will filter on chunksize 0x%0x" % chunksize )
			if dofreelist:
				if "offset" in args:
					if type(args["offset"]).__name__.lower() != "bool":
						try:
							if str(args["offset"]).lower().startswith("0x"):
								offset = int(args["offset"],16)
							else:
								offset = int(args["offset"])
						except:
							offset = 0
					if offset == 0:
						dbg.log("[!] Invalid offset specified")
					else:
						dbg.log("[+] Will add 0x%0x bytes between flink/blink and fwptr" % offset )			

			if not silent:
				if setbps:
					dbg.log("[+] Will set breakpoints on found CALL/JMP")
				if dopatch:
					dbg.log("[+] Will patch target for CALL/JMP with 0x41414141")
				dbg.log("[+] Extracting .text/.code sections from %d modules" % len(modulestosearch))
				dbg.updateLog()

			if len(modulestosearch) > 0:		
				for thismodule in modulestosearch:
					# find text section
					for thispage in orderedpages:
						page = allpages[thispage]
						pagestart = page.getBaseAddress()
						pagesize = page.getSize()
						ptr = MnPointer(pagestart)
						mod = ""
						sectionname = ""
						try:
							mod = ptr.belongsTo()
							if mod == thismodule:
								sectionname = page.getSection()
								if sectionname == ".text" or sectionname == ".code":	
									pagestoquery[mod] = [pagestart,pagestart+pagesize]
									break
						except:
							pass
			if len(pagestoquery) > 0:
				if not silent:
					dbg.log("[+] Analysing .text/.code sections")
					dbg.updateLog()
				for modname in pagestoquery:
					tmodcnt = 0
					nr_sizematch = 0
					pagestart = pagestoquery[modname][0]
					pageend = pagestoquery[modname][1]
					if not silent:
						dbg.log("    - Carving through %s (0x%08x - 0x%08x)" % (modname,pagestart,pageend))
						dbg.updateLog()
					loc = pagestart
					while loc < pageend:
						try:
							thisinstr = dbg.disasm(loc)
							instrbytes = thisinstr.getDump()
							if thisinstr.isJmp() or thisinstr.isCall():
								# check if it's reading a pointer from somewhere
								instrtext = getDisasmInstruction(thisinstr)
								opcodepart = instrbytes.upper()[0:4]
								if opcodepart == "FF15" or opcodepart == "FF25":
									if "[" in instrtext and "]" in instrtext:
										parts1 = instrtext.split("[")
										if len(parts1) > 1:
											parts2 = parts1[1].split("]")
											addy = parts2[0]
											# get the actual value and check if it's writeable
											if "(" in addy and ")" in addy:
												parts1 = addy.split("(")
												parts2 = parts1[1].split(")")
												addy = parts2[0]
											if isHexValue(addy):
												addyval = hexStrToInt(addy)
												access = getPointerAccess(addyval)
												if "WRITE" in access:
													if meetsCriteria(addyval,criteria):
														savetolog = False
														sizeinfo = ""
														if chunksize == 0:
															savetolog = True
														else:
															# check if this location could acts as a heap chunk for a certain size
															# the size field would be placed at the curren location - 8 bytes
															# and is 2 bytes large
															sizeval = 0
															if not dofreelist:
																sizeval = struct.unpack('<H',dbg.readMemory(addyval-8,2))[0]
																if sizeval >= chunksize:
																	savetolog = True
																	nr_sizematch += 1
																	sizeinfo = " Chunksize: %d (0x%02x) - " % ((sizeval*8),(sizeval*8))																
															else:
																sizeval = struct.unpack('<H',dbg.readMemory(addyval-8-offset,2))[0]
																#
																flink = struct.unpack('<L',dbg.readMemory(addyval-offset,4))[0]
																blink = struct.unpack('<L',dbg.readMemory(addyval+4-offset,4))[0]
																aflink = getPointerAccess(flink)
																ablink = getPointerAccess(blink)
																if "READ" in aflink and "READ" in ablink:
																	extr = ""
																	if sizeval == chunksize or sizeval == chunksize + 1:
																		extr = " **size match**"
																		nr_sizematch += 1
																	sizeinfo = " Chunksize: %d (0x%02x)%s, UserPtr 0x%08x, Flink 0x%08x, Blink 0x%08x - " % ((sizeval*8),(sizeval*8),extr,addyval-offset,flink,blink)
																	savetolog = True
														if savetolog:
															fwptrs[loc] = addyval
															tmodcnt += 1
															ptrx = MnPointer(addyval)
															mod = ptrx.belongsTo()

															tofile = "0x%08x : 0x%08x gets called from %s at 0x%08x (%s) - %s%s" % (addyval,addyval,mod,loc,instrtext,sizeinfo,ptrx.__str__())
															objwptr.write(tofile,wptrfile)
															if setbps:
																dbg.setBreakpoint(loc)
															if dopatch:
																dbg.writeLong(addyval,0x41414141)
							if len(instrbytes) > 0:
								loc = loc + len(instrbytes)/2
							else:
								loc = loc + 1
						except:
							loc = loc + 1
					if not silent:
						dbg.log("      Found %d pointers" % tmodcnt)
						if chunksize > 0:
							dbg.log("      %d pointers with size match" % nr_sizematch)								

			return

		def procGetxAT(args,mode):
		
			keywords = []
			keywordstring = ""
			modulecriteria = {}
			criteria = {}

			thisxat = {}

			entriesfound = 0
			
			if "s" in args:
				if type(args["s"]).__name__.lower() != "bool":
					keywordstring = args["s"].replace("'","").replace('"','')
					keywords = keywordstring.split(",")
			
			modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
			
			modulestosearch = getModulesToQuery(modulecriteria)
			if not silent:
				dbg.log("[+] Querying %d modules" % len(modulestosearch))
			
			if len(modulestosearch) > 0:
			
				xatfilename="%ssearch.txt" % mode
				objxatfilename = MnLog(xatfilename)
				xatfile = objxatfilename.reset()
			
				for thismodule in modulestosearch:
					thismod = MnModule(thismodule) 
					if mode == "iat":
						thisxat = thismod.getIAT()
					else:
						thisxat = thismod.getEAT()

					thismodule = thismod.getShortName()

					for thisfunc in thisxat:
						thisfuncname = thisxat[thisfunc].lower()
						origfuncname = thisfuncname
						firstindex = thisfuncname.find(".")
						if firstindex > 0:
							thisfuncname = thisfuncname[firstindex+1:len(thisfuncname)]
						addtolist = False
						iatptr_modname = ""
						modinfohr = ""
						theptr = 0
						if mode == "iat":
							theptr = struct.unpack('<L',dbg.readMemory(thisfunc,4))[0]
							ptrx = MnPointer(theptr)
							iatptr_modname = ptrx.belongsTo()
							if not iatptr_modname == "" and "." in iatptr_modname:
								iatptr_modparts = iatptr_modname.split(".")
								iatptr_modname = iatptr_modparts[0]
							if not "." in origfuncname and iatptr_modname != "" and not "!" in origfuncname:
								origfuncname = iatptr_modname.lower() + "." + origfuncname
								thisfuncname = origfuncname
								
							if "!" in origfuncname:
								oparts = origfuncname.split("!")
								origfuncname = iatptr_modname + "." + oparts[1]
								thisfuncname = origfuncname

							try:
								ModObj = MnModule(iatptr_modname)
								modinfohr = " - %s" % (ModObj.__str__())
							except:
								modinfohr = ""
								pass

						if len(keywords) > 0:
							for keyword in keywords:
								keyword = keyword.lower().strip()
								if ((keyword.startswith("*") and keyword.endswith("*")) or keyword.find("*") < 0):
									keyword = keyword.replace("*","")
									if thisfuncname.find(keyword) > -1:
										addtolist = True
										break
								if keyword.startswith("*") and not keyword.endswith("*"):
									keyword = keyword.replace("*","")
									if thisfuncname.endswith(keyword):
										addtolist = True
										break
								if keyword.endswith("*") and not keyword.startswith("*"):
									keyword = keyword.replace("*","")
									if thisfuncname.startswith(keyword):
										addtolist = True
										break
						else:
							addtolist = True
						if addtolist:
							entriesfound += 1
							# add info about the module

							if mode == "iat":
								thedelta = thisfunc - thismod.moduleBase
								logentry = "At 0x%s in %s (base + 0x%s) : 0x%s (ptr to %s) %s" % (toHex(thisfunc),thismodule.lower(),toHex(thedelta),toHex(theptr),origfuncname,modinfohr)
							else:
								thedelta = thisfunc - thismod.moduleBase
								logentry = "0x%08x : %s!%s (0x%08x+0x%08x)" % (thisfunc,thismodule.lower(),origfuncname,thismod.moduleBase,thedelta)
							dbg.log(logentry,address = thisfunc)
							objxatfilename.write(logentry,xatfile)
				if not silent:
					dbg.log("")
					dbg.log("%d entries found" % entriesfound)
			return

			
		#-----Metasploit module skeleton-----#
		def procSkeleton(args):
		
			cyclicsize = 5000
			if "c" in args:
				if type(args["c"]).__name__.lower() != "bool":
					try:
						cyclicsize = int(args["c"])
					except:
						cyclicsize = 5000

			exploittype = ""
			skeletonarg = ""
			usecliargs = False
			validstypes ={}
			validstypes["tcpclient"] = "network client (tcp)"
			validstypes["udpclient"] = "network client (udp)"
			validstypes["fileformat"] = "fileformat"
			exploittypes = [ "fileformat","network client (tcp)","network client (udp)" ]
			errorfound = False
			if __DEBUGGERAPP__ == "WinDBG" or "t" in args:
				if "t" in args:
					if type(args["t"]).__name__.lower() != "bool":
						skeltype = args["t"].lower()
						skelparts = skeltype.split(":")
						if skelparts[0] in validstypes:
							exploittype = validstypes[skelparts[0]]
							if len(skelparts) > 1:
								skeletonarg = skelparts[1]
							else:
								errorfound = True
							usecliargs = True
						else:
							errorfound = True
					else:
						errorfound = True
				else:
					errorfound = True
			# ask for type of module
			else:
				dbg.log(" ** Please select a skeleton exploit type from the dropdown list **",highlight=1)
				exploittype = dbg.comboBox("Select msf exploit skeleton to build :", exploittypes).lower().strip()

			if errorfound:
				dbg.log(" ** Please specify a valid skeleton type and argument **",highlight=1)
				dbg.log("    Valid types are : tcpclient:argument, udpclient:argument, fileformat:argument")
				dbg.log("    Example : skeleton for a pdf file format exploit: -t fileformat:pdf")
				dbg.log("              skeleton for tcp client against port 123: -t tcpclient:123")
				return
			if not exploittype in exploittypes:
				dbg.log("Boo - invalid exploit type, try again !",highlight=1)
				return
				
			portnr = 0
			extension = ""
			if exploittype.find("network") > -1:
				if usecliargs:
					portnr = skeletonarg
				else:
					portnr = dbg.inputBox("Remote port number : ")
				try:
					portnr = int(portnr)
				except:
					portnr = 0

			if exploittype.find("fileformat") > -1:
				if usecliargs:
					extension = skeletonarg
				else:
					extension = dbg.inputBox("File extension :")
			
			extension = extension.replace("'","").replace('"',"").replace("\n","").replace("\r","")
			
			if not extension.startswith("."):
				extension = "." + extension			
			
			exploitfilename="msfskeleton.rb"
			objexploitfile = MnLog(exploitfilename)
			global ignoremodules
			global noheader
			noheader = True
			ignoremodules = True
			exploitfile = objexploitfile.reset()			
			ignoremodules = False
			noheader = False

			modulecriteria = {}
			criteria = {}
			
			modulecriteria,criteria = args2criteria(args,modulecriteria,criteria)
			
			badchars = ""
			if "badchars" in criteria:
				badchars = criteria["badchars"]
				
			if "nonull" in criteria:
				if not '\x00' in badchars:
					badchars += '\x00'			
			
			skeletonheader,skeletoninit,skeletoninit2 = getSkeletonHeader(exploittype,portnr,extension,"",badchars)
			
			targetstr = "      'Targets'    =>\n"
			targetstr += "        [\n"
			targetstr += "          [ '<fill in the OS/app version here>',\n"
			targetstr += "            {\n"
			targetstr += "              'Ret'     =>  0x00000000,\n"
			targetstr += "              'Offset'  =>  0\n"
			targetstr += "            }\n"
			targetstr += "          ],\n"
			targetstr += "        ],\n"
			
			exploitstr = "  def exploit\n\n"
			if exploittype.find("network") > -1:
				if exploittype.find("tcp") > -1:
					exploitstr += "\n    connect\n\n"
				elif exploittype.find("udp") > -1:
					exploitstr += "\n    connect_udp\n\n"
			
			exploitstr += "    buffer = Rex::Text.pattern_create(" + str(cyclicsize) + ")\n"
			
			if exploittype.find("network") > -1:
				exploitstr += "\n    print_status(\"Trying target #{target.name}...\")\n"	
				if exploittype.find("tcp") > -1:
					exploitstr += "    sock.put(buffer)\n"
					exploitstr += "\n    handler\n"
				elif exploittype.find("udp") > -1:
					exploitstr += "    udp_sock.put(buffer)\n"
					exploitstr += "\n    handler(udp_sock)\n"			
			if exploittype == "fileformat":
				exploitstr += "\n    file_create(buffer)\n\n"						
			if exploittype.find("network") > -1:
				exploitstr += "    disconnect\n\n"						
				
			exploitstr += "  end\n"				
			
			objexploitfile.write(skeletonheader+"\n",exploitfile)
			objexploitfile.write(skeletoninit+"\n",exploitfile)
			objexploitfile.write(targetstr,exploitfile)
			objexploitfile.write(skeletoninit2,exploitfile)		
			objexploitfile.write(exploitstr,exploitfile)
			objexploitfile.write("end",exploitfile)	
			
			
			return


		def procFillChunk(args):
		
			reference = ""
			fillchar = "A"
			allregs = dbg.getRegs()
			origreference = ""

			deref = False
			refreg = ""
			offset = 0
			signstuff = 1
			customsize = 0

			if "s" in args:
				if type(args["s"]).__name__.lower() != "bool":
					sizearg = args["s"]
					if sizearg.lower().startswith("0x"):
						sizearg = sizearg.lower().replace("0x","")
						customsize = int(sizearg,16)
					else:
						customsize = int(sizearg)

			if "r" in args:
				if type(args["r"]).__name__.lower() != "bool":

					# break into pieces
					reference = args["r"].upper()
					origreference = reference
					if reference.find("[") > -1 and reference.find("]") > -1:
						refregtmp = reference.replace("[","").replace("]","").replace(" ","")
						if reference.find("+") > -1 or reference.find("-") > -1:
							# deref with offset
							refregtmpparts = []
							if reference.find("+") > -1:
								refregtmpparts = refregtmp.split("+")
								signstuff = 1
							if reference.find("-") > -1:
								refregtmpparts = refregtmp.split("-")
								signstuff = -1
							if len(refregtmpparts) > 1:
								offset = int(refregtmpparts[1].replace("0X",""),16) * signstuff
								deref = True
								refreg = refregtmpparts[0]
								if not refreg in allregs:
									dbg.log("** Please provide a valid reference using -r reg/reference **")
									return
							else:
								dbg.log("** Please provide a valid reference using -r reg/reference **")
								return																
						else:
							# only deref
							refreg = refregtmp
							deref = True
					else:
						# no deref, maybe offset
						if reference.find("+") > -1 or reference.find("-") > -1:
							# deref with offset
							refregtmpparts = []
							refregtmp = reference.replace(" ","")
							if reference.find("+") > -1:
								refregtmpparts = refregtmp.split("+")
								signstuff = 1
							if reference.find("-") > -1:
								refregtmpparts = refregtmp.split("-")
								signstuff = -1
							if len(refregtmpparts) > 1:
								offset = int(refregtmpparts[1].replace("0X",""),16) * signstuff
								refreg = refregtmpparts[0]
								if not refreg in allregs:
									dbg.log("** Please provide a valid reference using -r reg/reference **")
									return
							else:
								dbg.log("** Please provide a valid reference using -r reg/reference **")
								return																
						else:
							# only deref
							refregtmp = reference.replace(" ","")
							refreg = refregtmp
							deref = False
				else:
					dbg.log("** Please provide a valid reference using -r reg/reference **")
					return
			else:
				dbg.log("** Please provide a valid reference using -r reg/reference **")
				return

			if not refreg in allregs:
				dbg.log("** Please provide a valid reference using -r reg/reference **")
				return				

			dbg.log("Ref : %s" % refreg)
			dbg.log("Offset : %d (0x%s)" % (offset,toHex(int(str(offset).replace("-","")))))
			dbg.log("Deref ? : %s" % deref)

			if "b" in args:
				if type(args["b"]).__name__.lower() != "bool":
					if args["b"].find("\\x") > -1:
						fillchar = hex2bin(args["b"])[0]
					else:
						fillchar = args["b"][0]

			# see if we can read the reference
			refvalue = 0
			if deref:
				refref = 0
				try:
					refref = allregs[refreg]+offset
				except:
					dbg.log("** Unable to read from %s (0x%08x)" % (origreference,allregs[refreg]+offset))
				try:
					refvalue = struct.unpack('<L',dbg.readMemory(refref,4))[0]
				except:
					dbg.log("** Unable to read from %s (0x%08x) -> 0x%08x" % (origreference,allregs[reference]+offset,refref))
					return
			else:
				try:
					refvalue = allregs[refreg]+offset
				except:
					dbg.log("** Unable to read from %s (0x%08x)" % (reference,allregs[refreg]+offset))

			dbg.log("Reference : %s: 0x%08x" % (origreference,refvalue))
			dbg.log("Fill char : \\x%s" % bin2hex(fillchar))

			cmd2run = "!heap -p -a 0x%08x" % refvalue
			output = dbg.nativeCommand(cmd2run)
			outputlines = output.split("\n")
			heapinfo = ""
			for line in outputlines:
				if line.find("[") > -1 and line.find("]") > -1 and line.find("(") > -1 and line.find(")") > -1:
					heapinfo = line
					break
			if heapinfo == "":
				dbg.log("Address is not part of a heap chunk")
				if customsize > 0:
					dbg.log("Filling memory location starting at 0x%08x with \\x%s" % (refvalue,bin2hex(fillchar)))
					dbg.log("Number of bytes to write : %d (0x%08x)" % (customsize,customsize))
					data = fillchar * customsize
					dbg.writeMemory(refvalue,data)
					dbg.log("Done")
				else:
					dbg.log("Please specify a custom size with -s to fill up the memory location anyway")
			else:
				infofields = []
				cnt = 0
				charseen = False
				thisfield = ""
				while cnt < len(heapinfo):
					if heapinfo[cnt] == " " and charseen and thisfield != "":
						infofields.append(thisfield)
						thisfield = ""
					else:
						if not heapinfo[cnt] == " ":
							thisfield += heapinfo[cnt]
							charseen = True
					cnt += 1
				if thisfield != "":
					infofields.append(thisfield)
				if len(infofields) > 7:
					chunkptr = hexStrToInt(infofields[0]) 
					userptr = hexStrToInt(infofields[4])
					size = hexStrToInt(infofields[5])
					dbg.log("Heap chunk found at 0x%08x, size 0x%08x (%d) bytes" % (chunkptr,size,size))
					dbg.log("Filling chunk with \\x%s, starting at 0x%08x" % (bin2hex(fillchar),userptr))
					data = fillchar * size
					dbg.writeMemory(userptr,data)
					dbg.log("Done")
			return

		def procInfoDump(args):
			allpages = dbg.getMemoryPages()
			filename = "infodump.xml"
			xmldata = '<info>\n'
			xmldata += "<modules>\n"
			if len(g_modules) == 0:
				populateModuleInfo()
			modulestoquery=[]
			for thismodule,modproperties in g_modules.iteritems():
				xmldata += "  <module name='%s'>\n" % thismodule
				thisbase = getModuleProperty(thismodule,"base")
				thissize = getModuleProperty(thismodule,"size")
				xmldata += "    <base>0x%08x</base>\n" % thisbase
				xmldata += "    <size>0x%08x</size>\n" % thissize
				xmldata += "  </module>\n"
			xmldata += "</modules>\n"
			orderedpages = []
			for tpage in allpages.keys():
				orderedpages.append(tpage)
			orderedpages.sort()
			if len(orderedpages) > 0:
				xmldata += "<pages>\n"				
				# first dump module info to file
				objfile = MnLog(filename)
				infofile = objfile.reset(clear=True,showheader=False)
				f = open(infofile,"wb")
				for line in xmldata.split("\n"):
					if line != "":
						f.write(line + "\n")
				tolog = "Dumping the following pages to file:"
				dbg.log(tolog)
				tolog = "Start        End        Size         ACL"
				dbg.log(tolog)
				for thispage in orderedpages:
					page = allpages[thispage]
					pagestart = page.getBaseAddress()
					pagesize = page.getSize()
					ptr = MnPointer(pagestart)
					mod = ""
					sectionname = ""
					ismod = False
					isstack = False
					isheap = False
					try:
						mod = ptr.belongsTo()
						if mod != "":
							ismod = True
					except:
						mod = ""
					if not ismod:
						if ptr.isOnStack():
							isstack = True
					if not ismod and not isstack:
						if ptr.isInHeap():
							isheap = True
					if not ismod and not isstack and not isheap:
						acl = page.getAccess(human=True)
						if not "NOACCESS" in acl:
							tolog = "0x%08x - 0x%08x (0x%08x) %s" % (pagestart,pagestart + pagesize,pagesize,acl)
							dbg.log(tolog)
							# add page contents to xml
							thispage = dbg.readMemory(pagestart,pagesize)
							f.write("  <page start=\"0x%08x\">\n" % pagestart)
							f.write("    <size>0x%08x</size>\n" % pagesize)
							f.write("    <acl>%s</acl>\n" % acl)
							f.write("    <contents>")
							memcontents = ""
							for thisbyte in thispage:
								memcontents += bin2hex(thisbyte)
							f.write(memcontents)
							f.write("</contents>\n")
							f.write("  </page>\n")
				f.write("</pages>\n")
				f.write("</info>")
				dbg.log("")
				f.close()
				dbg.log("Done")
			return

		
		def procPEB(args):
			"""
			Show the address of the PEB
			"""
			pebaddy = dbg.getPEBAddress()
			dbg.log("PEB is located at 0x%08x" % pebaddy,address=pebaddy)
			return

		def procTEB(args):
			"""
			Show the address of the TEB for the current thread
			"""
			tebaddy = dbg.getCurrentTEBAddress()
			dbg.log("TEB is located at 0x%08x" % tebaddy,address=tebaddy)
			return

		def procPageACL(args):
			global silent
			silent = True
			findaddy = 0
			if "a" in args:
				findaddy,addyok = getAddyArg(args["a"])
				if not addyok:
					dbg.log("%s is an invalid address" % args["a"], highlight=1)
					return
			if findaddy > 0:
				dbg.log("Displaying page information around address 0x%08x" % findaddy)
			allpages = dbg.getMemoryPages()
			dbg.log("Total of %d pages : "% len(allpages))
			filename="pageacl.txt"
			orderedpages = []
			for tpage in allpages.keys():
				orderedpages.append(tpage)
			orderedpages.sort()
			# find indexes to show in case we have specified an address
			toshow = []
			previouspage = 0
			nextpage = 0
			pagefound = False
			if findaddy > 0:
				for thispage in orderedpages:
					page = allpages[thispage]
					pagestart = page.getBaseAddress()
					pagesize = page.getSize()
					pageend = pagestart + pagesize
					if findaddy >= pagestart and findaddy < pageend:
						toshow.append(thispage)
						pagefound = True
					if pagefound and previouspage > 0:
						if not previouspage in toshow:
							toshow.append(previouspage)
						if not thispage in toshow:
							toshow.append(thispage) # nextpage
						break
					previouspage = thispage
			if len(toshow) > 0:
				toshow.sort()
				orderedpages = toshow
				dbg.log("Showing %d pages" % len(orderedpages))
			if len(orderedpages) > 0:
				objfile = MnLog(filename)
				aclfile = objfile.reset()
				tolog = "Start        End        Size         ACL"
				dbg.log(tolog)
				objfile.write(tolog,aclfile)
				for thispage in orderedpages:
					page = allpages[thispage]
					pagestart = page.getBaseAddress()
					pagesize = page.getSize()
					ptr = MnPointer(pagestart)
					mod = ""
					sectionname = ""
					try:
						mod = ptr.belongsTo()
						if not mod == "":
							mod = "(" + mod + ")"
							sectionname = page.getSection()
					except:
						#print traceback.format_exc()
						pass
					if mod == "":
						if ptr.isOnStack():
							mod = "(Stack)"
						elif ptr.isInHeap():
							mod = "(Heap)"
					acl = page.getAccess(human=True)
					tolog = "0x%08x - 0x%08x (0x%08x) %s %s %s" % (pagestart,pagestart + pagesize,pagesize,acl,mod, sectionname)
					objfile.write(tolog,aclfile)
					dbg.log(tolog)
			silent = False
			return

		def procMacro(args):
			validcommands = ["run","set","list","del","add","show"]
			validcommandfound = False
			selectedcommand = ""
			for command in validcommands:
				if command in args:
					validcommandfound = True
					selectedcommand = command
					break
			dbg.log("")
			if not validcommandfound:
				dbg.log("*** Please specify a valid command. Valid commands are :")
				for command in validcommands:
					dbg.log("    -%s" % command)
				return			

			macroname = ""
			if "set" in args:
				if type(args["set"]).__name__.lower() != "bool":
					macroname = args["set"]

			if "show" in args:
				if type(args["show"]).__name__.lower() != "bool":
					macroname = args["show"]

			if "add" in args:
				if type(args["add"]).__name__.lower() != "bool":
					macroname = args["add"]				

			if "del" in args:
				if type(args["del"]).__name__.lower() != "bool":
					macroname = args["del"]	

			if "run" in args:
				if type(args["run"]).__name__.lower() != "bool":
					macroname = args["run"]	

			filename = ""
			index = -1
			insert = False
			iamsure = False
			if "index" in args:
				if type(args["index"]).__name__.lower() != "bool":
					index = int(args["index"])
					if index < 0:
						dbg.log("** Please use a positive integer as index",highlight=1)

			if "file" in args:
				if type(args["file"]).__name__.lower() != "bool":
					filename = args["file"]

			if filename != "" and index > -1:
				dbg.log("** Please either provide an index or a filename, not both",highlight=1)
				return

			if "insert" in args:
				insert = True

			if "iamsure" in args:
				iamsure = True

			argcommand = ""
			if "cmd" in args:
				if type(args["cmd"]).__name__.lower() != "bool":
					argcommand = args["cmd"]


			dbg.setKBDB("monamacro.db")
			macros = dbg.getKnowledge("macro")
			if macros is None:
				macros = {}

			if selectedcommand == "list":
				for macro in macros:
					thismacro = macros[macro]
					macronametxt = "Macro : '%s' : %d command(s)" % (macro,len(thismacro))
					dbg.log(macronametxt)
				dbg.log("")
				dbg.log("Number of macros : %d" % len(macros))

			if selectedcommand == "show":
				if macroname != "":
					if not macroname in macros:
						dbg.log("** Macro %s does not exist !" % macroname)
						return
					else:
						macro = macros[macroname]
						macronametxt = "Macro : %s" % macroname
						macroline = "-" * len(macronametxt)
						dbg.log(macronametxt)
						dbg.log(macroline)
						thismacro = macro
						macrolist = []
						for macroid in thismacro:
							macrolist.append(macroid)
						macrolist.sort()
						nr_of_commands = 0
						for macroid in macrolist:
							macrocmd = thismacro[macroid]
							if macrocmd.startswith("#"):
								dbg.log("   [%04d] File:%s" % (macroid,macrocmd[1:]))
							else:
								dbg.log("   [%04d] %s" % (macroid,macrocmd))
							nr_of_commands += 1
						dbg.log("")
						dbg.log("Nr of commands in this macro : %d" % nr_of_commands)
				else:
					dbg.log("** Please specify the macroname to show !",highlight=1)
					return					

			if selectedcommand == "run":
				if macroname != "":
					if not macroname in macros:
						dbg.log("** Macro %s does not exist !" % macroname)
						return
					else:
						macro = macros[macroname]
						macronametxt = "Running macro : %s" % macroname
						macroline = "-" * len(macronametxt)
						dbg.log(macronametxt)
						dbg.log(macroline)
						thismacro = macro
						macrolist = []
						for macroid in thismacro:
							macrolist.append(macroid)
						macrolist.sort()
						for macroid in macrolist:
							macrocmd = thismacro[macroid]
							if macrocmd.startswith("#"):
								dbg.log("Executing script %s" % macrocmd[1:])
								output = dbg.nativeCommand("$<%s" % macrocmd[1:])
								dbg.logLines(output)
								dbg.log("-" * 40)
							else:
								dbg.log("Index %d : %s" % (macroid,macrocmd))
								dbg.log("")
								output = dbg.nativeCommand(macrocmd)
								dbg.logLines(output)
								dbg.log("-" * 40)
						dbg.log("")
						dbg.log("[+] Done.")
				else:
					dbg.log("** Please specify the macroname to run !",highlight=1)
					return	

			if selectedcommand == "set":
				if macroname != "":
					if not macroname in macros:
						dbg.log("** Macro %s does not exist !" % macroname)
						return
					if argcommand == "" and filename == "":
						dbg.log("** Please enter a valid command with parameter -cmd",highlight=1)
						return
					thismacro = macros[macroname]
					if index == -1:
						for i in thismacro:
							thiscmd = thismacro[i]
							if thiscmd.startswith("#"):
								dbg.log("** You cannot edit a macro that uses a scriptfile.",highlight=1)
								dbg.log("   Edit file %s instead" % thiscmd[1:],highlight=1)
								return						
						if filename == "":
							# append to end of the list
							# find the next index first
							nextindex = 0
							for macindex in thismacro:
								if macindex >= nextindex:
									nextindex = macindex+1
							if thismacro.__class__.__name__ == "dict":
								thismacro[nextindex] = argcommand
							else:
								thismacro = {}
								thismacro[nextindex] = argcommand
						else:
							thismacro = {}
							nextindex = 0
							thismacro[0] = "#%s" % filename
						macros[macroname] = thismacro
						dbg.addKnowledge("macro",macros)
						dbg.log("[+] Done, saved new command at index %d." % nextindex)
					else:
						# user has specified an index
						if index in thismacro:
							if argcommand == "#":
								# remove command at this index
								del thismacro[index]
							else:
								# if macro already contains a file entry, bail out
								for i in thismacro:
									thiscmd = thismacro[i]
									if thiscmd.startswith("#"):
										dbg.log("** You cannot edit a macro that uses a scriptfile.",highlight=1)
										dbg.log("   Edit file %s instead" % thiscmd[1:],highlight=1)
										return
								# index exists - overwrite unless -insert was provided too
								# remove or insert ?
								#print sys.argv
								if not insert:
									thismacro[index] = argcommand
								else:
									# move things around
									# get ordered list of existing indexes
									indexes = []
									for macindex in thismacro:
										indexes.append(macindex)
									indexes.sort()
									thismacro2 = {}
									cmdadded = False
									for i in indexes:
										if i < index:
											thismacro2[i] = thismacro[i]
										elif i == index:
											thismacro2[i] = argcommand
											thismacro2[i+1] = thismacro[i]
										elif i > index:
											thismacro2[i+1] = thismacro[i]
									thismacro = thismacro2
						else:
							# index does not exist, add new command to this index
							for i in thismacro:
								thiscmd = thismacro[i]
								if thiscmd.startswith("#"):
									dbg.log("** You cannot edit a macro that uses a scriptfile.",highlight=1)
									dbg.log("   Edit file %s instead" % thiscmd[1:],highlight=1)
									return							
							if argcommand != "#":
								thismacro[index] = argcommand
							else:
								dbg.log("** Index %d does not exist, unable to remove the command at that position" % index,highlight=1)
						macros[macroname] = thismacro
						dbg.addKnowledge("macro",macros)
						if argcommand != "#":
							dbg.log("[+] Done, saved new command at index %d." % index)
						else:
							dbg.log("[+] Done, removed command at index %d." % index)
				else:
					dbg.log("** Please specify the macroname to edit !",highlight=1)
					return

			if selectedcommand == "add":
				if macroname != "":
					if macroname in macros:
						dbg.log("** Macro '%s' already exists !" % macroname,highlight=1)
						return
					else:
						macros[macroname] = {}
						dbg.log("[+] Adding macro '%s'" % macroname)
						dbg.addKnowledge("macro",macros)
						dbg.log("[+] Done.")
				else:
					dbg.log("** Please specify the macroname to add !",highlight=1)
					return


			if selectedcommand == "del":
				if not macroname in macros:
					dbg.log("** Macro '%s' doesn't exist !" % macroname,highlight=1)
				else:
					if not iamsure:
						dbg.log("** To delete macro '%s', please add the -iamsure flag to the command" % macroname)
						return
					else:
						dbg.forgetKnowledge("macro",macroname)
						dbg.log("[+] Done, deleted macro '%s'" % macroname)
			return


		def procEnc(args):
			validencoders = ['alphanum']
			encodertyperror = True
			byteerror = True
			encodertype = ""
			bytestoencodestr = ""
			bytestoencode = ""
			badbytes = ""
			
			if "t" in args:
				if type(args["t"]).__name__.lower() != "bool":
					encodertype = args["t"]
					encodertyperror = False

			if "s" in args:
				if type(args["s"]).__name__.lower() != "bool":
					bytestoencodestr = args["s"]
					byteerror = False

			if "f" in args:
				if type(args["f"]).__name__.lower() != "bool":
					binfile = args["f"]
					if os.path.exists(binfile):
						if not silent:
							dbg.log("[+] Reading bytes from %s" % binfile)
						try:
							f = open(binfile,"rb")
							content = f.readlines()
							f.close()
							for c in content:
								for a in c:
									bytestoencodestr += "\\x%02x" % ord(a)
							byteerror = False
						except:
							dbg.log("*** Error - unable to read bytes from %s" % binfile)
							dbg.logLines(traceback.format_exc(),highlight=True)
							byteerror = True
					else:
						byteerror = True
				else:
					byteerror = True

			if "cpb" in args:
				if type(args["cpb"]).__name__.lower() != "bool":
					badbytes = hex2bin(args["cpb"])

			if not encodertype in validencoders:
				encodertyperror = True

			if bytestoencodestr == "":
				byteerror = True
			else:
				bytestoencode = hex2bin(bytestoencodestr)

			if encodertyperror:
				dbg.log("*** Please specific a valid encodertype with parameter -t.",highlight=True)
				dbg.log("*** Valid types are: %s" % validencoders,highlight=True)


			if byteerror:
				dbg.log("*** Please specify a valid series of bytes with parameter -s",highlight=True)
				dbg.log("*** or specify a valid path with parameter -f",highlight=True)

			if encodertyperror or byteerror:
				return
			else:
				cEncoder = MnEncoder(bytestoencode)
				encodedbytes = ""
				if encodertype == "alphanum":
					encodedbytes = cEncoder.encodeAlphaNum(badchars = badbytes)
					# determine correct sequence of dictionary
					if len(encodedbytes) > 0:
						logfile = MnLog("encoded_%s.txt" % encodertype)
						thislog = logfile.reset()
						if not silent:
							dbg.log("")
							dbg.log("Results:")
							dbg.log("--------")
						logfile.write("",thislog)
						logfile.write("Results:",thislog)
						logfile.write("--------",thislog)
						encodedindex = []
						fulllist_str = ""
						fulllist_bin = ""
						for i in encodedbytes:
							encodedindex.append(i)
						for i in encodedindex:
							thisline = encodedbytes[i]
							# 0 = bytes
							# 1 = info
							thislinebytes = "\\x" +  "\\x".join(bin2hex(a) for a in thisline[0])
							logline = "  %s : %s : %s" % (thisline[0],thislinebytes,thisline[1])
							if not silent:
								dbg.log("%s" % logline)
							logfile.write(logline,thislog)
							fulllist_str += thislinebytes
							fulllist_bin += thisline[0]

						if not silent:
							dbg.log("")
							dbg.log("Full encoded string:")
							dbg.log("--------------------")
							dbg.log("%s" % fulllist_bin)
						logfile.write("",thislog)
						logfile.write("Full encoded string:",thislog)
						logfile.write("--------------------",thislog)
						logfile.write("%s" % fulllist_bin,thislog)
						logfile.write("",thislog)
						logfile.write("Full encoded hex:",thislog)
						logfile.write("-----------------",thislog)
						logfile.write("%s" % fulllist_str,thislog)
			return

		def procString(args):
			mode = ""
			useunicode = False
			terminatestring = True
			addy = 0
			regs = dbg.getRegs()
			stringtowrite = ""
			# read or write ?
			if not "r" in args and not "w" in args:
				dbg.log("*** Error: you must indicate if you want to read (-r) or write (-w) ***",highlight=True)
				return
			addresserror = False
			if not "a" in args:
				addresserror = True
			else:
				if type(args["a"]).__name__.lower() != "bool":
					# check if it's a register or not
					if str(args["a"]).upper() in regs:
						addy = regs[str(args["a"].upper())]
					else:
						addy = int(args["a"],16)
				else:
					addresserror = True

			if addresserror:
				dbg.log("*** Error: you must specify a valid address with -a ***",highlight=True)
				return

			if "w" in args:
				mode = "write"
			if "r" in args:
				# read wins, because it's non destructive
				mode = "read"
			if "u" in args:
				useunicode = True

			stringerror = False
			if "w" in args and not "s" in args:
				stringerror = True
			if "s" in args:
				if type(args["s"]).__name__.lower() != "bool":
					stringtowrite = args["s"]
				else:
					stringerror = True

			if "noterminate" in args:
				terminatestring = False

			if stringerror:
				dbg.log("*** Error: you must specify a valid string with -s ***",highlight=True)
				return

			if mode == "read":
				stringinmemory = ""
				extra = " "
				try:
					if not useunicode:
						stringinmemory = dbg.readString(addy)
					else:
						stringinmemory = dbg.readWString(addy)
						extra = " (unicode) "
					dbg.log("String%sat 0x%08x:" % (extra,addy))
					dbg.log("%s" % stringinmemory)
				except:
					dbg.log("Unable to read string at 0x%08x" % addy)
			if mode == "write":
				origstring = stringtowrite
				writtendata = ""
				try:
					if not useunicode:
						if terminatestring:
							stringtowrite += "\x00"
						byteswritten = ""
						for c in stringtowrite:
							byteswritten += " %s" % bin2hex(c)
						dbg.writeMemory(addy,stringtowrite)
						writtendata = dbg.readString(addy)
						dbg.log("Wrote string (%d bytes) to 0x%08x:" % (len(stringtowrite),addy))
						dbg.log("%s" % byteswritten)
					else:
						newstring = ""
						for c in stringtowrite:
							newstring += "%s%s" % (c,"\x00")
						if terminatestring:
							newstring += "\x00\x00"
						dbg.writeMemory(addy,newstring)
						dbg.log("Wrote unicode string (%d bytes) to 0x%08x" % (len(newstring),addy))
						writtendata = dbg.readWString(addy)
						byteswritten = ""
						for c in newstring:
							byteswritten += " %s" % bin2hex(c)
						dbg.log("%s" % byteswritten)
					if not writtendata.startswith(origstring):
						dbg.log("Write operation succeeded, but the string in memory doesn't appear to be there",highlight=True)
				except:
					dbg.log("Unable to write the string to 0x%08x" % addy)	
					dbg.logLines(traceback.format_exc(),highlight=True)			
			return


		def procKb(args):
			validcommands = ['set','list','del']
			validcommandfound = False
			selectedcommand = ""
			selectedid = ""
			selectedvalue = ""
			for command in validcommands:
				if command in args:
					validcommandfound = True
					selectedcommand = command
					break
			dbg.log("")
			if not validcommandfound:
				dbg.log("*** Please specify a valid command. Valid commands are :")
				for command in validcommands:
					dbg.log("    -%s" % command)
				return

			if "id" in args:
				if type(args["id"]).__name__.lower() != "bool":
					selectedid = args["id"]

			if "value" in args:
				if type(args["value"]).__name__.lower() != "bool":
					selectedvalue = args["value"]

			dbg.log("Knowledgebase database : %s" % dbg.getKBDB())
			kb = dbg.listKnowledge()
			if selectedcommand == "list":
				dbg.log("Number of IDs in Knowledgebase : %d" % len(kb))
				if len(kb) > 0:
					if selectedid == "":
						dbg.log("IDs :")
						dbg.log("-----")
						for kbid in kb:
							dbg.log(kbid)
					else:
						if selectedid in kb:
							kbid = dbg.getKnowledge(selectedid)
							kbtype = kbid.__class__.__name__
							kbtitle = "Entries for ID %s (type %s) :" % (selectedid,kbtype)
							dbg.log(kbtitle)
							dbg.log("-" * (len(kbtitle)+2))
							if selectedvalue != "":
								dbg.log("  (Filter : %s)" % selectedvalue)
							nrentries = 0
							if kbtype == "dict":
								for dictkey in kbid:
									if selectedvalue == "" or selectedvalue in dictkey:
										logline = ""
										if kbid[dictkey].__class__.__name__ == "int" or kb[dictkey].__class__.__name__ == "long":
											logline = "  %s : %d (0x%x)" % (str(dictkey),kbid[dictkey],kbid[dictkey])
										else:
											logline = "  %s : %s" % (str(dictkey),kbid[dictkey])
										dbg.log(logline)
										nrentries += 1
							if kbtype == "list":
								cnt = 0
								for entry in kbid:
									dbg.log("  %d : %s" % (cnt,kbid[entry]))
									cnt += 1
									nrentries += 1
							if kbtype == "str":
								dbg.log("  %s" % kbid)
								nrentries += 1
							if kbtype == "int" or kbtype == "long":
								dbg.log("  %d (0x%08x)" % (kbid,kbid))
								nrentries += 1

							dbg.log("")
							filtertxt = ""
							if selectedvalue != "":
								filtertxt="filtered "
							dbg.log("Number of %sentries for ID %s : %d" % (filtertxt,selectedid,nrentries))
						else:
							dbg.log("ID %s was not found in the Knowledgebase" % selectedid)

			if selectedcommand == "set":
				# we need an ID and a value argument
				if selectedid == "":
					dbg.log("*** Please enter a valid ID with -id",highlight=1)
					return
				if selectedvalue == "":
					dbg.log("*** Please enter a valid value",highlight=1)
					return
				if selectedid in kb:
					# vtableCache
					if selectedid == "vtableCache":
						# split on command
						valueparts = selectedvalue.split(",")
						if len(valueparts) == 2:
							vtablename = valueparts[0].strip(" ")
							vtablevalue = 0
							if "0x" in valueparts[1].lower():
								vtablevalue = int(valueparts[1],16)
							else:
								vtablevalue = int(valueparts[1])
							kbadd = {}
							kbadd[vtablename] = vtablevalue
							dbg.addKnowledge(selectedid,kbadd)
						else:
							dbg.log("*** Please provide a valid value for -value")
							dbg.log("*** KB %s contains a list, please use a comma")
							dbg.log("*** to separate entries. First entry should be a string,")
							dbg.log("*** Second entry should be an integer.")
							return
					else:
						dbg.addKnowledge(selectedid,selectedvalue)
					dbg.log(" ")
					dbg.log("ID %s updated." % selectedid)
				else:
					dbg.log("ID %s was not found in the Knowledgebase" % selectedid)

			if selectedcommand == "del":
				if selectedid == "" or selectedid not in kb:
					dbg.log("*** Please enter a valid ID with -id",highlight=1)
					return
				else:
					dbg.forgetKnowledge(selectedid,selectedvalue)
				if selectedvalue == "":
					dbg.log("*** Entire ID %s removed from Knowledgebase" % selectedid)
				else:
					dbg.log("*** Object %s in ID %s removed from Knowledgebase" % (selectedvalue,selectedid))
			return

		def procBPSeh(self):
			sehchain = dbg.getSehChain()
			dbg.log("Nr of SEH records : %d" % len(sehchain))
			if len(sehchain) > 0:
				dbg.log("SEH Chain :")
				dbg.log("-----------")
				dbg.log("Address     Next SEH    Handler")
				for sehrecord in sehchain:
					address = sehrecord[0]
					sehandler = sehrecord[1]
					nseh = ""
					try:
						nsehvalue = struct.unpack('<L',dbg.readMemory(address,4))[0]
						nseh = "0x%08x" % nsehvalue
					except:
						nseh = "0x????????"
					bpsuccess = True
					try:
						if __DEBUGGERAPP__ == "WinDBG":
							bpsuccess = dbg.setBreakpoint(sehandler)
						else:
							dbg.setBreakpoint(sehandler)
							bpsuccess = True
					except:
						bpsuccess = False
					bptext = ""
					if not bpsuccess:
						bptext = "BP failed"
					else:
						bptext = "BP set"
					ptr = MnPointer(sehandler)
					funcinfo = ptr.getPtrFunction()
					dbg.log("0x%08x  %s  0x%08x %s <- %s" % (address,nseh,sehandler,funcinfo,bptext))
			dbg.log("")
			return "Done"

		def procSehChain(self):
			sehchain = dbg.getSehChain()
			dbg.log("Nr of SEH records : %d" % len(sehchain))
			handlersoverwritten = {}
			if len(sehchain) > 0:
				dbg.log("Start of chain (TEB FS:[0]) : 0x%08x" % sehchain[0][0])
				dbg.log("Address     Next SEH    Handler")
				dbg.log("-------     --------    -------")
				for sehrecord in sehchain:
					recaddress = sehrecord[0]
					sehandler = sehrecord[1]
					nseh = ""
					try:
						nsehvalue = struct.unpack('<L',dbg.readMemory(recaddress,4))[0]
						nseh = "0x%08x" % nsehvalue
					except:
						nseh = 0
						sehandler = 0
					overwritedata = checkSEHOverwrite(recaddress,nseh,sehandler)
					overwritemark = ""
					funcinfo = ""
					if sehandler > 0:
						ptr = MnPointer(sehandler)
						funcinfo = ptr.getPtrFunction()
					else:
						funcinfo = " (corrupted record)"
						if str(nseh).startswith("0x"):
							nseh = "0x%08x" % int(nseh,16)
						else:
							nseh = "0x%08x" % int(nseh)
					if len(overwritedata) > 0:
						handlersoverwritten[recaddress] = overwritedata
						smashoffset = int(overwritedata[1])
						typeinfo = ""
						if overwritedata[0] == "unicode":
							smashoffset += 2
							typeinfo = " [unicode]"
						overwritemark = " (record smashed at offset %d%s)" % (smashoffset,typeinfo)
						
					dbg.log("0x%08x  %s  0x%08x %s%s" % (recaddress,nseh,sehandler,funcinfo, overwritemark), recaddress)
			if len(handlersoverwritten) > 0:
				dbg.log("")
				dbg.log("Payload structure suggestion(s):")
				for overwrittenhandler in handlersoverwritten:
					overwrittendata = handlersoverwritten[overwrittenhandler]
					overwrittentype = overwrittendata[0]
					overwrittenoffset = int(overwrittendata[1])
					if not overwrittentype == "unicode":
						dbg.log("[Junk * %d]['\\xeb\\x06\\x41\\x41'][p/p/r][shellcode][more junk if needed]" % (overwrittenoffset))
					else:
						overwrittenoffset += 2
						dbg.log("[Junk * %d][nseh - walkover][unicode p/p/r][venetian alignment][shellcode][more junk if needed]" % overwrittenoffset)
			return


		def procDumpLog(args):
			logfile = ""
			levels = 0
			nestedsize = 0x28
			filtersize = 0
			ignorefree = False
			
			if "f" in args:
				if type(args["f"]).__name__.lower() != "bool":
					logfile = args["f"]
			
			if "nofree" in args:
				ignorefree = True			
					

			if "l" in args:
				if type(args["l"]).__name__.lower() != "bool":
					if str(args["l"]).lower().startswith("0x"):
						try:
							levels = int(args["l"],16)
						except:
							levels = 0
					else:
						try:
							levels = int(args["l"])
						except:
							levels = 0

			if "m" in args:
				if type(args["m"]).__name__.lower() != "bool":
					if str(args["m"]).lower().startswith("0x"):
						try:
							nestedsize = int(args["m"],16)
						except:
							nestedsize = 0x28
					else:
						try:
							nestedsize = int(args["m"])
						except:
							nestedsize = 0x28

			if "s" in args:
				if type(args["s"]).__name__.lower() != "bool":
					if str(args["s"]).lower().startswith("0x"):
						try:
							filtersize = int(args["s"],16)
						except:
							filtersize = 0
					else:
						try:
							filtersize = int(args["s"])
						except:
							filtersize = 0

			if logfile == "":
				dbg.log(" *** Error: please specify a valid logfile with argument -f ***",highlight=1)
				return

			allocs = 0
			frees = 0
			# open logfile and record all objects & sizes
			logdata = {}
			try:
				dbg.log("[+] Parsing logfile %s" % logfile)
				f = open(logfile,"rb")
				contents = f.readlines()
				f.close()

				for tline in contents:
					line = str(tline)
					if line.startswith("alloc("):
						size = ""
						addy = ""
						lineparts = line.split("(")
						if len(lineparts) > 1:
							sizeparts = lineparts[1].split(")")
							size = sizeparts[0].replace(" ","")
						lineparts = line.split("=")
						if len(lineparts) > 1:
							linepartaddy = lineparts[1].split(" ")
							for lpa in linepartaddy:
								if addy != "":
									break
								if lpa != "":
									addy = lpa 
						if size != "" and addy != "":
							size = size.lower()
							addy = addy.lower()
							if not addy in logdata:
								if filtersize == 0:
									logdata[addy] = size
									allocs += 1
								else:
									try:
										isize = int(size,16)
										if isize == filtersize:
											logdata[addy] = size
											allocs += 1
									except:
										continue

					if line.startswith("free(") and not ignorefree:
						addy = ""
						lineparts = line.split("(")
						if len(lineparts) > 1:
							addyparts = lineparts[1].split(")")
							addy = addyparts[0].replace(" ","")
						if addy != "":
							addy = addy.lower()
							if addy in logdata:
								del logdata[addy]
								frees += 1			

				if ignorefree:
					dbg.log("[+] Ignoring all free() events, showing all allocations")
				dbg.log("[+] Logfile parsed, %d objects found" % len(logdata))
				if filtersize > 0:
					dbg.log("    Only showing alloc chunks of size 0x%08x" % filtersize)
				dbg.log("    Total allocs: %d, total free: %d" % (allocs,frees))
				dbg.log("[+] Dumping objects")
				logfile = MnLog("dump_alloc_free.txt")
				thislog = logfile.reset()
				logfile.write("Addresses to dump:", thislog)
				allocsizegroups = {}
				allocsizes = []
				heapgranularity = 8
				for addy in logdata:
					logfile.write("%s (%s)" % (addy, logdata[addy]), thislog)
					allocsize = getHeapAllocSize(logdata[addy], heapgranularity)
					if not allocsize in allocsizegroups:
						allocsizegroups[allocsize] = [addy]
					else:
						allocsizegroups[allocsize].append(addy)
					if not allocsize in allocsizes:
						allocsizes.append(allocsize)
				logfile.write("", thislog);
				logfile.write("(Allocated) Size groups, heap granularity %d bytes" % heapgranularity, thislog)
				allocsizes.sort()
				for allocsize in allocsizes:
					logfile.write("Size 0x%02x" % allocsize, thislog)
					for allocsizeaddy in allocsizegroups[allocsize]:
						logfile.write("  %s (%s)" % (allocsizeaddy, logdata[allocsizeaddy]), thislog)
					
				for addy in logdata:
					asize = logdata[addy]
					ptrx = MnPointer(int(addy,16))
					size = int(asize,16)
					dumpdata = ptrx.dumpObjectAtLocation(size,levels,nestedsize,thislog,logfile)
					
			except:
				dbg.log(" *** Unable to open logfile %s ***" % logfile,highlight=1)
				dbg.log(traceback.format_exc())
				return


			return


		def procDumpObj(args):
			addy = 0
			levels = 0
			size = 0
			nestedsize = 0x28
			regs = dbg.getRegs()
			if "a" in args:
				if type(args["a"]).__name__.lower() != "bool":
					addy,addyok = getAddyArg(args["a"])

			if "s" in args:
				if type(args["s"]).__name__.lower() != "bool":
					if str(args["s"]).lower().startswith("0x"):
						try:
							size = int(args["s"],16)
						except:
							size = 0
					else:
						try:
							size = int(args["s"])
						except:
							size = 0

			if "l" in args:
				if type(args["l"]).__name__.lower() != "bool":
					if str(args["l"]).lower().startswith("0x"):
						try:
							levels = int(args["l"],16)
						except:
							levels = 0
					else:
						try:
							levels = int(args["l"])
						except:
							levels = 0

			if "m" in args:
				if type(args["m"]).__name__.lower() != "bool":
					if str(args["m"]).lower().startswith("0x"):
						try:
							nestedsize = int(args["m"],16)
						except:
							nestedsize = 0
					else:
						try:
							nestedsize = int(args["m"])
						except:
							nestedsize = 0

			errorsfound = False
			if addy == 0:
				errorsfound = True
				dbg.log("*** Please specify a valid address to argument -a ***",highlight=1)
			else:
				ptrx = MnPointer(addy)
			osize = size
			if size == 0:
				# no size specified
				if addy > 0:
					dbg.log("[+] No size specified, checking if address is part of known heap chunk")
					
					if ptrx.isInHeap():
						heapinfo = ptrx.getHeapInfo()
						heapaddy = heapinfo[0]
						chunkobj = heapinfo[3]
						if not heapaddy == None:
							if heapaddy > 0:
								chunkaddy = chunkobj.chunkptr
								size = chunkobj.usersize
								dbg.log("    Address found in chunk 0x%08x, heap 0x%08x, (user)size 0x%02x" % (chunkaddy, heapaddy, size))
								addy = chunkobj.userptr
								if size > 0xfff:
									dbg.log("    I'll only dump 0xfff bytes from the object, for performance reasons")
									size = 0xfff
			if size > 0xfff and osize > 0:
				errorsfound = True
				dbg.log("*** Please keep the size below 0xfff (argument -s) ***",highlight=1)
			if size == 0:
				size = 0x28
			if levels > 0 and nestedsize == 0:
				errorsfound = True
				dbg.log("*** Please specify a valid size to argument -m ***",highlight=1)				

			if not errorsfound:
				ptrx = MnPointer(addy)
				dumpdata = ptrx.dumpObjectAtLocation(size,levels,nestedsize)

			return


		# routine to copy bytes from one location to another
		def procCopy(args):
			src = 0
			dst = 0
			nrbytes = 0
			regs = dbg.getRegs()
			if "src" in args:
				if type(args["src"]).__name__.lower() != "bool":
					src,addyok = getAddyArg(args["src"])

			if "dst" in args:
				if type(args["dst"]).__name__.lower() != "bool":
					dst,addyok = getAddyArg(args["dst"])

			if "n" in args:
				if type(args["n"]).__name__.lower() != "bool":
					if "+" in str(args['n']) or "-" in str(args['n']):
						nrbytes,bytesok = getAddyArg(args['n'])
						if not bytesok:
							errorsfound = True
					else:
						if str(args['n']).lower().startswith("0x"):
							try:
								nrbytes = int(args["n"],16)
							except:
								nrbytes = 0
						else:
							try:
								nrbytes = int(args["n"])
							except:
								nrbytes = 0

			errorsfound = False
			if src == 0:
				errorsfound = True
				dbg.log("*** Please specify a valid source address to argument -src ***",highlight=1)
			if dst == 0:
				errorsfound = True
				dbg.log("*** Please specify a valid destination address to argument -dst ***",highlight=1)
			if nrbytes == 0:
				errorsfound = True
				dbg.log("*** Please specify a valid number of bytes to argument -n ***",highlight=1)

			if not errorsfound:
				dbg.log("[+] Attempting to copy 0x%08x bytes from 0x%08x to 0x%08x" % (nrbytes, src, dst))
				sourcebytes = dbg.readMemory(src,nrbytes)
				try:
					dbg.writeMemory(dst,sourcebytes)
					dbg.log("    Done.")
				except:
					dbg.log("    *** Copy failed, check if both locations are accessible/mapped",highlight=1)

			return



		# unicode alignment routines written by floyd (http://www.floyd.ch, twitter: @floyd_ch)
		def procUnicodeAlign(args):
			leaks = False
			address = 0
			alignresults = {}
			bufferRegister = "eax" #we will put ebp into the buffer register
			timeToRun = 15
			registers = {"eax":0, "ebx":0, "ecx":0, "edx":0, "esp":0, "ebp":0,}
			showerror = False
			regs = dbg.getRegs()

			if "l" in args:
				leaks = True

			if "a" in args:
				if type(args["a"]).__name__.lower() != "bool":
					address,addyok = getAddyArg(args["a"])
			else:
				address = regs["EIP"]
				if leaks:
					address += 1

			if address == 0:
				dbg.log("Please enter a valid address with argument -a",highlight=1)
				dbg.log("This address must be the location where the alignment code will be placed/start")
				dbg.log("(without leaking zero byte). Don't worry, the script will only use")
				dbg.log("it to calculate the offset from the address to EBP.")
				showerror=True

			if "b" in args:
				if args["b"].lower().strip() == "eax":
					bufferRegister = 'eax'
				elif args["b"].lower().strip() == "ebx":
					bufferRegister = 'ebx'
				elif args["b"].lower().strip() == "ecx":
					bufferRegister = 'ecx'
				elif args["b"].lower().strip() == "edx":
					bufferRegister = 'edx'
				else:
					dbg.log("Please enter a valid register with argument -b")
					dbg.log("Valid registers are: eax, ebx, ecx, edx")
					showerror = True

			if "t" in args and args["t"] != "":
				try:
					timeToRun = int(args["t"])
					if timeToRun < 0:
						timeToRun = timeToRun * (-1)
				except:
					dbg.log("Please enter a valid integer for -t",highlight=1)
					showerror=True
			if "ebp" in args and args["ebp"] != "":
				try:
					registers["ebp"] = int(args["ebp"],16)
				except:
					dbg.log("Please enter a valid value for ebp",highlight=1)
					showerror=True

			dbg.log("[+] Start address for venetian alignment routine: 0x%08x" % address)
			dbg.log("[+] Will prepend alignment with null byte compensation? %s" % str(leaks).lower())
			# ebp must be writeable for this routine to work
			value_of_ebp = regs["EBP"]
			dbg.log("[+] Checking if ebp (0x%08x) is writeable" % value_of_ebp)
			ebpaccess = getPointerAccess(value_of_ebp)
			if not "WRITE" in ebpaccess:
				dbg.log("[!] Warning! ebp does not appear to be writeable!",highlight = 1)
				dbg.log("    You will have to run some custom instructions first to make ebp writeable")
				dbg.log("    and at that point, run this mona command again.")
				dbg.log("    Hints: maybe you can pop something off the stack into ebp,")
				dbg.log("    or push esp and pop it into ebp.")
				showerror = True
			else:
				dbg.log("    OK (%s)" % ebpaccess)
			if not showerror:

				alignresults = prepareAlignment(leaks, address, bufferRegister, timeToRun, registers)
				# write results to file
				if len(alignresults) > 0:
					if not silent:
						dbg.log("[+] Alignment generator finished, %d results" % len(alignresults))
						logfile = MnLog("venetian_alignment.txt")
						thislog = logfile.reset()
						for resultnr in alignresults:
							resulttitle = "Alignment routine %d:" % resultnr
							logfile.write(resulttitle,thislog)
							logfile.write("-" * len(resulttitle),thislog)
							theseresults = alignresults[resultnr]
							for resultinstructions in theseresults:
								logfile.write("Instructions:",thislog)
								resultlines = resultinstructions.split(";")
								for resultline in resultlines:
									logfile.write("   %s" % resultline.strip(),thislog)
								logfile.write("Hex:",thislog)
								logfile.write("'%s'" % theseresults[resultinstructions],thislog)
							logfile.write("",thislog)
			return alignresults


		def prepareAlignment(leaks, address, bufferRegister, timeToRun, registers):

			def getRegister(registerName):
				registerName = registerName.upper()
				regs = dbg.getRegs()
				if registerName in regs:
					return regs[registerName]

			def calculateNewXregister(x,h,l):
				return ((x>>16)<<16)+(h<<8)+l

			prefix = ""
			postfix = ""
			additionalLength = 0 #Length of the prefix+postfix instructions in after-unicode-conversion bytes
			code_to_get_rid_of_zeros = "add [ebp],ch; " #\x6d --> \x00\x6d\x00

			buf_sig = bufferRegister[1]
			
			registers_to_fill = ["ah", "al", "bh", "bl", "ch", "cl", "dh", "dl"] #important: h's first!
			registers_to_fill.remove(buf_sig+"h")
			registers_to_fill.remove(buf_sig+"l")
			
			leadingZero = leaks

			for name in registers:
				if not registers[name]:
					registers[name] = getRegister(name)

			#256 values with only 8276 instructions (bruteforced), best found so far:
			#values_to_generate_all_255_values = [71, 87, 15, 251, 162, 185]
			#but to be on the safe side, let's take only A-Za-z values (in 8669 instructions):
			values_to_generate_all_255_values = [86, 85, 75, 109, 121, 99]
			
			new_values = zip(registers_to_fill, values_to_generate_all_255_values)
			
			if leadingZero:
				prefix += code_to_get_rid_of_zeros
				additionalLength += 2
				leadingZero = False
			#prefix += "mov bl,0; mov bh,0; mov cl,0; mov ch,0; mov dl,0; mov dh,0; "
			#additionalLength += 12
			for name, value in zip(registers_to_fill, values_to_generate_all_255_values):
				padding = ""
				if value < 16:
					padding = "0"
				if "h" in name:
					prefix += "mov e%sx,0x4100%s%s00; " % (name[0], padding, hex(value)[2:])
					prefix += "add [ebp],ch; "
					additionalLength += 8
				if "l" in name:
					prefix += "mov e%sx,0x4100%s%s00; " % (buf_sig, padding, hex(value)[2:])
					prefix += "add %s,%sh; " % (name, buf_sig)
					prefix += "add [ebp],ch; "
					additionalLength += 10
			leadingZero = False
			new_values_dict = dict(new_values)
			for new in registers_to_fill[::2]:
				n = new[0]
				registers['e%sx'%n] = calculateNewXregister(registers['e%sx'%n], new_values_dict['%sh'%n], new_values_dict['%sl'%n])
			
			if leadingZero:
				prefix += code_to_get_rid_of_zeros
				additionalLength += 2
				leadingZero = False
			#Let's push the value of ebp into the BufferRegister
			prefix += "push ebp; %spop %s; " % (code_to_get_rid_of_zeros, bufferRegister)
			leadingZero = True
			additionalLength += 6
			registers[bufferRegister] = registers["ebp"]

			if not leadingZero:
				#We need a leading zero for the ADD operations
				prefix += "push ebp; " #something 1 byte, doesn't matter what
				leadingZero = True
				additionalLength += 2
						
			#The last ADD command will leak another zero to the next instruction
			#Therefore append (postfix) a last instruction to get rid of it
			#so the shellcode is nicely aligned				
			postfix += code_to_get_rid_of_zeros
			additionalLength += 2
			
			alignresults = generateAlignment(address, bufferRegister, registers, timeToRun, prefix, postfix, additionalLength)

			return alignresults


		def generateAlignment(alignment_code_loc, bufferRegister, registers, timeToRun, prefix, postfix, additionalLength):

			import copy, random, time

			alignresults = {}

			def sanitiseZeros(originals, names):
				for index, i in enumerate(originals):
					if i == 0:
						warn("Your %s register is zero. That's bad for the heuristic." % names[index])
						warn("In general this means there will be no result or they consist of more bytes.")

			def checkDuplicates(originals, names):
				duplicates = len(originals) - len(set(originals))
				if duplicates > 0:
					warn("""Some of the 2 byte registers seem to be the same. There is/are %i duplicate(s):""" % duplicates)
					warn("In general this means there will be no result or they consist of more bytes.")
					warn(", ".join(names))
					warn(", ".join(hexlist(originals)))

			def checkHigherByteBufferRegisterForOverflow(g1, name, g2):
				overflowDanger = 0x100-g1
				max_instructions = overflowDanger*256-g2
				if overflowDanger <= 3:
					warn("Your BufferRegister's %s register value starts pretty high (%s) and might overflow." % (name, hex(g1)))
					warn("Therefore we only look for solutions with less than %i bytes (%s%s until overflow)." % (max_instructions, hex(g1), hex(g2)[2:]))
					warn("This makes our search space smaller, meaning it's harder to find a solution.")
				return max_instructions

			def randomise(values, maxValues):
				for index, i in enumerate(values):
					if random.random() <= MAGIC_PROBABILITY_OF_ADDING_AN_ELEMENT_FROM_INPUTS:
						values[index] += 1 
						values[index] = values[index] % maxValues[index]

			def check(as1, index_for_higher_byte, ss, gs, xs, ys, M, best_result):
				g1, g2 = gs
				s1, s2 = ss
				sum_of_instructions = 2*sum(xs) + 2*sum(ys) + M
				if best_result > sum_of_instructions:
					res0 = s1
					res1 = s2
					for index, _ in enumerate(as1):
						res0 += as1[index]*xs[index] % 256
					res0 = res0 - ((g2+sum_of_instructions)/256)
					as2 = copy.copy(as1)
					as2[index_for_higher_byte] = (g1 + ((g2+sum_of_instructions)/256)) % 256
					for index, _ in enumerate(as2):
						res1 += as2[index]*ys[index] % 256
					res1 = res1 - sum_of_instructions
					if g1 == res0 % 256 and g2 == res1 % 256:
						return sum_of_instructions
				return 0
			
			def printNicely(names, buffer_registers_4_byte_names, xs, ys, additionalLength=0, prefix="", postfix=""):
				
				thisresult = {}

				resulting_string = prefix
				sum_bytes = 0
				for index, x in enumerate(xs):
					for k in range(0, x):
						resulting_string += "add "+buffer_registers_4_byte_names[0]+","+names[index]+"; "
						sum_bytes += 2
				for index, y in enumerate(ys):
					for k in range(y):
						resulting_string += "add "+buffer_registers_4_byte_names[1]+","+names[index]+"; "
						sum_bytes += 2
				resulting_string += postfix
				sum_bytes += additionalLength
				if not silent:
					info("[+] %i resulting bytes (%i bytes injection) of Unicode code alignment. Instructions:"%(sum_bytes,sum_bytes/2))
					info("   ", resulting_string)
				hex_string = metasm(resulting_string)
				if not silent:
					info("    Unicode safe opcodes without zero bytes:")
					info("   ", hex_string)
				thisresult[resulting_string] = hex_string
				return thisresult


			def metasm(inputInstr):
				#the immunity and metasm assembly differ a lot:
				#immunity add [ebp],ch "\x00\xad\x00\x00\x00\x00"
				#metasm add [ebp],ch "\x00\x6d\x00" --> we want this!
				#Therefore implementing our own "metasm" mapping here
				#same problem for things like mov eax,0x41004300			     
				ass_operation = {'add [ebp],ch': '\\x00\x6d\\x00', 'pop ebp': ']', 'pop edx': 'Z', 'pop ecx': 'Y', 'push ecx': 'Q',
						 'pop ebx': '[', 'push ebx': 'S', 'pop eax': 'X', 'push eax': 'P', 'push esp': 'T', 'push ebp': 'U',
						 'push edx': 'R', 'pop esp': '\\', 'add dl,bh': '\\x00\\xfa', 'add dl,dh': '\\x00\\xf2',
						 'add dl,ah': '\\x00\\xe2', 'add ah,al': '\\x00\\xc4', 'add ah,ah': '\\x00\\xe4', 'add ch,bl': '\\x00\\xdd',
						 'add ah,cl': '\\x00\\xcc', 'add bl,ah': '\\x00\\xe3', 'add bh,dh': '\\x00\\xf7', 'add bl,cl': '\\x00\\xcb',
						 'add ah,ch': '\\x00\\xec', 'add bl,al': '\\x00\\xc3', 'add bh,dl': '\\x00\\xd7', 'add bl,ch': '\\x00\\xeb',
						 'add dl,cl': '\\x00\\xca', 'add dl,bl': '\\x00\\xda', 'add al,ah': '\\x00\\xe0', 'add bh,ch': '\\x00\\xef',
						 'add al,al': '\\x00\\xc0', 'add bh,cl': '\\x00\\xcf', 'add al,ch': '\\x00\\xe8', 'add dh,bl': '\\x00\\xde',
						 'add ch,ch': '\\x00\\xed', 'add cl,dl': '\\x00\\xd1', 'add al,cl': '\\x00\\xc8', 'add dh,bh': '\\x00\\xfe',
						 'add ch,cl': '\\x00\\xcd', 'add cl,dh': '\\x00\\xf1', 'add ch,ah': '\\x00\\xe5', 'add cl,bl': '\\x00\\xd9',
						 'add dh,al': '\\x00\\xc6', 'add ch,al': '\\x00\\xc5', 'add cl,bh': '\\x00\\xf9', 'add dh,ah': '\\x00\\xe6',
						 'add dl,dl': '\\x00\\xd2', 'add dh,cl': '\\x00\\xce', 'add dh,dl': '\\x00\\xd6', 'add ah,dh': '\\x00\\xf4',
						 'add dh,dh': '\\x00\\xf6', 'add ah,dl': '\\x00\\xd4', 'add ah,bh': '\\x00\\xfc', 'add ah,bl': '\\x00\\xdc',
						 'add bl,bh': '\\x00\\xfb', 'add bh,al': '\\x00\\xc7', 'add bl,dl': '\\x00\\xd3', 'add bl,bl': '\\x00\\xdb',
						 'add bh,ah': '\\x00\\xe7', 'add bl,dh': '\\x00\\xf3', 'add bh,bl': '\\x00\\xdf', 'add al,bl': '\\x00\\xd8',
						 'add bh,bh': '\\x00\\xff', 'add al,bh': '\\x00\\xf8', 'add al,dl': '\\x00\\xd0', 'add dl,ch': '\\x00\\xea',
						 'add dl,al': '\\x00\\xc2', 'add al,dh': '\\x00\\xf0', 'add cl,cl': '\\x00\\xc9', 'add cl,ch': '\\x00\\xe9',
						 'add ch,bh': '\\x00\\xfd', 'add cl,al': '\\x00\\xc1', 'add ch,dh': '\\x00\\xf5', 'add cl,ah': '\\x00\\xe1',
						 'add dh,ch': '\\x00\\xee', 'add ch,dl': '\\x00\\xd5', 'add ch,ah': '\\x00\\xe5', 'mov dh,0': '\\xb6\\x00',
						 'add dl,ah': '\\x00\\xe2', 'mov dl,0': '\\xb2\\x00', 'mov ch,0': '\\xb5\\x00', 'mov cl,0': '\\xb1\\x00',
						 'mov bh,0': '\\xb7\\x00', 'add bl,ah': '\\x00\\xe3', 'mov bl,0': '\\xb3\\x00', 'add dh,ah': '\\x00\\xe6',
						 'add cl,ah': '\\x00\\xe1', 'add bh,ah': '\\x00\\xe7'}
				for example_instr, example_op in [("mov eax,0x41004300", "\\xb8\\x00\\x43\\x00\\x41"),
								  ("mov ebx,0x4100af00", "\\xbb\\x00\\xaf\\x00\\x41"),
								  ("mov ecx,0x41004300", "\\xb9\\x00\\x43\\x00\\x41"),
								  ("mov edx,0x41004300", "\\xba\\x00\\x43\\x00\\x41")]:
					for i in range(0,256):
						padding =""
						if i < 16:
							padding = "0"
						new_instr = example_instr[:14]+padding+hex(i)[2:]+example_instr[16:]
						new_op = example_op[:10]+padding+hex(i)[2:]+example_op[12:]
						ass_operation[new_instr] = new_op
				res = ""
				for instr in inputInstr.split("; "):
					if instr in ass_operation:
						res += ass_operation[instr].replace("\\x00","")
					elif instr.strip():
						warn("    Couldn't find metasm assembly for %s" % str(instr))
						warn("    You have to manually convert it in the metasm shell")
						res += "<"+instr+">"
				return res
				
			def getCyclic(originals):
				cyclic = [0 for i in range(0,len(originals))]
				for index, orig_num in enumerate(originals):
					cycle = 1
					num = orig_num
					while True:
						cycle += 1
						num += orig_num
						num = num % 256
						if num == orig_num:
							cyclic[index] = cycle
							break
				return cyclic

			def hexlist(lis):
				return [hex(i) for i in lis]
				
			def theX(num):
				res = (num>>16)<<16 ^ num
				return res
				
			def higher(num):
				res = num>>8
				return res
				
			def lower(num):
				res = ((num>>8)<<8) ^ num
				return res
				
			def info(*text):
				dbg.log(" ".join(str(i) for i in text))
				
			def warn(*text):
				dbg.log(" ".join(str(i) for i in text), highlight=1)
				
			def debug(*text):
				if False:
					dbg.log(" ".join(str(i) for i in text))


			buffer_registers_4_byte_names = [bufferRegister[1]+"h", bufferRegister[1]+"l"]
			buffer_registers_4_byte_value = theX(registers[bufferRegister])
			
			MAGIC_PROBABILITY_OF_ADDING_AN_ELEMENT_FROM_INPUTS=0.25
			MAGIC_PROBABILITY_OF_RESETTING=0.04
			MAGIC_MAX_PROBABILITY_OF_RESETTING=0.11

			originals = []
			ax = theX(registers["eax"])
			ah = higher(ax)
			al = lower(ax)
				
			bx = theX(registers["ebx"])
			bh = higher(bx)
			bl = lower(bx)
			
			cx = theX(registers["ecx"])
			ch = higher(cx)
			cl = lower(cx)
			
			dx = theX(registers["edx"])
			dh = higher(dx)
			dl = lower(dx)
			
			start_address = theX(buffer_registers_4_byte_value)
			s1 = higher(start_address)
			s2 = lower(start_address)
			
			alignment_code_loc_address = theX(alignment_code_loc)
			g1 = higher(alignment_code_loc_address)
			g2 = lower(alignment_code_loc_address)
			
			names = ['ah', 'al', 'bh', 'bl', 'ch', 'cl', 'dh', 'dl']
			originals = [ah, al, bh, bl, ch, cl, dh, dl]
			sanitiseZeros(originals, names)
			checkDuplicates(originals, names)
			best_result = checkHigherByteBufferRegisterForOverflow(g1, buffer_registers_4_byte_names[0], g2)
						
			xs = [0 for i in range(0,len(originals))]
			ys = [0 for i in range(0,len(originals))]
			
			cyclic = getCyclic(originals)
			mul = 1
			for i in cyclic:
				mul *= i

			if not silent:
				dbg.log("[+] Searching for random solutions for code alignment code in at least %i possibilities..." % mul)
				dbg.log("    Bufferregister: %s" % bufferRegister)
				dbg.log("    Max time: %d seconds" % timeToRun)
				dbg.log("")

			#We can't even know the value of AH yet (no, it's NOT g1 for high instruction counts)
			cyclic2 = copy.copy(cyclic)
			cyclic2[names.index(buffer_registers_4_byte_names[0])] = 9999999
			
			number_of_tries = 0.0
			beginning = time.time()
			resultFound = False
			resultcnt = 0
			while time.time()-beginning < timeToRun: #Run only timeToRun seconds!
				randomise(xs, cyclic)
				randomise(ys, cyclic2)
				
				#[Extra constraint!]
				#not allowed: all operations with the bufferRegister,
				#because we can not rely on it's values, e.g.
				#add al, al
				#add al, ah
				#add ah, ah
				#add ah, al
				xs[names.index(buffer_registers_4_byte_names[0])] = 0
				xs[names.index(buffer_registers_4_byte_names[1])] = 0
				ys[names.index(buffer_registers_4_byte_names[0])] = 0
				ys[names.index(buffer_registers_4_byte_names[1])] = 0
				
				tmp = check(originals, names.index(buffer_registers_4_byte_names[0]), [s1, s2], [g1, g2], xs, ys, additionalLength, best_result)

				if tmp > 0:
					best_result = tmp
					#we got a new result
					resultFound = True
					alignresults[resultcnt] = printNicely(names, buffer_registers_4_byte_names, xs, ys, additionalLength, prefix, postfix)
					resultcnt += 1
					if not silent:
						dbg.log("    Time elapsed so far: %s seconds" % (time.time()-beginning))
						dbg.log("")
				#Slightly increases probability of resetting with time
				probability = MAGIC_PROBABILITY_OF_RESETTING+number_of_tries/(10**8)
				if probability < MAGIC_MAX_PROBABILITY_OF_RESETTING:
					number_of_tries += 1.0
				if random.random() <= probability:
					xs = [0 for i in range(0,len(originals))]
					ys = [0 for i in range(0,len(originals))]
			if not silent:
				dbg.log("")
				dbg.log("    Done. Total time elapsed: %s seconds" % (time.time()-beginning))
			

				if not resultFound:
					dbg.log("")
					dbg.log("No results. Please try again (you might want to increase -t)")
				dbg.log("")
				dbg.log("If you are unsatisfied with the result, run the command again and use the -t option")
				dbg.log("")
			return alignresults
		# end unicode alignemt routines


		def procHeapCookie(args):
			# first find all writeable pages
			allpages = dbg.getMemoryPages()
			filename="heapcookie.txt"
			orderedpages = []
			cookiemonsters = []
			for tpage in allpages.keys():
				orderedpages.append(tpage)
			orderedpages.sort()
			for thispage in orderedpages:
				page = allpages[thispage]
				page_base = page.getBaseAddress()
				page_size = page.getSize()
				page_end = page_base + page_size
				acl = page.getAccess(human=True)
				if "WRITE" in acl:
					processpage = True
					# don't even bother if page belongs to module that is ASLR/Rebased
					pageptr = MnPointer(page_base)
					thismodulename = pageptr.belongsTo()
					if thismodulename != "":
						thismod = MnModule(thismodulename)
						if thismod.isAslr or thismod.isRebase:
							processpage = False
					if processpage:
						dbg.log("[+] Walking page 0x%08x - 0x%08x (%s)" % (page_base,page_end,acl))
						startptr = page_base  # we need to start here
						while startptr < page_end-16:
							# pointer needs to pass 3 tests
							try:
								heap_entry = startptr
								userptr = heap_entry + 0x8
								cookieptr = heap_entry + 5
								raw_heapcookie = dbg.readMemory(cookieptr,1)
								heapcookie = struct.unpack("<B",raw_heapcookie)[0]

								hexptr1 = "%08x" % userptr
								hexptr2 = "%08x" % heapcookie 

								a1 = hexStrToInt(hexptr1[6:])
								a2 = hexStrToInt(hexptr2[6:])

								test1 = False
								test2 = False
								test3 = False

								if (a1 & 7) == 0:
									test1 = True
								if (a2 & 1) == 1:
									test2 = True
								if (a2 & 8) == 8:
									test3 = True

								if test1 and test2 and test3:
									cookiemonsters.append(startptr+0x8)
							except:
								pass
							startptr += 1
			dbg.log("")
			if len(cookiemonsters) > 0:
				# write to log
				dbg.log("Found %s (fake) UserPtr pointers." % len(cookiemonsters))
				all_ptrs = {}
				all_ptrs[""] = cookiemonsters
				logfile = MnLog(filename)
				thislog = logfile.reset()
				processResults(all_ptrs,logfile,thislog)
			else:
				dbg.log("Bad luck, no results.")			
			return


		def procFlags(args):
			currentflag = getNtGlobalFlag()
			dbg.log("[+] NtGlobalFlag: 0x%08x" % currentflag)
			flagvalues = getNtGlobalFlagValues(currentflag)
			if len(flagvalues) == 0:
				dbg.log("    No GFlags set")
			else:
				for flagvalue in flagvalues:
					dbg.log("    0x%08x : %s" % (flagvalue,getNtGlobalFlagValueName(flagvalue)))
			return


		def procEval(args):
			# put all args together
			argline = ""
			if len(currentArgs) > 1:
				if __DEBUGGERAPP__ == "WinDBG":
					for a in currentArgs[2:]:
						argline += a
				else:
					for a in currentArgs[1:]:
						argline += a 
				argline = argline.replace(" ","")
			if argline.replace(" ","") != "":
				dbg.log("[+] Evaluating expression '%s'" % argline)
				val,valok = getAddyArg(argline)
				if valok:
					dbg.log("    Result: 0x%08x" % val)
				else:
					dbg.log("    *** Unable to evaluate expression ***")
			else:
				dbg.log("    *** No expression found***")	
			return



		def procDiffHeap(args):

			global ignoremodules
			filenamebefore = "heapstate_before.db"
			filenameafter = "heapstate_after.db"

			ignoremodules = True

			statefilebefore = MnLog(filenamebefore)
			thisstatefilebefore = statefilebefore.reset(clear=False)

			statefileafter = MnLog(filenameafter)
			thisstatefileafter = statefileafter.reset(clear=False)

			ignoremodules = False


			beforestate = {}
			afterstate = {}

			#do we want to save states, or diff them?

			if not "before" in args and not "after" in args and not "diff" in args:
				dbg.log("*** Missing mandatory argument -before, -after or -diff ***", highlight=1)
				return

			if "diff" in args:
				# check if before and after state file exists
				if os.path.exists(thisstatefilebefore) and os.path.exists(thisstatefileafter):
					# read contents from both states into dict
					dbg.log("[+] Reading 'before' state from %s" % thisstatefilebefore)
					beforestate = readPickleDict(thisstatefilebefore)
					dbg.log("[+] Reading 'after' state from %s" % thisstatefileafter)
					afterstate = readPickleDict(thisstatefileafter)
					# compare
					dbg.log("[+] Diffing heap states...")

				else:
					if not os.path.exists(thisstatefilebefore):
						dbg.log("[-] Oops, unable to find 'before' state file %s" % thisstatefilebefore)
					if not os.path.exists(thisstatefileafter):
						dbg.log("[-] Oops, unable to find 'after' state file %s" % thisstatefileafter)
				return

			elif "before" in args:
				thisstatefilebefore = statefilebefore.reset(showheader=False)
				dbg.log("[+] Enumerating current heap layout, please wait...")
				currentstate = getCurrentHeapState()
				dbg.log("[+] Saving current heap layout to 'before' heap state file %s" % thisstatefilebefore)
				# save dict to file
				try:
					writePickleDict(thisstatefilebefore, currentstate)
					dbg.log("[+] Done")
				except:
					dbg.log("[-] Error while saving current state to file")
				return

			elif "after" in args:
				thisstatefileafter = statefileafter.reset(showheader=False)
				dbg.log("[+] Enumerating current heap layout, please wait...")
				currentstate = getCurrentHeapState()
				dbg.log("[+] Saving current heap layout to 'after' heap state file %s" % thisstatefileafter)
				try:
					writePickleDict(thisstatefileafter, currentstate)
					dbg.log("[+] Done")
				except:
					dbg.log("[-] Error while saving current state to file")				
				return			

			return


		def procFlow(args):

			srplist = []
			endlist = []
			cregs = []
			cregsc = []
			avoidlist = []
			endloc = 0
			rellist = {}
			funcnamecache = {}
			branchstarts = {}
			maxinstr = 60
			maxcalllevel = 3
			callskip = 0
			instrcnt = 0
			regs = dbg.getRegs()
			aregs = getAllRegs()
			addy = regs["EIP"]
			addyerror = False
			eaddy = 0
			showfuncposition = False

			if "cl" in args:
				if type(args["cl"]).__name__.lower() != "bool":
					try:
						maxcalllevel = int(args["cl"])
					except:
						pass

			if "cs" in args:
				if type(args["cs"]).__name__.lower() != "bool":
					try:
						callskip = int(args["cs"])
					except:
						pass
			if "avoid" in args:
				if type(args["avoid"]).__name__.lower() != "bool":
					try:
						avoidl = args["avoid"].replace("'","").replace('"',"").replace(" ","").split(",")
						for aa in avoidl:
							a,aok = getAddyArg(aa)
							if aok:
								if not a in avoidlist:
									avoidlist.append(a)
					except:
						pass		

			if "cr" in args:
				if type(args["cr"]).__name__.lower() != "bool":
					crdata = args["cr"]
					crdata = crdata.replace("'","").replace('"',"").replace(" ","")
					crlist = crdata.split(",")
					for c in crlist:
						c1 = c.upper()
						if c1 in aregs:
							cregs.append(c1)
							csmall = getSmallerRegs(c1)
							for cs in csmall:
								cregs.append(cs)

			if "crc" in args:
				if type(args["crc"]).__name__.lower() != "bool":
					crdata = args["crc"]
					crdata = crdata.replace("'","").replace('"',"").replace(" ","")
					crlist = crdata.split(",")
					for c in crlist:
						c1 = c.upper()
						if c1 in aregs:
							cregsc.append(c1)
							csmall = getSmallerRegs(c1)
							for cs in csmall:
								cregsc.append(cs)

			cregs = list(set(cregs))
			cregsc = list(set(cregsc))

			if "n" in args:
				if type(args["n"]).__name__.lower() != "bool":
					try:
						maxinstr = int(args["n"])
					except:
						pass	

			if "func" in args:
				showfuncposition = True

			if "a" in args:
				if type(args["a"]).__name__.lower() != "bool":
					addy,addyok = getAddyArg(args["a"])
					if not addyok:		
						dbg.log(" ** Please provide a valid start location with argument -a **")
						return

			if "e" in args:
				if type(args["e"]).__name__.lower() != "bool":
					eaddy,eaddyok = getAddyArg(args["e"])
					if not eaddyok:
						dbg.log(" ** Please provide a valid end location with argument -e **")
						return										


			dbg.log("[+] Max nr of instructions per branch: %d" % maxinstr)
			dbg.log("[+] Maximum CALL level: %d" % maxcalllevel)
			if len(avoidlist) > 0:
				dbg.log("[+] Only showing flows that don't contains these pointer(s):")
				for a in avoidlist:
					dbg.log("    0x%08x" % a)
			if callskip > 0:
				dbg.log("[+] Skipping details of the first %d child functions" % callskip)
			if eaddy > 0:
				dbg.log("[+] Searching all possible paths between 0x%08x and 0x%08x" % (addy,eaddy))
			else:
				dbg.log("[+] Searching all possible paths from 0x%08x" % (addy))
			if len(cregs) > 0:
				dbg.log("[+] Controlled registers: %s" % cregs)
			if len(cregsc) > 0:
				dbg.log("[+] Controlled register contents: %s" % cregsc)

			# first, get SRPs at this point
			if addy == regs["EIP"]:
				cmd2run = "k"
				srpdata = dbg.nativeCommand(cmd2run)
				for line in srpdata.split("\n"):
					linedata = line.split(" ")
					if len(linedata) > 1:
						childebp = linedata[0]
						srp = linedata[1]
						if isAddress(childebp) and isAddress(srp):
							srplist.append(hexStrToInt(srp))

			branchstarts[addy] = [0,srplist,0]
			curlocs = [addy]

			# create relations
			while len(curlocs) > 0:
				curloc = curlocs.pop(0)
				callcnt = 0
				#dbg.log("New start location: 0x%08x" % curloc)
				prevloc = curloc
				instrcnt = branchstarts[curloc][0]
				srplist = branchstarts[curloc][1]
				currcalllevel = branchstarts[curloc][2]
				while instrcnt < maxinstr:
					beforeloc = prevloc
					prevloc = curloc
					try:
						thisopcode = dbg.disasm(curloc)
						instruction = getDisasmInstruction(thisopcode)				
						instructionbytes = thisopcode.getBytes()
						instructionsize = thisopcode.opsize
						opupper = instruction.upper()
						if opupper.startswith("RET"): 
							if currcalllevel > 0:
								currcalllevel -= 1
							if len(srplist) > 0:
								newloc = srplist.pop(0)
								rellist[curloc] = [newloc]
								curloc = newloc
							else:
								break
						elif opupper.startswith("JMP"):
							if "(" in opupper and ")" in opupper:
								ipartsa = opupper.split(")")
								ipartsb = ipartsa[0].split("(")
								if len(ipartsb) > 0:
									jmptarget = ipartsb[1]
									if isAddress(jmptarget):
										newloc = hexStrToInt(jmptarget)
										rellist[curloc] = [newloc]
										curloc = newloc
						elif opupper.startswith("J"):
							if "(" in opupper and ")" in opupper:
								ipartsa = opupper.split(")")
								ipartsb = ipartsa[0].split("(")
								if len(ipartsb) > 0:
									jmptarget = ipartsb[1]
									if isAddress(jmptarget):
										newloc = hexStrToInt(jmptarget)
										if not newloc in curlocs:
											curlocs.append(newloc)
										branchstarts[newloc] = [instrcnt,srplist,currcalllevel]
										newloc2 = prevloc + instructionsize
										rellist[curloc] = [newloc,newloc2]
										curloc = newloc2
										#dbg.log("    Added 0x%08x as alternative branch start" % newloc)
						elif opupper.startswith("CALL"):
							
							if ("(" in opupper and ")" in opupper) and currcalllevel < maxcalllevel and callcnt > callskip:
								ipartsa = opupper.split(")")
								ipartsb = ipartsa[0].split("(")
								if len(ipartsb) > 0:
									jmptarget = ipartsb[1]
									if isAddress(jmptarget):
										newloc = hexStrToInt(jmptarget)
										rellist[curloc] = [newloc]
										curloc = newloc
								newretptr = prevloc + instructionsize
								srplist.insert(0,newretptr)
								currcalllevel += 1
							else:
								# don't show the function details, simply continue after the call
								newloc = curloc+instructionsize
								rellist[curloc] = [newloc]
								curloc = newloc
							callcnt += 1
						else:
							curloc += instructionsize
							rellist[prevloc] = [curloc]
					except:
						#dbg.log("Unable to disasm at 0x%08x, past: 0x%08x" % (curloc,beforeloc))
						if not beforeloc in endlist:
							endlist.append(beforeloc)
						instrcnt = maxinstr
						break
					#dbg.log("%d 0x%08x : %s  -> 0x%08x" % (instrcnt,prevloc,instruction,curloc))
					instrcnt += 1
				if not curloc in endlist:
					endlist.append(curloc)

			dbg.log("[+] Found total of %d possible flows" % len(endlist))

			if eaddy > 0:
				if eaddy in rellist:
					endlist = [eaddy]
					dbg.log("[+] Limit flows to cases that contain 0x%08x" % eaddy)
				else:
					dbg.log(" ** Unable to reach 0x%08x ** " % eaddy)
					dbg.log("    Try increasing max nr of instructions with parameter -n")
					return

			filename = "flows.txt"
			logfile = MnLog(filename)
			thislog = logfile.reset()

			dbg.log("[+] Processing %d endings" % len(endlist))
			endingcnt = 1
			processedresults = []
			for endaddy in endlist:
				dbg.log("[+] Creating all paths between 0x%08x and 0x%08x" % (addy,endaddy))
				allpaths = findAllPaths(rellist,addy,endaddy)
				if len(allpaths) == 0:
					#dbg.log("    *** No paths from 0x%08x to 0x%08x *** " % (addy,endaddy))
					continue

				dbg.log("[+] Ending: 0x%08x (%d/%d), %d paths" % (endaddy,endingcnt,len(endlist), len(allpaths)))
				endingcnt += 1

				for p in allpaths:
					if p in processedresults:
						dbg.log("    > Skipping duplicate path from 0x%08x to 0x%08x" % (addy,endaddy))
					else:
						processedresults.append(p)
						skipthislist = False
						logl = "Path from 0x%08x to 0x%08x (%d instructions) :" % (addy,endaddy,len(p))
						if len(avoidlist) > 0:
							for a in avoidlist:
								if a in p:
									dbg.log("    > Skipping path, contains 0x%08x (which should be avoided)"%a)
									skipthislist = True
									break
						if not skipthislist:
							logfile.write("\n",thislog)
							logfile.write(logl,thislog)
							logfile.write("-" * len(logl),thislog)
							dbg.log("    > Simulating path from 0x%08x to 0x%08x (%d instructions)" % (addy,endaddy,len(p)))
							cregsb = []
							for c in cregs:
								cregsb.append(c)
							cregscb = []
							for c in cregsc:
								cregscb.append(c)

							prevfname = ""
							fname = ""
							foffset = ""
							previnstruction = ""
							for thisaddy in p:
								if showfuncposition:
									if previnstruction == "" or previnstruction.startswith("RET") or previnstruction.startswith("J") or previnstruction.startswith("CALL"):
										if not thisaddy in funcnamecache:
											fname,foffset = getFunctionName(thisaddy)
											funcnamecache[thisaddy] = [fname,foffset]
										else:
											fname = funcnamecache[thisaddy][0]
											foffset = funcnamecache[thisaddy][1]
										if fname != prevfname:
											prevfname = fname
											locname = fname
											if foffset != "":
												locname += "+%s" % foffset
											logfile.write("#--- %s ---" % locname,thislog)
										#dbg.log("%s" % locname)

								thisopcode = dbg.disasm(thisaddy)
								instruction = getDisasmInstruction(thisopcode)
								previnstruction = instruction
								clist = []
								clistc = []
								for c in cregsb:
									combins = []
									combins.append(" %s" % c)
									combins.append("[%s" % c)
									combins.append(",%s" % c)
									combins.append("%s]" % c)
									combins.append("%s-" % c)
									combins.append("%s+" % c)
									combins.append("-%s" % c)
									combins.append("+%s" % c)
									for comb in combins:
										if comb in instruction and not c in clist:
											clist.append(c)

								for c in cregscb:
									combins = []
									combins.append(" %s" % c)
									combins.append("[%s" % c)
									combins.append(",%s" % c)
									combins.append("%s]" % c)
									combins.append("%s-" % c)
									combins.append("%s+" % c)
									combins.append("-%s" % c)
									combins.append("+%s" % c)
									for comb in combins:
										if comb in instruction and not c in clistc:
											clistc.append(c)
								
								rsrc,rdst = getSourceDest(instruction)

								csource = False
								cdest = False

								if rsrc in cregsb or rsrc in cregscb:
									csource = True
								if rdst in cregsb or rdst in cregscb:
									cdest = True

								destructregs = ["MOV","XOR","OR"]
								writeregs = ["INC","DEC","AND"]


								ocregsb = copy.copy(cregsb)

								if not instruction.startswith("TEST") and not instruction.startswith("CMP"):
									for d in destructregs:
										if instruction.startswith(d):
											sourcefound = False
											sourcereg = ""
											destfound = False
											destreg = ""

											for s in clist:
												for sr in rsrc:
													if s in sr and not sourcefound:
														sourcefound = True
														sourcereg = s
												for sr in rdst:
													if s in sr and not destfound:
														destfound = True
														destreg = s

											if sourcefound and destfound:
												if not destreg in cregsb:
													cregsb.append(destreg)
											if destfound and not sourcefound:
												sregs = getSmallerRegs(destreg)
												if destreg in cregsb:
													cregsb.remove(destreg)
												for s in sregs:
													if s in cregsb:
														cregsb.remove(s)
											break
								#else:
									#dbg.log("    Control: %s" % ocregsb)


								logfile.write("0x%08x : %s" % (thisaddy,instruction),thislog)
								
								#if len(cregs) > 0 or len(cregsb) > 0:
								#	if cmp(ocregsb,cregsb) == -1:
								#		dbg.log("    Before: %s" % ocregsb)
								#		dbg.log("    After : %s" % cregsb)
			return


		def procChangeACL(args):
			size = 1
			addy = 0
			acl = ""
			addyerror = False
			aclerror = False
			if "a" in args:
				if type(args["a"]).__name__.lower() != "bool":
					addy,addyok = getAddyArg(args["a"])
					if not addyok:
						addyerror = True
			if "acl" in args:
				if type(args["acl"]).__name__.lower() != "bool":
					if args["acl"].upper() in memProtConstants:
						acl = args["acl"].upper()
					else:
						aclerror = True
			else:
				aclerror = True	
			
			if addyerror:
				dbg.log(" *** Please specify a valid address to argument -a ***")

			if aclerror:
				dbg.log(" *** Please specify a valid memory protection constant with -acl ***")
				dbg.log(" *** Valid values are :")
				for acltype in memProtConstants:
					dbg.log("     %s (%s = 0x%02x)" % (toSize(acltype,10),memProtConstants[acltype][0],memProtConstants[acltype][1]))

			if not addyerror and not aclerror:
				pageacl = memProtConstants[acl][1]
				pageaclname = memProtConstants[acl][0]
				dbg.log("[+] Current ACL: %s" % getPointerAccess(addy))
				dbg.log("[+] Desired ACL: %s (0x%02x)" % (pageaclname,pageacl))
				retval = dbg.rVirtualAlloc(addy,1,0x1000,pageacl)
			return


		def procToBp(args):
			"""
			Generate WinDBG syntax to create a logging breakpoint on a given location
			"""
			addy = 0
			addyerror = False
			executenow = False
			locsyntax = ""
			regsyntax = ""
			poisyntax = ""
			dmpsyntax = ""
			instructionparts = []
			global silent
			oldsilent = silent
			regs = dbg.getRegs()
			silent = True
			if "a" in args:
				if type(args["a"]).__name__.lower() != "bool":
					addy,addyok = getAddyArg(args["a"])
					if not addyok:
						addyerror = True
			else:
				addy = regs["EIP"]

			if "e" in args:
				executenow = True

			if addyerror:
				dbg.log(" *** Please provide a valid address with argument -a ***",highlight=1)
				return

			# get RVA for addy (or absolute address if addy is not part of a module)
			bpdest = "0x%08x" % addy
			instruction = ""
			ptrx = MnPointer(addy)
			modname = ptrx.belongsTo()
			if not modname == "":
				mod = MnModule(modname)
				m = mod.moduleBase
				rva = addy - m
				bpdest = "%s+0x%02x" % (modname,rva)
				thisopcode = dbg.disasm(addy)
				instruction = getDisasmInstruction(thisopcode)

			locsyntax = "bp %s" % bpdest

			instructionparts = multiSplit(instruction,[" ",","])

			usedregs = []
			
			for reg in regs:
				for ipart in instructionparts:
					if reg.upper() in ipart.upper():
						usedregs.append(reg)

			if len(usedregs) > 0:
				regsyntax = '.printf \\"'
				argsyntax = ""
				
				for ipart in instructionparts:
					for reg in regs:
						if reg.upper() in ipart.upper():

							if "[" in ipart:
								regsyntax += ipart.replace("[","").replace("]","")
								regsyntax += ": 0x%08x, "

								argsyntax += "%s," % ipart.replace("[","").replace("]","")

								regsyntax += ipart
								regsyntax += ": 0x%08x, "								

								argsyntax += "%s," % ipart.replace("[","poi(").replace("]",")")
								
								iparttxt = ipart.replace("[","").replace("]","")
								dmpsyntax += ".echo;.echo %s:;dds %s L 0x24/4;" % (iparttxt,iparttxt)
							else:
								regsyntax += ipart
								regsyntax += ": 0x%08x, "								
								argsyntax += "%s," % ipart 
				argsyntax = argsyntax.strip(",")
				regsyntax = regsyntax.strip(", ")
				regsyntax += '\\",%s;' % argsyntax

			if "CALL" in instruction.upper():
				dmpsyntax += '.echo;.printf \\"Stack (esp: 0x%08x):\\",esp;.echo;dds esp L 0x4;'

			if instruction.upper().startswith("RET"):
				dmpsyntax += '.echo;.printf \\"EAX: 0x%08x, Ret To: 0x%08x, Arg1: 0x%08x, Arg2: 0x%08x, Arg3: 0x%08x, Arg4: 0x%08x\\",eax,poi(esp),poi(esp+4),poi(esp+8),poi(esp+c),poi(esp+10);'

			bpsyntax = locsyntax + ' ".echo ---------------;u eip L 1;' + regsyntax + dmpsyntax + ".echo;g" + '"'
			filename = "logbps.txt"
			logfile = MnLog(filename)
			thislog = logfile.reset(False,False)
			with open(thislog, "a") as fh:
				fh.write(bpsyntax + "\n")
			silent = oldsilent
			dbg.log("%s" % bpsyntax)
			dbg.log("Updated %s" % thislog)
			if executenow:
				dbg.nativeCommand(bpsyntax)
				dbg.log("> Breakpoint set at 0x%08x" % addy)
			return


		def procAllocMem(args):
			size = 0x1000
			addy = 0
			sizeerror = False
			addyerror = False
			byteerror = False
			fillup = False
			writemore = False
			fillbyte = "A"
			acl = "RWX"

			if "s" in args:
				if type(args["s"]).__name__.lower() != "bool":
					sval = args["s"]
					if sval.lower().startswith("0x"):
						try:
							size = int(sval,16)
						except:
							sizeerror = True
					else:
						try:
							size = int(sval)
						except:
							sizeerror = True
				else:
					sizeerror = True

			if "b" in args:
				if type(args["b"]).__name__.lower() != "bool":
					try:
						fillbyte = hex2bin(args["b"])[0]
					except:
						dbg.log(" *** Invalid byte specified with -b ***")
						byteerror = True

			if size < 0x1:
				sizeerror = True
				dbg.log(" *** Minimum size is 0x1 bytes ***",highlight=1)

			if "a" in args:
				if type(args["a"]).__name__.lower() != "bool":
					addy,addyok = getAddyArg(args["a"])
					if not addyok:
						addyerror = True

			if "fill" in args:
				fillup = True
				if "force" in args:
					writemore = True

			aclerror = False
			if "acl" in args:
				if type(args["acl"]).__name__.lower() != "bool":
					if args["acl"].upper() in memProtConstants:
						acl = args["acl"].upper()
					else:
						aclerror = True
						dbg.log(" *** Please specify a valid memory protection constant with -acl ***")
						dbg.log(" *** Valid values are :")
						for acltype in memProtConstants:
							dbg.log("     %s (%s = 0x%02x)" % (toSize(acltype,10),memProtConstants[acltype][0],memProtConstants[acltype][1]))

			if addyerror:
				dbg.log(" *** Please specify a valid address with -a ***",highlight=1)

			if sizeerror:
				dbg.log(" *** Please specify a valid size with -s ***",highlight = 1)
			
			if not addyerror and not sizeerror and not byteerror and not aclerror:
				dbg.log("[+] Requested allocation size: 0x%08x (%d) bytes" % (size,size))
				if addy > 0:
					dbg.log("[+] Desired target location : 0x%08x" % addy)
				pageacl = memProtConstants[acl][1]
				pageaclname = memProtConstants[acl][0]
				if addy > 0:
					dbg.log("    Current page ACL: %s" % getPointerAccess(addy))
				dbg.log("    Desired page ACL: %s (0x%02x)" % (pageaclname,pageacl))
				VIRTUAL_MEM = ( 0x1000 | 0x2000 )
				allocat = dbg.rVirtualAlloc(addy,size,0x1000,pageacl)
				if addy == 0 and allocat > 0:
					retval = dbg.rVirtualProtect(allocat,1,pageacl)
				else:
					retval = dbg.rVirtualProtect(addy,1,pageacl)
				
				dbg.log("[+] Allocated memory at 0x%08x" % allocat)
				#if allocat > 0:
				#	dbg.log("    ACL 0x%08x: %s" % (allocat,getPointerAccess(allocat)))
				#else:
				#	dbg.log("    ACL 0x%08x: %s" % (addy,getPointerAccess(addy)))

				if allocat == 0 and fillup and not writemore:
					dbg.log("[+] It looks like the page was already mapped. Use the -force argument")
					dbg.log("    to make me write to 0x%08x anyway" % addy)
				if (allocat > 0 and fillup) or (writemore and fillup):
					loc = 0
					written = 0
					towrite = size
					while loc < towrite:
						try:
							dbg.writeMemory(addy+loc,fillbyte)
							written += 1
						except:
							pass
						loc += 1
					dbg.log("[+] Wrote %d times \\x%s to chunk at 0x%08x" % (written,bin2hex(fillbyte),addy))
			return


		def procHideDebug(args):
			peb = dbg.getPEBAddress()			
			dbg.log("[+] Patching PEB (0x%08x)" % peb)
			if peb == 0:
				dbg.log("** Unable to find PEB **")
				return

			isdebugged = struct.unpack('<B',dbg.readMemory(peb + 0x02,1))[0]
			processheapflag = dbg.readLong(peb + 0x18)
			processheapflag += 0x10
			processheapvalue = dbg.readLong(processheapflag)
			ntglobalflag = dbg.readLong(peb + 0x68)

			dbg.log("    Patching PEB.IsDebugged       : 0x%x -> 0x%x" % (isdebugged,0))
			dbg.writeMemory(peb + 0x02, '\x00')
			
			dbg.log("    Patching PEB.ProcessHeap.Flag : 0x%x -> 0x%x" % (processheapvalue,0))
			dbg.writeLong(processheapflag,0)
			
			dbg.log("    Patching PEB.NtGlobalFlag     : 0x%x -> 0x%x" % (ntglobalflag,0))
			dbg.writeLong(peb + 0x68, 0)
			
			dbg.log("    Patching PEB.LDR_DATA Fill pattern")
			a = dbg.readLong(peb + 0xc)
			while a != 0:
				a += 1
				try:
					b = dbg.readLong(a)
					c = dbg.readLong(a + 4)
					if (b == 0xFEEEFEEE) and (c == 0xFEEEFEEE):
						dbg.writeLong(a,0)
						dbg.writeLong(a + 4,0)
						a += 7
				except:
					break

			uef = dbg.getAddress("kernel32.UnhandledExceptionFilter")
			if uef > 0:
				dbg.log("[+] Patching kernel32.UnhandledExceptionFilter (0x%08x)" % uef)
				uef += 0x86
				dbg.writeMemory(uef, dbg.assemble(" \
					PUSH EDI \
				"))
			else:
				dbg.log("[-] Failed to hook kernel32.UnhandledExceptionFilter (0x%08x)")

			remdebpres = dbg.getAddress("kernel32.CheckRemoteDebuggerPresent")
			if remdebpres > 0:
				dbg.log("[+] Patching CheckRemoteDebuggerPresent (0x%08x)" % remdebpres)
				dbg.writeMemory( remdebpres, dbg.assemble( " \
					MOV   EDI, EDI                                    \n \
					PUSH EBP                                         \n \
					MOV  EBP, ESP                                    \n \
					MOV   EAX, [EBP + C]                              \n \
					PUSH  0                                           \n \
					POP   [EAX]                                       \n \
					XOR   EAX, EAX                                    \n \
					POP   EBP                                         \n \
					RET   8                                           \
				" ) )
			else:
				dbg.log("[-] Unable to patch CheckRemoteDebuggerPresent")

			gtc = dbg.getAddress("kernel32.GetTickCount")
			if gtc > 0:
				dbg.log("[+] Patching GetTickCount (0x%08x)" % gtc)
				patch = dbg.assemble("MOV EDX, 0x7FFE0000") + Poly_ReturnDW(0x0BADF00D) + dbg.assemble("Ret")
				while len(patch) > 0x0F:
					patch = dbg.assemble("MOV EDX, 0x7FFE0000") + Poly_ReturnDW(0x0BADF00D) + dbg.assemble("Ret")
				dbg.writeMemory( gtc, patch )
			else:
				dbg.log("[-] Unable to pach GetTickCount")

			zwq = dbg.getAddress("ntdll.ZwQuerySystemInformation")
			if zwq > 0:
				dbg.log("[+] Patching ZwQuerySystemInformation (0x%08x)" % zwq)
				isPatched = False
				a = 0
				s = 0
				while a < 3:
					a += 1
					s += dbg.disasmSizeOnly(zwq + s).opsize
				FakeCode = dbg.readMemory(zwq, 1) + "\x78\x56\x34\x12" + dbg.readMemory(zwq + 5, 1)
				if FakeCode == dbg.assemble("PUSH 0x12345678\nRET"):
					isPatched = True
					a = dbg.readLong(zwq+1)
					i = 0
					s = 0
					while i < 3:
						i += 1
						s += dbg.disasmSizeOnly(a+s).opsize

				if isPatched:
					dbg.log("    Function was already patched.")
				else:
					a = dbg.remoteVirtualAlloc(size=0x1000)
					if a > 0:
						dbg.log("    Writing instructions to 0x%08x" % a)
						dbg.writeMemory(a, dbg.readMemory(zwq,s))
						pushCode = dbg.assemble("PUSH 0x%08x" % (zwq + s))
						patchCode = "\x83\x7c\x24\x08\x07"	# CMP [ESP+8],7
						patchCode += "\x74\x06"	
						patchCode += pushCode
						patchCode += "\xC3"					# RETN
						patchCode += "\x8B\x44\x24\x0c"		# MOV EAX,[ESP+0x0c]
						patchCode += "\x6a\x00"				# PUSH 0
						patchCode += "\x8f\x00"				# POP [EAX]
						patchCode += "\x33\xC0"				# XOR EAX,EAX
						patchCode += "\xC2\x14\x00"			# RETN 14
						dbg.writeMemory( a + s, patchCode)
						# redirect function
						dbg.writeMemory( zwq, dbg.assemble( "PUSH 0x%08X\nRET" % a) )

					else:
						dbg.log("    ** Unable to allocate memory in target process **")

			else:
				dbg.log("[-] Unable to patch ZwQuerySystemInformation")

			return			


		# ----- Finally, some main stuff ----- #
		
		# All available commands and their Usage :
		
		sehUsage = """Default module criteria : non safeseh, non aslr, non rebase
This function will retrieve all stackpivot pointers that will bring you back to nseh in a seh overwrite exploit
Optional argument: 
    -all : also search outside of loaded modules"""
	
		configUsage = """Change config of mona.py
Available options are : -get <parameter>, -set <parameter> <value> or -add <parameter> <value_to_add>
Valid parameters are : workingfolder, excluded_modules, author"""
	
		jmpUsage = """Default module criteria : non aslr, non rebase 
Mandatory argument :  -r <reg>  where reg is a valid register"""
	
		ropfuncUsage = """Default module criteria : non aslr, non rebase, non os
Output will be written to ropfunc.txt"""
	
		modulesUsage = """Shows information about the loaded modules"""
		
		ropUsage="""Default module criteria : non aslr,non rebase,non os
Optional parameters : 
    -offset <value> : define the maximum offset for RET instructions (integer, default : 40)
    -distance <value> : define the minimum distance for stackpivots (integer, default : 8).
                        If you want to specify a min and max distance, set the value to min,max
    -depth <value> : define the maximum nr of instructions (not ending instruction) in each gadget (integer, default : 6)
    -split : write gadgets to individual files, grouped by the module the gadget belongs to
    -fast : skip the 'non-interesting' gadgets
    -end <instruction(s)> : specify one or more instructions that will be used as chain end. 
                               (Separate instructions with #). Default ending is RETN
    -f \"file1,file2,..filen\" : use mona generated rop files as input instead of searching in memory
    -rva : use RVA's in rop chain
    -s <technique> : only create a ROP chain for the selected technique (options: virtualalloc, virtualprotect)    
    -sort : sort the output in rop.txt (sort on pointer value)"""
	
		jopUsage="""Default module criteria : non aslr,non rebase,non os
Optional parameters : 
    -depth <value> : define the maximum nr of instructions (not ending instruction) in each gadget (integer, default : 8)"""	
							   
							   
		stackpivotUsage="""Default module criteria : non aslr,non rebase,non os
Optional parameters : 
    -offset <value> : define the maximum offset for RET instructions (integer, default : 40)
    -distance <value> : define the minimum distance for stackpivots (integer, default : 8)
                        If you want to specify a min and max distance, set the value to min,max
    -depth <value> : define the maximum nr of instructions (not ending instruction) in each gadget (integer, default : 6)"""							   
							   
		filecompareUsage="""Compares 2 or more files created by mona using the same output commands
Make sure to use files that are created with the same version of mona and 
contain the output of the same mona command.
Mandatory argument : -f \"file1,file2,...filen\"
Put all filenames between one set of double quotes, and separate files with comma's.
You can specify a foldername as well with -f, all files in the root of that folder will be part of the compare.
Output will be written to filecompare.txt and filecompare_not.txt (not matching pointers)
Optional parameters : 
    -contains \"INSTRUCTION\"  (will only list if instruction is found)
    -nostrict (will also list pointer is instructions don't match in all files)
    -range <number> : find overlapping ranges for all pointers + range. 
                      When using -range, the -contains and -nostrict options will be ignored
    -ptronly : only show matching pointers (slightly faster). Doesn't work when 'range' is used"""

		patcreateUsage="""Create a cyclic pattern of a given size. Output will be written to pattern.txt
in ascii, hex and unescape() javascript format
Mandatory argument : size (numberic value)
Optional arguments :
    -extended : extend the 3rd characterset (numbers) with punctuation marks etc
    -c1 <chars> : set the first charset to this string of characters
    -c2 <chars> : set the second charset to this string of characters
    -c3 <chars> : set the third charset to this string of characters"""
	
		patoffsetUsage="""Find the location of 4 bytes in a cyclic pattern
Mandatory argument : the 4 bytes to look for
Note :  you can also specify a register
Optional arguments :
    -extended : extend the 3rd characterset (numbers) with punctuation marks etc
    -c1 <chars> : set the first charset to this string of characters
    -c2 <chars> : set the second charset to this string of characters
    -c3 <chars> : set the third charset to this string of characters
Note : the charset must match the charset that was used to create the pattern !
"""

		findwildUsage = """Find instructions in memory, accepts wildcards :
Mandatory arguments :
        -s <instruction#instruction#instruction>  (separate instructions with #)
Optional arguments :
        -b <address> : base/bottom address of the search range
        -t <address> : top address of the search range
        -depth <nr>  : number of instructions to go deep
        -all : show all instruction chains, even if it contains something that might break the chain	
        -distance min=nr,max=nr : you can use a numeric offset wildcard (a single *) in the first instruction of the search
        the distance parameter allows you to specify the range of the offset		
Inside the instructions string, you can use the following wildcards :
        * = any instruction
        r32 = any register
Example : pop r32#*#xor eax,eax#*#pop esi#ret
        """


		findUsage= """Find a sequence of bytes in memory.
Mandatory argument : -s <pattern> : the sequence to search for. If you specified type 'file', then use -s to specify the file.
This file needs to be a file created with mona.py, containing pointers at the begin of each line.
Optional arguments:
    -type <type>    : Type of pattern to search for : bin,asc,ptr,instr,file
    -b <address> : base/bottom address of the search range
    -t <address> : top address of the search range
    -c : skip consecutive pointers but show length of the pattern instead
    -p2p : show pointers to pointers to the pattern (might take a while !)
           this setting equals setting -level to 1
    -level <number> : do recursive (p2p) searches, specify number of levels deep
                      if you want to look for pointers to pointers, set level to 1
    -offset <number> : subtract a value from a pointer at a certain level
    -offsetlevel <number> : level to subtract a value from a pointer
    -r <number> : if p2p is used, you can tell the find to also find close pointers by specifying -r with a value.
                  This value indicates the number of bytes to step backwards for each search
    -unicode : used in conjunction with search type asc, this will convert the search pattern to unicode first 
    -ptronly : Only show the pointers, skip showing info about the pointer (slightly faster)"""
	
		assembleUsage = """Convert instructions to opcode. Separate multiple instructions with #.
Mandatory argument : -s <instructions> : the sequence of instructions to assemble to opcode"""
	
		infoUsage = """Show information about a given address in the context of the loaded application
Mandatory argument : -a <address> : the address to query"""

		dumpUsage = """Dump the specified memory range to a file. Either the end address or the size of
buffer needs to be specified.
Mandatory arguments :
    -s <address> : start address
    -f <filename> : the name of the file where to write the bytes
Optional arguments:
    -n <size> : the number of bytes to copy (size of the buffer)
    -e <address> : the end address of the copy"""
	
# 		compareUsage = """Compares contents of a binary file with locations in memory.
# Mandatory argument :
#     -f <filename> : full path to binary file
# Optional argument :
#     -a <address> : the exact address of the bytes in memory (address or register). 
#                    If you don't specify an address, I will try to locate the bytes in memory 
#                    by looking at the first 8 bytes.
#     -s : skip locations that belong to a module
#     -unicode : perform unicode search. Note: input should *not* be unicode, it will be expanded automatically"""


		compareUsage = """Compare a file created by mona's bytearray/msfvenom/gdb/hex/xxd/hexdump/ollydbg with a copy in memory.
Mandatory argument :
    -f <filename> : full path to input file
Optional argument :
    -a <address> : the exact address of the bytes in memory (address or register). 
                   If you don't specify an address, I will try to locate the bytes in memory 
                   by looking at the first 8 bytes.
    -s : skip locations that belong to a module
    -unicode : perform unicode search. Note: input should *not* be unicode, it will be expanded automatically
	-t : input file type format. If no file type format is specified, I will try to guess the input file type format.
		 
		 Available formats:
		'raw', 'hexdump', 'js-unicode', 'dword', 'xxd', 'byte-array', 'hexstring', 'hexdump-C', 'classic-hexdump', 'escaped-hexes', 'msfvenom-powershell', 'gdb', 'ollydbg', 'msfvenom-ruby', 'msfvenom-c', 'msfvenom-carray', 'msfvenom-python'
	"""

		offsetUsage = """Calculate the number of bytes between two addresses. You can use 
registers instead of addresses. 
Mandatory arguments :
    -a1 <address> : the first address/register
    -a2 <address> : the second address/register"""
	
		bpUsage = """Set a breakpoint when a given address is read from, written to or executed
Mandatory arguments :
    -a <address> : the address where to set the breakpoint
                   (absolute address / register / modulename!functionname)
    -t <type> : type of the breakpoint, can be READ, WRITE or SFX"""
	
		bfUsage = """Set a breakpoint on exported or imported function(s) of the selected modules. 
Mandatory argument :
    -t <type> : type of breakpoint action. Can be 'add', 'del' or 'list'
Optional arguments :
    -f <function type> : set to 'import' or 'export' to read IAT or EAT. Default : export
    -s <func,func,func> : specify function names. 
                          If you want a bp on all functions, set -s to *"""	
	
		nosafesehUsage = """Show modules that are not safeseh protected"""
		nosafesehaslrUsage = """Show modules that are not safeseh protected, not subject to ASLR, and won't get rebased either"""
		noaslrUsage = """Show modules that are not subject to ASLR and won't get rebased"""
		findmspUsage = """Finds begin of a cyclic pattern in memory, looks if one of the registers contains (is overwritten) with a cyclic pattern
or points into a cyclic pattern. findmsp will also look if a SEH record is overwritten and finally, 
it will look for cyclic patterns on the stack, and pointers to cyclic pattern on the stack.
Optional argument :
    -distance <value> : distance from ESP, applies to search on the stack. Default : search entire stack
Note : you can use the same options as with pattern_create and pattern_offset in terms of defining the character set to use"""

		suggestUsage = """Suggests an exploit buffer structure based on pointers to a cyclic pattern
Note : you can use the same options as with pattern_create and pattern_offset in terms of defining the character set to use
Mandatory argument in case you are using WinDBG:
    -t <type:arg> : skeletontype. Valid types are :
                tcpclient:port, udpclient:port, fileformat:extension
                Examples : -t tcpclient:21
                           -t fileformat:pdf"""
		
		bytearrayUsage = """Creates a byte array, can be used to find bad characters
Optional arguments :
    -cpb <bytes> : bytes to exclude from the array. Example : '\\x00\\x0a\\x0d'
                   Note: you can specify wildcards using .. 
                   Example: '\\x00\\x0a..\\x20\\x32\\x7f..\\xff'
    -s : optional starting hex, example: '\\x7f'
    -e : optional ending hex, example: '\\xff'
         Example: -s \\x01 -e \\x7f to have all bytes from 0x01 to 0x7f
                  -s \\xff -e \\x7f to have all bytes from 0xff to 0x7f in reverse
    -r : show array backwards (reversed), starting at \\xff
    Output will be written to bytearray.txt, and binary output will be written to bytearray.bin"""
	
		headerUsage = """Convert contents of a binary file to code that can be run to produce the file
Mandatory argument :
    -f <filename> : source filename
Optional argument:
    -t <type>     : specify type of output. Valid choices are 'ruby' (default) or 'python' """
	
		updateUsage = """Update mona to the latest version"""
		getpcUsage = """Find getpc routine for specific register
Mandatory argument :
    -r : register (ex: eax)"""

		eggUsage = """Creates an egghunter routine
Optional arguments :
    -t : tag (ex: w00t). Default value is w00t
    -c : enable checksum routine. Only works in conjunction with parameter -f
    -f <filename> : file containing the shellcode
    -startreg <reg> : start searching at the address pointed by this reg
    -wow64 : generate wow64 egghunter (Win7 and Win10). Default is traditional 32bit egghunter
    -winver <ver> : indicate Windows version for wow64 egghunter. Default is Windows 10. 
                    valid values are 7 and 10.	
DEP Bypass options :
    -depmethod <method> : method can be "virtualprotect", "copy" or "copy_size"
    -depreg <reg> : sets the register that contains a pointer to the API function to bypass DEP. 
                    By default this register is set to ESI
    -depsize <value> : sets the size for the dep bypass routine
    -depdest <reg> : this register points to the location of the egghunter itself.  
                     When bypassing DEP, the egghunter is already marked as executable. 
                     So when using the copy or copy_size methods, the DEP bypass in the egghunter 
                     would do a "copy 2 self".  In order to be able to do so, it needs a register 
                     where it can copy the shellcode to. 
                     If you leave this empty, the code will contain a GetPC routine."""
		
		stacksUsage = """Shows all stacks for each thread in the running application"""
		
		skeletonUsage = """Creates a Metasploit exploit module skeleton for a specific type of exploit
Mandatory argument in case you are using WinDBG:
    -t <type:arg> : skeletontype. Valid types are :
                tcpclient:port, udpclient:port, fileformat:extension
                Examples : -t tcpclient:21
                           -t fileformat:pdf
Optional arguments :
    -s : size of the cyclic pattern (default : 5000)
"""
	
		heapUsage = """Show information about various heap chunk lists
Mandatory arguments :
    -h <address> : base address of the heap to query
    -t <type> : where type is 'segments', 'chunks', 'layout',
                'fea' (let mona determine the frontend allocator),
                'lal' (force display of LAL FEA, only on XP/2003),
                'lfh' (force display of LFH FEA (Vista/Win7/...)),
                'bea' (backend allocator, mona will automatically determine what it is),
                'all' (show all information)
    Note: 'layout' will show all heap chunks and their vtables & strings. Use on WinDBG for maximum results.
Optional arguments :
    -expand : Works only in combination with 'layout', will include VA/LFH/... chunks in the search.
              VA/LFH chunks may be very big, so this might slow down the search.
    -stat : show statistics (also works in combination with -h heap, -t segments or -t chunks
    -size <nr> : only show strings of at least the specified size. Works in combination with 'layout'
    -after <data> : only show current & next chunk layout entries when an entry contains this data
                    (Only works in combination with 'layout')
    -v : show data / write verbose info to the Log window"""
	
		getiatUsage = """Show IAT entries from selected module(s)
Optional arguments :
    -s <keywords> : only show IAT entries that contain one of these keywords"""

		geteatUsage = """Show EAT entries from selected module(s)
Optional arguments :
    -s <keywords> : only show EAT entries that contain one of these keywords"""
	
		deferUsage = """Set a deferred breakpoint
Mandatory arguments :
    -a <target>,<target>,... 
    target can be an address, a modulename.functionname or module.dll+offset (hex value)
    Warning, modulename.functionname is case sensitive !
	""" 
	
		calltraceUsage = """Logs all CALL instructions
Mandatory arguments :
    -m module : specify what module to search for CALL instructions (global option)	
Optional arguments :
    -a <number> : number of arguments to show for each CALL
    -r : also trace RETN instructions (will slow down process!)""" 	

		fillchunkUsage = """Fills a heap chunk, referenced by a register, with A's (or another character)
Mandatory arguments :
    -r <reg/reference> : reference to heap chunk to fill
Optional arguments :
    -b <character or byte to use to fill up chunk>
    -s <size> : if the referenced chunk is not found, and a size is defined with -s,
                memory will be filled anyway, up to the specified size"""

		getpageACLUsage = """List all mapped pages and show the ACL associated with each page
Optional arguments : 
    -a <address> : only show page information around this address.
                   (Page before, current page and page after will be displayed)"""
		
		bpsehUsage = """Sets a breakpoint on all current SEH Handler function pointers"""

		kbUsage = """Manage knowledgebase data
Mandatory arguments:
    -<type> : type can be 'list', 'set' or 'del'
    To 'set' ( = add / update ) a KB entry, or 'del' an entry, 
    you will need to specify 2 additional arguments:
        -id <id> : the Knowledgebase ID
        -value <value> : the value to add/update.  In case of lists, use a comma to separate entries.
    The -list parameter will show all current ID's
    To see the contents of a specific ID, use the -id <id> parameter."""

		macroUsage = """Manage macros for WinDBG
Arguments:
    -run <macroname> : run the commands defined in the specified macro
    -show <macroname> : show all commands defined in the specified macro
    -add <macroname> : create a new macro
    -set <macroname> -index <nr> -cmd <windbg command(s)> : edit a macro
               If you set the -command value to #, the command at the specified index
               will be removed.  If you have specified an existing index, the command 
               at that position will be replaced, unless you've also specified the -insert parameter.
               If you have not specified an index, the command will be appended to he list.
    -set <macroname> -file <filename> : will tell this macro to execute all instructions in the
               specified file. You can only enter one file per macro.
    -del <macroname> -iamsure: remove the specified macro. Use with care, I won't ask if you're sure."""

		sehchainUsage = """Displays the SEH chain for the current thread.
This command will also attempt to display offsets and suggest a payload structure
in case a cyclic pattern was used to overwrite the chain."""

		heapCookieUsage = """Will attempt to find reliable writeable pointers that can help avoiding
a heap cookie check during an arbitrary free on Windows XP"""

		hidedebugUsage = """Will attempt to hide the debugger from the process"""
		gflagsUsage = """Will show the currently set GFlags, based on the PEB.NtGlobalFlag value"""
		fwptrUsage = """Search for calls to pointers in a writeable location, 
will assist with finding a good target for 4byte arbitrary writes
Optional arguments:
    -bp : Set breakpoints on all found CALL instructions
    -patch : Patch the target of each CALL with 0x41414141
    -chunksize <nr> : only list the pointer if location-8 bytes contains a size value larger than <nr>
                      (size in blocks, not bytes)
    -offset <nr> : add <nr> bytes of offset within chunk, after flink/blink pointer 
                  (use in combination with -freelist and -chunksize <nr>)
    -freelist : Search for fwptr that are preceeded by 2 readable pointers that can act as flink/blink"""

		allocmemUsage = """Allocate RWX memory in the debugged process.
Optional arguments:
    -s <size>    : desired size of allocated chunk. VirtualAlloc will allocate at least 0x1000 bytes,
                   but this size argument is only useful when used in combination with -fill.
    -a <address> : desired target location for allocation, set to start of chunk to allocate.
    -acl <level> : overrule default RWX memory protection.
    -fill        : fill 'size' bytes (-s) of memory at specified address (-a) with A's.
    -force       : use in combination with -fill, in case page was already mapped but you still want to
                   fill the chunk at the desired location.
    -b <byte>    : Specify what byte to write to the desired location. Defaults to '\\x41'    
"""  

		changeaclUsage = """Change the ACL of a given page.
Arguments:
    -a <address>   : Address belonging to the page that needs to be changed
    -acl <level>   : New ACL. Valid values are R,RW,RXW,RX,N,GUARD,NOCACHE,WC""" 

		infodumpUsage = """Dumps contents of memory to file. Contents will include all pages that don't
belong to stack, heap or loaded modules.
Output will be written to infodump.xml"""

		pebUsage = """Show the address of the Process Environment Block (PEB)"""

		tebUsage = """Show the address of the Thread Environment Block (TEB) for the current thread"""

		jsehUsage = """(look for jmp/call dword ptr[ebp/esp+nn and ebp-nn] + add esp,8+ret) 
Only addresses outside address range of modules will be listed unless parameter '-all' is given. 
In that case, all addresses will be listed. TRY THIS ONE !"""
		
		
		encUsage = """Encode a series of bytes
Arguments:
    -t <type>         : Type of encoder to use.  Allowed value(s) are alphanum 
    -s <bytes>        : The bytes to encode (or use -f instead)
    -f <path to file> : The full path to the binary file that contains the bytes to encode"""
		
		stringUsage = """Read a string from memory or write a string to memory
Arguments:
    -r                : Read a string, use in combination with -a
    -w                : Write a string, use in combination with -a and -s
    -noterminate      : Do not terminate the string (using in combination with -w)
    -u                : use UTF-16 (Unicode) mode
    -s <string>       : The string to write
    -a <address>      : The location to read from or write to"""

		unicodealignUsage = """Generates a venetian shellcode alignment stub which can be placed directly before unicode shellcode.

Arguments:
    -a <address>      : Specify the address where the alignment code will start/be placed
                      : If -a is not specified, the current value in EIP will be used.
    -l                : Prepend alignment with a null byte compensating nop equivalent
                        (Use this if the last instruction before the alignment routine 'leaks' a null byte)
    -b <reg>          : Set the bufferregister, defaults to eax
    -t <seconds>      : Time in seconds to run heuristics (defaults to 15)
    -ebp <value>      : Overrule the use of the 'current' value of ebp, 
                        ebp/address will be used to calculate offset to shellcode"""

		copyUsage = """Copies bytes from one location to another.

Arguments:
    -src <address>    : The source address
    -dst <address>    : The destination address
    -n <number>       : The number of bytes to copy""" 

		dumpobjUsage = """Dump the contents of an object.

Arguments:
    -a <address>      : Address of object
    -s <number>       : Size of object (default value: 0x28 or size of chunk)
Optional arguments:
    -l <number>       : Recursively dump objects
    -m <number>       : Size for recursive objects (default value: 0x28)
"""

		dumplogUsage = """Dump all objects recorded in an alloc/free log
Note: dumplog will only dump objects that have not been freed in the same logfile.
Expected syntax for log entries:
    Alloc : 'alloc(size in hex) = address'
    Free  : 'free(address)'
Additional text after the alloc & free info is fine.
Just make sure the syntax matches exactly with the examples above.
Arguments:
    -f <path/to/logfile> : Full path to the logfile
Optional arguments:
    -l <number>       : Recursively dump objects
    -m <number>       : Size for recursive objects (default value: 0x28)
    -s <number>       : Only take allocated chunks of this exact size into consideration
    -nofree           : Ignore all free() events, show all allocations (including those that were freed)""" 

		tobpUsage = """Generate WinDBG syntax to set a logging breakpoint at a given location
Arguments:
    -a <address>      : Location (address, register) for logging breakpoint
Optional arguments:
    -e                : Execute breakpoint command right away"""

		flowUsage = """Simulates execution flows from current location (EIP), tries all conditional jump combinations
Optional arguments:
    -e <address>                 : Show execution flows that will reach specified address
    -avoid <address,address,...> : Only show paths that don't contain any of the pointers to avoid
    -n <nr>                      : Max nr of instructions, default: 60
    -cl <nr>                     : Max level of CALL to follow in detail, default: 3
    -cs <nr>                     : Don't show details of first <nr> CALL/child functions. default: 0
    -func                        : Show function names (slows down process)."""

		evalUsage = """Evaluates an expression
Arguments:
    <the expression to evaluate>

Accepted syntax includes: 
    hex values, decimal values (prefixed with 0n), registers, 
    module names, 'heap' ( = address of default process heap),
    module!functionname
    simple math operations"""

		diffheapUsage = """Compare current heap layout with previously saved state
Arguments:
    -save     : save current state to disk 
    -diff     : compare current state with previously saved state""" 


		commands["seh"] 			= MnCommand("seh", "Find pointers to assist with SEH overwrite exploits",sehUsage, procFindSEH)
		commands["config"] 			= MnCommand("config","Manage configuration file (mona.ini)",configUsage,procConfig,"conf")
		commands["jmp"]				= MnCommand("jmp","Find pointers that will allow you to jump to a register",jmpUsage,procFindJMP, "j")
		commands["ropfunc"] 		= MnCommand("ropfunc","Find pointers to pointers (IAT) to interesting functions that can be used in your ROP chain",ropfuncUsage,procFindROPFUNC)
		commands["rop"] 			= MnCommand("rop","Finds gadgets that can be used in a ROP exploit and do ROP magic with them",ropUsage,procROP)
		commands["jop"] 			= MnCommand("jop","Finds gadgets that can be used in a JOP exploit",jopUsage,procJOP)		
		commands["jseh"]			= MnCommand("jseh", "Finds gadgets that can be used to bypass SafeSEH", jsehUsage, procJseh)
		commands["stackpivot"]		= MnCommand("stackpivot","Finds stackpivots (move stackpointer to controlled area)",stackpivotUsage,procStackPivots)
		commands["modules"] 		= MnCommand("modules","Show all loaded modules and their properties",modulesUsage,procShowMODULES,"mod")
		commands["filecompare"]		= MnCommand("filecompare","Compares 2 or more files created by mona using the same output commands",filecompareUsage,procFileCOMPARE,"fc")
		commands["pattern_create"]	= MnCommand("pattern_create","Create a cyclic pattern of a given size",patcreateUsage,procCreatePATTERN,"pc")
		commands["pattern_offset"]	= MnCommand("pattern_offset","Find location of 4 bytes in a cyclic pattern",patoffsetUsage,procOffsetPATTERN,"po")
		commands["find"] 			= MnCommand("find", "Find bytes in memory", findUsage, procFind,"f")
		commands["findwild"]		= MnCommand("findwild", "Find instructions in memory, accepts wildcards", findwildUsage, procFindWild,"fw")
		commands["assemble"] 		= MnCommand("assemble", "Convert instructions to opcode. Separate multiple instructions with #",assembleUsage,procAssemble,"asm")
		commands["info"] 			= MnCommand("info", "Show information about a given address in the context of the loaded application",infoUsage,procInfo)
		commands["dump"] 			= MnCommand("dump", "Dump the specified range of memory to a file", dumpUsage,procDump)
		commands["offset"]          = MnCommand("offset", "Calculate the number of bytes between two addresses", offsetUsage, procOffset)		
		#commands["compare"]			= MnCommand("compare","Compare contents of a binary file with a copy in memory", compareUsage, procCompare,"cmp")
		commands["compare"]			= MnCommand("compare","Compare a file created by msfvenom/gdb/hex/xxd/hexdump/ollydbg with a copy in memory", compareUsage, procCompare,"cmp")
		commands["breakpoint"]		= MnCommand("bp","Set a memory breakpoint on read/write or execute of a given address", bpUsage, procBp,"bp")
		commands["nosafeseh"]		= MnCommand("nosafeseh", "Show modules that are not safeseh protected", nosafesehUsage, procModInfoS)
		commands["nosafesehaslr"]	= MnCommand("nosafesehaslr", "Show modules that are not safeseh protected, not aslr and not rebased", nosafesehaslrUsage, procModInfoSA)		
		commands["noaslr"]			= MnCommand("noaslr", "Show modules that are not aslr or rebased", noaslrUsage, procModInfoA)
		commands["findmsp"]			= MnCommand("findmsp","Find cyclic pattern in memory", findmspUsage,procFindMSP,"findmsf")
		commands["suggest"]			= MnCommand("suggest","Suggest an exploit buffer structure", suggestUsage,procSuggest)
		commands["bytearray"]		= MnCommand("bytearray","Creates a byte array, can be used to find bad characters",bytearrayUsage,procByteArray,"ba")
		commands["header"]			= MnCommand("header","Read a binary file and convert content to a nice 'header' string",headerUsage,procPrintHeader)
		commands["update"]			= MnCommand("update","Update mona to the latest version",updateUsage,procUpdate,"up")
		commands["getpc"]			= MnCommand("getpc","Show getpc routines for specific registers",getpcUsage,procgetPC)	
		commands["egghunter"]		= MnCommand("egghunter","Create egghunter code",eggUsage,procEgg,"egg")
		commands["stacks"]			= MnCommand("stacks","Show all stacks for all threads in the running application",stacksUsage,procStacks)
		commands["skeleton"]		= MnCommand("skeleton","Create a Metasploit module skeleton with a cyclic pattern for a given type of exploit",skeletonUsage,procSkeleton)
		commands["breakfunc"]		= MnCommand("breakfunc","Set a breakpoint on an exported function in on or more dll's",bfUsage,procBf,"bf")
		commands["heap"]			= MnCommand("heap","Show heap related information",heapUsage,procHeap)
		commands["getiat"]			= MnCommand("getiat","Show IAT of selected module(s)",getiatUsage,procGetIAT,"iat")
		commands["geteat"]          = MnCommand("geteat","Show EAT of selected module(s)",geteatUsage,procGetEAT,"eat")
		commands["pageacl"]         = MnCommand("pageacl","Show ACL associated with mapped pages",getpageACLUsage,procPageACL,"pacl")
		commands["bpseh"]           = MnCommand("bpseh","Set a breakpoint on all current SEH Handler function pointers",bpsehUsage,procBPSeh,"sehbp")
		commands["kb"]				= MnCommand("kb","Manage Knowledgebase data",kbUsage,procKb,"kb")
		commands["encode"]			= MnCommand("encode","Encode a series of bytes",encUsage,procEnc,"enc")
		commands["unicodealign"]	= MnCommand("unicodealign","Generate venetian alignment code for unicode stack buffer overflow",unicodealignUsage,procUnicodeAlign,"ua")
		#commands["heapcookie"]      = MnCommand("heapcookie","Looks for writeable pointers that can help avoiding cookie check during arbitrary free",heapCookieUsage,procHeapCookie,"hc")
		if __DEBUGGERAPP__ == "Immunity Debugger":
			commands["deferbp"]		= MnCommand("deferbp","Set a deferred breakpoint",deferUsage,procBu,"bu")
			commands["calltrace"]	= MnCommand("calltrace","Log all CALL instructions",calltraceUsage,procCallTrace,"ct")
		if __DEBUGGERAPP__ == "WinDBG":
			commands["fillchunk"]	= MnCommand("fillchunk","Fill a heap chunk referenced by a register",fillchunkUsage,procFillChunk,"fchunk")
			commands["dumpobj"]		= MnCommand("dumpobj","Dump the contents of an object",dumpobjUsage,procDumpObj,"do")
			commands["dumplog"]     = MnCommand("dumplog","Dump objects present in alloc/free log file",dumplogUsage,procDumpLog,"dl")
			commands["changeacl"]   = MnCommand("changeacl","Change the ACL of a given page",changeaclUsage,procChangeACL,"ca")
			commands["allocmem"]	= MnCommand("allocmem","Allocate some memory in the process",allocmemUsage,procAllocMem,"alloc")
			commands["tobp"]		= MnCommand("tobp","Generate WinDBG syntax to create a logging breakpoint at given location",tobpUsage,procToBp,"2bp")
			commands["flow"]		= MnCommand("flow","Simulate execution flows, including all branch combinations",flowUsage,procFlow,"flw")
			#commands["diffheap"]	= MnCommand("diffheap", "Compare current heap layout with previously saved state", diffheapUsage, procDiffHeap, "dh")
		commands["fwptr"]			= MnCommand("fwptr", "Find Writeable Pointers that get called", fwptrUsage, procFwptr, "fwp")
		commands["sehchain"]		= MnCommand("sehchain","Show the current SEH chain",sehchainUsage,procSehChain,"exchain")
		commands["hidedebug"]		= MnCommand("hidedebug","Attempt to hide the debugger",hidedebugUsage,procHideDebug,"hd")
		commands["gflags"]			= MnCommand("gflags", "Show current GFlags settings from PEB.NtGlobalFlag", gflagsUsage, procFlags, "gf")
		commands["infodump"]		= MnCommand("infodump","Dumps specific parts of memory to file", infodumpUsage, procInfoDump,"if")
		commands["peb"]				= MnCommand("peb","Show location of the PEB",pebUsage,procPEB,"peb")
		commands["teb"]				= MnCommand("teb","Show TEB related information",tebUsage,procTEB,"teb")
		commands["string"]			= MnCommand("string","Read or write a string from/to memory",stringUsage,procString,"str")
		commands["copy"]			= MnCommand("copy","Copy bytes from one location to another",copyUsage,procCopy,"cp")
		commands["?"]				= MnCommand("?","Evaluate an expression",evalUsage,procEval,"eval")
		# get the options
		opts = {}
		last = ""
		arguments = []
		argcopy = copy.copy(args)

		aline = " ".join(a for a in argcopy)
		if __DEBUGGERAPP__ == "WinDBG":
			aline = "!py " + aline
		else:
			aline = "!mona " + aline
		dbg.log("[+] Command used:")
		dbg.log("%s" % aline)	


		# in case we're not using Immunity
		if "-showargs" in args:
			dbg.log("-" * 50)
			dbg.log("args: %s" % args)

		if len(args) > 0:
			if args[0].lower().startswith("mona") or args[0].lower().endswith("mona") or args[0].lower().endswith("mona.py"):
				args.pop(0)
		
		if len(args) >= 2:
			arguments = args[1:]
		if "-showargs" in args:
			dbg.log("arguments: %s" % arguments)

		
		for word in arguments:
			if (word[0] == '-'):
				word = word.lstrip("-")
				opts[word] = True
				last = word
			else:
				if (last != ""):
					if str(opts[last]) == "True":
						opts[last] = word
					else:
						opts[last] = opts[last] + " " + word
					#last = ""
		# if a command only requires a value and not a switch ?
		# then we'll drop the value into dictionary with key "?"
		if len(args) > 1 and args[1][0] != "-":
			opts["?"] = args[1]
	
		
		if len(args) < 1:
			commands["help"].parseProc(opts)
			return("")
		
		command = args[0]
		if "-showargs" in args:
			dbg.log("command: %s" % command)
			dbg.log("-" * 50)
			args.remove("-showargs")
			arguments.remove("-showargs")			
		
		# ----- execute the chosen command ----- #
		if command in commands:
			if command.lower().strip() == "help":
				commands[command].parseProc(args)
			else:
				commands[command].parseProc(opts)
		
		else:
			# maybe it's an alias
			aliasfound = False
			for cmd in commands:
				if commands[cmd].alias == command:
					commands[cmd].parseProc(opts)
					aliasfound = True
			if not aliasfound:
				commands["help"].parseProc(None)
				return("** Invalid command **")
		
		# ----- report ----- #
		endtime = datetime.datetime.now()
		delta = endtime - starttime
		dbg.log("")
		dbg.log("[+] This mona.py action took %s" % str(delta))	
		dbg.setStatusBar("Done")
				
	except:
		dbg.log("*" * 80,highlight=True)
		dbg.logLines(traceback.format_exc(),highlight=True)
		dbg.log("*" * 80,highlight=True)
		dbg.error(traceback.format_exc())
	
	return ""

if __name__ == "__main__":
	dbg.log("Hold on...")
	# do we need to profile ?
	doprofile = False
	if "-profile" in sys.argv:
		doprofile = True
		dbg.log("Starting profiler...")
		cProfile.run('main(sys.argv)', 'monaprofile')
	else:
		main(sys.argv)
	if doprofile:
		dbg.log("[+] Showing profile stats...")
		p = pstats.Stats('monaprofile')	
		dbg.log(" ***** ALL *****")
		p.print_stats()		
		dbg.log(" ***** CUMULATIVE *****")
		p.sort_stats('cumulative').print_stats(30)
		dbg.log(" ***** TIME *****")
		p.sort_stats('time', 'cum').print_stats(30)
	# clear memory
	if __DEBUGGERAPP__ == "WinDBG":
		dbglib.clearvars()
	try:
	#	allvars = [var for var in globals() if var[0] != "_"]
	#	for var in allvars:
	#		del globals()[var]
		resetGlobals()
		dbg = None
	except:
		pass
