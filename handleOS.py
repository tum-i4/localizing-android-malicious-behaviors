#!/usr/bin/python

import os
import subprocess
import csv
import shutil

def execute(command):
	"""
	Execute a shell command and return the results
	:param command: the shell command that should be executed
	:type command: string
	:return: results of the execution of the command
	:rtype: string
	:example:

	handleOS.execute('apyori-run -s 0.5 -c 0.5 < '../data/prob_0.1/assocData_50_-150.tsv'')
	"""
	proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
	(out, err) = proc.communicate()
	return out

def writeFile(filename, data):
	# write data to location specified by 'filename'
	with open(filename, 'w') as f:
		f.write(data)
	f.close
	print 'Data was written to file '+str(filename)

def readFile(filename):
	# read data from file defined by 'filename'
	with open(filename, 'r') as f:
		data = f.read()
	f.close
	return data

def exists(newPath):
	# returns True if the folder at 'newPath' exists, otherwise it returns False
	if os.path.exists(newPath):
		return True
	else:
		return False

def createOutputFolder(newPath):
	# creates a folder at the location specified by 'newPath' if it does not exists yet
	if not exists(newPath):
		os.makedirs(newPath)

def copyFileToNewDirectory(filename, newFolder):
	# copies a file to a new directory defined by the parameter 'newFolder'
	shutil.copy2(filename, newFolder)

def deleteAllFilesInFolder(path):
	# delete all files that are found in the folder specified by the parameter 'path'
	for filename in os.listdir(path):
    		os.remove(os.path.join(path, filename))

def getAllFilesInFolder(path):
	# return all files that are stored in the folder 'path'
	return [filename for filename in os.listdir(path)]

def getFilenamesWithPrefix(path, prefix):
	# get all files from the folder defined by 'path' that start with 'prefix'
    	prefixed = [filename for filename in os.listdir(path) if filename.startswith(prefix)]
    	return prefixed

def writeCSVFile(filename, data):
	# write data to .csv file
	with open(filename, 'w') as f:
		for i in range(len(data)):
			f.write(data[i]+'\n')
	f.close
	print 'Data was written to csv file '+str(filename)
		
def writeNumberOfFiles(filepath, number, length, isBenignData):
	# depending on the kind of data the name is chosen	
	kind = ''
	if isBenignData:
		kind = 'benign'
	else:
		kind = 'malicious'
	# write number of files with the length specified by the parameter 'length' to the file
	with open(filepath, 'a') as f:
		line = kind+': at length '+str(length)+' number of files is '+str(number)+'\n'
		f.write(line)
	f.close

def readCSVFile(path):
	# read data from a .csv file and convert the content into an array
	data = []
	with open(path, 'r') as f:
		reader = csv.reader(f)
		for line in reader:
			array = []
			splittedLine = line[0].split(';')
			for i in range(len(splittedLine)):
				array.append(splittedLine[i])
			data.append(array)
	f.close
	return data

