#!/usr/bin/python

import json
import os
import uuid

def getData(filepath):
	# load data from json file
    	with open(filepath) as dataFile:
        	data = json.load(dataFile)
    	dataFile.close
    	return data

def write(path, newData):
	# write data to json file
    	with open(path, 'w') as f:
        	json.dump(newData, f)
    	f.close
    	print 'Data was written to file '+str(path)

def writeToGeneratedFile(path, newData):
	# generate unique name for the new file before writing to it
    	filename = str(uuid.uuid4())+'.json'
    	with open(path+filename, 'w') as f:
        	json.dump(newData, f)
    	f.close
    	return filename

def allFilesInFolder(path):
    	data = []
    	fileNames = []
	# load data from each file in the folder specified by the parameter 'path'
    	for filename in os.listdir(path):
        	fileData = getData(path+filename)
        	data.append(fileData)
		fileNames.append(path+filename)
    	return data, fileNames

def getAmountOfFilesInFolder(path, beginPosition, amount):
    	data = []
    	fileNames = []
	# load data from an amount of files in the folder specified by the parameter 'path'
    	for filename in os.listdir(path)[beginPosition:beginPosition+amount]:
        	fileData = getData(path+filename)
        	data.append(fileData)
		fileNames.append(path+filename)
    	return data, fileNames

def getNumberOfFilesInFolder(path):
    	number = len(os.listdir(path))
    	return number

def getAllMethods(data):
	"""
	Extract the method names from the traces
	:param data: API traces that include the parameters id, group, class, arguments, return value and the method name
	:type data: dictionary
	:return: the methods included in the input traces
	:rtype: list
	"""
    	elements = []
    	for i in range(len(data['calls'])):
        	elem = data['calls'][i]['method']
        	elements.append(elem)
    	return elements

