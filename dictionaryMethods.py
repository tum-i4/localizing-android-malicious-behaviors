#!/usr/bin/python

import handleJsonFile as jsonf
import ast

def getMethodDictionary(path):
	"""
	Load the dictionary, which is located at 'path'
	:param path: path to the location of the dictionary
	:type path: string
	:return: dictionary containing the method names of API traces
	:rtype: list
	"""
	dictionary = jsonf.getData(path)
	return dictionary

def convertToMethodNames(numbers, pathToDictionary):
	"""
	Convert the numbers to the corresponding method names using the dictionary
	:param numbers: list of numbers, which will be converted to their method names in this function
	:param pathToDictionary: path to the location of the dictionary
	:type numbers: list
	:type pathToDictionary: string
	:return: list of method names
	:rtype: list
	"""
	array = ast.literal_eval(numbers)	
	names = []
	dictionary = getMethodDictionary(pathToDictionary)
	# for each number look up the method name in the dictionary
	for i in range(len(array)):
		current = getKeyByValue(array[i], dictionary)
		names.append(str(current))
	return names

def getKeyByValue(number, dictionary):
	return dictionary.keys()[dictionary.values().index(int(number))]

def updateNumericDictionaryOfMethods(pathToNewTraces, pathToDictionary):
	"""
	Update the dictionary with the method names of API calls in the given traces
	:param pathToNewTraces: path to the folder containing the traces, for which the dictionary should be updated
	:param pathToDictionary: path to the location of the dictionary
	:type pathToNewTraces: string
	:type pathToDictionary: string
	:example:

	dictionaryMethods.updateNumericDictionaryOfMethods('../../input_data/piggybacked_malware/', '../../input_data/dictionary.txt')
	"""
    	old_dict = jsonf.getData(pathToDictionary)
    	updated_dict = update(pathToNewTraces, old_dict)
	jsonf.write(pathToDictionary, updated_dict)
    	print('numeric dictionary of methods updated')

def update(path, old_dict):
	updated_dict = old_dict	
	position = 0
	amount = 10
	numberOfFiles = jsonf.getNumberOfFilesInFolder(path)
	# load traces in packages of 10 in order to ensure a smooth execution
	for i in range(0, (numberOfFiles/amount)+1):
		data, fileNames = jsonf.getAmountOfFilesInFolder(path, position, amount)
		# add method names to the dictionary, which are not displayed in it yet
		updated_dict = addMissingEntries(old_dict, data)
		position = position + amount
	return updated_dict

def addMissingEntries(old_dict, data):
    updated_dict = old_dict
    counter = len(old_dict)
    for i in range(len(data)):
	# get all methods in the current trace and insert these that are still missing in the dictionary
        methods = jsonf.getAllMethods(data[i])
        for j in range(len(methods)):
            updated_dict, counter = insertIfMissing(methods[j], updated_dict, counter)
    return updated_dict

def insertIfMissing(method, updated_dict, counter):
	# methods that only vary by the warning text are viewed as the same, therefore we slice the methods to the core
    	slicedMethod = sliceMethod(method)
    	if slicedMethod not in updated_dict:
        	print(' key: ', slicedMethod, 'value: ', counter)
        	updated_dict[slicedMethod] = counter
        	counter = counter+1
    	return updated_dict, counter

def sliceMethod(method):
	# slice method by removing warning notes and additional information
	method = method.split(' ')[0]
	return method


