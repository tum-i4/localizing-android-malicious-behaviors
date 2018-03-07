#!/usr/bin/python

import handleJsonFile as jsonf
import dictionaryMethods as dictMeth
import handleOS as system

def getMaliciousFiles(threshold, data, withLog):
	"""
	Gets the files that are classified as 'malicious' regarding a given threshold
	:param threshold: threshold, which separates files into 'benign' and 'malicious' by their log-likelihood values
	:param data: content of the input file that contains the log-likelihood values of the regarded traces as well as paths to these traces
	:param withPath: describes if the log-likelihood value should be included in the output 
	:type threshold: int
	:type data: list
	:type withPath: boolean
	:return: paths of files that are classified as 'malicious' regarding the threshold, may include the log-likelihood values of these files
	:rtype: list
	"""
	files = []
	for i in range(len(data)):
		log = data[i][0]
		# if the log-likelihood value farer away from zero than the threshold it is classified as 'malicious'
		if log < threshold:
			# append only the paths to the result or also include the log-likelihood values regarding the variable 'withLog'
			if withLog:
				files.append(data[i])
			else:
				files.append(data[i][1])
	return files

def getDefinedMaliciousBehavior(pathToData):
	"""
	Loads the defined malicious behaviors stored in the file 'definedMalicious.txt'
	:param pathToData: path to the folder, in which the file with the defined malicious behaviors can be found
	:type withPath: string
	:return: defined malicious behaviors
	:rtype: list
	"""
	maliciousString = system.readFile(pathToData+"definedMalicious.txt")
	malicious = getArrayFromString(maliciousString)
	return malicious

def getArrayFromString(string):
	array = []
	# split string into different behaviors
	splitted = string.split('\n')
	for i in range(len(splitted)):
		if splitted[i] != '':
			# separate the single methods of each malicious behavior
			entry = splitted[i].split(',')
			array.append(entry)
	return array

def getDataFromFiles(files, length, pathToDictionary):
	allSamples = []
	amount = 10
	# load traces in packages of 10 in order to ensure a smooth execution
	for i in range(0, (len(files)/amount)+1):
		partOfData = getAmountOfData(i, amount, files)
		samples = createAllSamples(partOfData, length, pathToDictionary)
		allSamples.append(samples)
	allSamples = combineLists(allSamples)
	return allSamples

def getAmountOfData(index, amount, files):
	data = []
	for i in range(index*amount,(index+1)*amount):
		if i < len(files):
			fileData = jsonf.getData(files[i])
			data.append(fileData)
	return data

def combineLists(samples):
	allSamples = []
	for i in range(len(samples)):
		for j in range(len(samples[i])):
			allSamples.append(samples[i][j])
	return allSamples

def createAllSamples(data, maxLength, pathToDictionary):
	allSamples = []
	for i in range(len(data)):
		sample = createSampleFromData(data[i], pathToDictionary)
		# only add sample of length 'maxLength'
		if len(sample) >= maxLength:
			allSamples.append(sample[0:maxLength])
	return allSamples

def createSampleFromData(data, pathToDictionary):
	dictionary = dictMeth.getMethodDictionary(pathToDictionary)	
	sample = []
	methods = jsonf.getAllMethods(data)
	# create a sample containing only the method names without additional warning issues
	for j in range(len(methods)):
		slicedMethod = dictMeth.sliceMethod(methods[j])
		sample.append(dictionary[slicedMethod])
	return sample

def fetchSampleFixedLength(pathToElement, pathToDictionary, length):
	entries = jsonf.getData(pathToElement)
	sample = createSampleFromData(entries, pathToDictionary)
	# only consider the first 'x' methods of the sample in order to fix the length of the sample
	sample = sample[0:length]
	return sample

def createTSVForFolder(threshold, length, pathToFolder, pathToDictionary, numberOfMalBehaviors):
	data = []	
	# the numbering of the malicious behaviors starts at 1
	for i in range(1, numberOfMalBehaviors+1):
		data.extend(jsonf.getData(pathToFolder+'malBehavior_'+str(i)+'/logMaliciousWithPath_'+str(length)+'.txt'))
	# insert only these files that are classified as 'malicious' regarding the threshold in the output file
	files = getMaliciousFiles(threshold, data, False)
	writeDataToTSVFile(files, length, threshold, pathToDictionary, pathToFolder)

def createTSVForFiles(threshold, length, pathToLogFiles, pathToDictionary, isBenignData):
	files = []	
	# if benign data is regarded the .tsv file is created from the 'logBenignWithPath' files
	if isBenignData:
		path = pathToLogFiles+'logBenignWithPath_'+str(length)+'.txt'
		files = getFilesForTSVFile(threshold, path)
	# otherwise the 'logMaliciousWithPath' files are used as input
	else:
		path = pathToLogFiles+'logMaliciousWithPath_'+str(length)+'.txt'
		files = getFilesForTSVFile(threshold, path)
	writeDataToTSVFile(files, length, threshold, pathToDictionary, pathToLogFiles)

def getFilesForTSVFile(threshold, path):
	data = jsonf.getData(path)
	# include only files that are classified as 'malicious' regarding the threshold
	maliciousFiles = getMaliciousFiles(threshold, data, False)
	return maliciousFiles

def writeDataToTSVFile(files, length, threshold, pathToDictionary, pathToLogFiles):
	# convert the data into a .tsv format
	data = getDataInTSVFormat(files, length, pathToDictionary)
	filename = pathToLogFiles+'assocData_'+str(length)+'_'+str(threshold)+'.tsv'
	system.writeFile(filename, data)

def getDataInTSVFormat(files, length, pathToDictionary):
	data = getDataFromFiles(files, length, pathToDictionary)
	tsv = turnToTSVFormat(data)
	return tsv

def turnToTSVFormat(data):
	tsvFormat = ''
	for i in range(len(data)):
		sample = data[i]
		row = createRowTSVFormat(sample)
		# the last row of the file excludes the final line break
		if i == len(data)-1:
			tsvFormat = tsvFormat+row[0:row.rfind('\n')]
		else:
			tsvFormat = tsvFormat+row
	return tsvFormat

def createRowTSVFormat(sample):
	row = ''
	for j in range(len(sample)):
		# the last entry of the trace is added by itself
		if j == len(sample)-1:
			row = row+str(sample[j])
		# after any other entry a tab is added
		else:
			row = row+str(sample[j])+'\t'
	# every row end with a line break
	row = row+'\n' 
	return row

