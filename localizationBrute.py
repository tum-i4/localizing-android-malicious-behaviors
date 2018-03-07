#!/usr/bin/python

import handleOS as system
import handleData as hdata
import handleJsonFile as jsonf
import classification as clf
import dictionaryMethods as dictMeth
import database as db
import levenshtein as lev
import ast

def localize(pathToLogFiles, modelsArray, pathToDictionary, thresholdsAndLengths, minLengthBlocks, malBehavior, expId, malBehaviorNumber):
	"""
	Localize the most malicious segments of the traces with Hidden Markov Models
	:param pathToLogFiles: path to the folder containing the classification results
	:param modelsArray: list of hidden markov models and the domain of the observations for each fixed length
	:param pathToDictionary: path to the dictionary file that contains the method names of the API calls 
	:param thresholdAndLengths: list of lengths to which samples should be fixed and the corresponding thresholds for classification
	:param minLengthBlocks: the minimum length the splitted blocks should have after the splitting of the traces
	:param malBehavior: the inserted malicious behavior we want to localize
	:param expId: id of the current experiment in the database
	:param malBehaviorNumber: the number of the inserted malicious behavior
	:type pathToLogFiles: string
	:type modelsArray: list
	:type pathToDictionary: string
	:type thresholdAndLengths: list
	:type minLengthBlocks: int
	:type malBehavior: list
	:type expId: int
	:type malBehaviorNumber: int
	"""
	for i in range(len(thresholdsAndLengths)):		
		threshold = thresholdsAndLengths[i][0]
		length = thresholdsAndLengths[i][1]
		pathToFile = pathToLogFiles+'logMaliciousWithPath_'+str(length)+'.txt'
		outputPath = pathToLogFiles+'bruteForce_'+str(length)+'.csv'
		# compute the log-likelihood values for segments of the traces while splitting to get to the most malicious parts of the traces
		segments = getLogsToMaliciousSegments(pathToFile, modelsArray[i], pathToDictionary, length, threshold, minLengthBlocks)
		# calculate the metrics appearance and difference on the segments and write the results to the output files
		writeToFile(outputPath, segments, pathToDictionary, length, malBehavior, expId, malBehaviorNumber)

def localizeRealData(pathToLogFiles, modelsArray, pathToDictionary, thresholdsAndLengths, minLengthBlocks):
	"""
	Localize the most malicious segments of real data with Hidden Markov Models
	:param pathToLogFiles: path to the folder containing the classification results
	:param modelsArray: list of hidden markov models and the domain of the observations for each fixed length
	:param pathToDictionary: path to the dictionary file that contains the method names of the API calls 
	:param thresholdAndLengths: list of lengths to which samples should be fixed and the corresponding thresholds for classification
	:param minLengthBlocks: the minimum length the splitted blocks should have after the splitting of the traces
	:type pathToLogFiles: string
	:type modelsArray: list
	:type pathToDictionary: string
	:type thresholdAndLengths: list
	:type minLengthBlocks: int
	"""
	for i in range(len(thresholdsAndLengths)):		
		threshold = thresholdsAndLengths[i][0]
		length = thresholdsAndLengths[i][1]
		pathToFile = pathToLogFiles+'logMaliciousWithPath_'+str(length)+'.txt'
		outputPath = pathToLogFiles+'bruteForce_'+str(length)+'.csv'
		# compute the log-likelihood values for segments of the traces while splitting to get to the most malicious parts of the traces
		segments = getLogsToMaliciousSegments(pathToFile, modelsArray[i], pathToDictionary, length, threshold, minLengthBlocks)
		# write the results for each fixed length to the output files
		writeRealDataToFile(outputPath, segments, pathToDictionary)

def getLogsToMaliciousSegments(pathToFile, modelAndSigma, pathToDictionary, length, threshold, minLengthBlocks):
	# get the files that were classified as malicious in the classification step
	dataArray = getMaliciousFiles(pathToFile, threshold)	
	model = modelAndSigma[0]
	sigma = modelAndSigma[1]
	allMaliciousCalls = []
	for i in range(len(dataArray)):
		# split each trace until the parts are not more malicious than their parent part
		maliciousCalls = getSamplesAndLocalize(dataArray[i], pathToDictionary, length, model, sigma, minLengthBlocks)
		allMaliciousCalls.append(maliciousCalls)
	return allMaliciousCalls

def getMaliciousFiles(pathToFile, threshold):
	data = jsonf.getData(pathToFile)
	files = hdata.getMaliciousFiles(threshold, data, True)
	return files

def getSamplesAndLocalize(data, pathToDictionary, length, model, sigma, minLengthBlocks):
	log = data[0]
	# normalize the log-likelihood value with the length of the regarded part
	normLog = log/length
	pathToElement = data[1]
	sample = hdata.fetchSampleFixedLength(pathToElement, pathToDictionary, length)
	# split the currently regarded part and compute the log-likelihood values of the children parts
	maliciousCalls = splitAndComputeLog(sample, length, model, sigma, normLog, minLengthBlocks)
	return maliciousCalls

def splitAndComputeLog(sample, length, model, sigma, log, minLengthBlocks):	
	# stop the splitting if it would results in blocks that do not have a length of 'minLengthBlocks'
	if len(sample) < (minLengthBlocks*2):	
		return []
	else:
		# split into 2 parts and compute the log-likelihood values for them
		newLength = (length/2)
		part1 = sample[0:newLength]
		part2 = sample[newLength:]
		return computeLogsForParts(part1, part2, model, sigma, log, minLengthBlocks)

def computeLogsForParts(part1, part2, model, sigma, log, minLengthBlocks):
	# compute log-likelihood value for each of the parts
	log1 = clf.computeLogForOneSample(model, sigma, part1)
	log2 = clf.computeLogForOneSample(model, sigma, part2)
	# normalize the log-likelihood values with the length of the regarded part and compare them to the log-likelihood value of the parent part
	normLog1 = log1/len(part1)
	normLog2 = log2/len(part2)
	return compareLogs(log, normLog1, normLog2, part1, part2, model, sigma, minLengthBlocks)	

def compareLogs(log, normLog1, normLog2, part1, part2, model, sigma, minLengthBlocks):
	# stop the splitting if the log-likelihood values of the children parts are both bigger than the parent part and their more benign
	if normLog1 > log and normLog2 > log:		
		return []
	else:
		if normLog1 < log and normLog2 < log:
			return bothAreMoreMalicious(normLog1, normLog2, part1, part2, model, sigma, minLengthBlocks)
		else:
			return oneIsMoreMalicious(log, normLog1, normLog2, part1, part2, model, sigma, minLengthBlocks)

def bothAreMoreMalicious(normLog1, normLog2, part1, part2, model, sigma, minLengthBlocks):
	next1 = computeNext(normLog1, part1, model, sigma, minLengthBlocks)
	next2 = computeNext(normLog2, part2, model, sigma, minLengthBlocks)
	return next1+next2

def oneIsMoreMalicious(log, normLog1, normLog2, part1, part2, model, sigma, minLengthBlocks):
	if normLog1 < log:
		return computeNext(normLog1, part1, model, sigma, minLengthBlocks)
	elif normLog2 < log:
		return computeNext(normLog2, part2, model, sigma, minLengthBlocks)

def computeNext(logPart, part, model, sigma, minLengthBlocks):
	# split the current part and compute the log-likehood values for its parts
	next = splitAndComputeLog(part, len(part), model, sigma, logPart, minLengthBlocks)
	return [part, logPart]+next

def writeToFile(filename, data, pathToDictionary, length, malBehavior, expId, malBehaviorNumber):
	maliciousSegments = getMaliciousSegments(data)	
	# compute the percentage of the appearance of the malicious segments as the most malicious segment in all traces and look up the names of the methods
	perc = getPercentages(maliciousSegments)
	namedData = lookUpNames(perc, pathToDictionary)
	# calculate the metrics appearance and difference and add them to the results
	resultingData = addDifferenceToMalBehavior(namedData, malBehavior)
	insertIntoDatabase(expId, malBehaviorNumber, length, resultingData)
	system.writeCSVFile(filename, resultingData)

def writeRealDataToFile(filename, data, pathToDictionary):
	maliciousSegments = getMaliciousSegments(data)
	# compute the percentage of the appearance of the malicious segments as the most malicious segment in all traces and look up the names of the methods
	perc = getPercentages(maliciousSegments)
	namedData = lookUpNames(perc, pathToDictionary)
	system.writeCSVFile(filename, namedData)

def getMaliciousSegments(data):
	mostMalicious = []
	for i in range(len(data)):
		if data[i] == []:
			continue
		elif data[i] == None:
			raise ValueError(data[i])
		else:
			segment, log = getMostMaliciousSegment(data[i])
			mostMalicious.append(segment)
	return mostMalicious

def getMostMaliciousSegment(dataEntry):
	mostMalicious = 0
	index = -1
	# get the segment that is the most malicious one in the trace from the calculated log-likelihood values in the splitting of the trace
	for i in range(len(dataEntry)):
		if i%2 == 1:
			if dataEntry[i] < mostMalicious:
				mostMalicious = dataEntry[i]
				index = i
	log = dataEntry[index]
	segment = dataEntry[index-1]
	return segment, log

def getPercentages(data):
	# create a dictionary, which contains the most malicious segments and count how often they appear
	percentages, numberOfElements = fillDictionary(data)
	for key, value in percentages.items():
		percentages[key] = round(float(value)/float(numberOfElements), 4)
	return percentages

def fillDictionary(data):
	dictionary = {}
	numberOfElements = 0
	for i in range(len(data)):
		element = str(data[i])
		dictionary, numberOfElements = updateDict(element, dictionary, numberOfElements)
	return dictionary, numberOfElements

def updateDict(entry, dictionary, numberOfElements):
	# if the dictionary contains the current malicious block already, increase the stored number of it by 1
	if dictionary.has_key(entry):
		dictionary[entry] = dictionary.get(entry)+1
		numberOfElements = numberOfElements+1
	# otherwise include the malicious block into the dictionary
	else:
		dictionary[entry] = 1
		numberOfElements = numberOfElements+1
	return dictionary, numberOfElements

def lookUpNames(percentages, pathToDictionary):
	data = ['maliciousCalls;percentage']
	for number in sorted(percentages, key=percentages.get, reverse=True):
		newKey = dictMeth.convertToMethodNames(number, pathToDictionary)
		entry = str(newKey)+';'+str(percentages[number])		
		data.append(entry)
	return data

def addDifferenceToMalBehavior(namedData, malBehavior):
	resultingData = namedData
	# for each most malicious segment compute the difference and appearance and put all information together
	for i in range(len(namedData)):
		entry = namedData[i]
		# update the header of the list
		if i == 0:
			newEntry = entry+';maliciousBehaviorAppears;difference[calls]'
		# compute the difference and appearance of the currently regarded most malicious block
		else:
			appearenceAndDiff = computeDifference(entry, malBehavior)
			newEntry = entry+';'+appearenceAndDiff
		resultingData[i] = newEntry
	return resultingData

def computeDifference(entry, malBehavior):
	"""
	Compute the difference between the malicious segments and the inserted malicious behavior and check if the segment contains the malicious behavior
	:param entry: the most malicious segment of a trace
	:param malBehavior: malicious behavior that was inserted into the benign traces
	:type entry: string
	:type malBehavior: list
	:return: the results of the appearance and difference metric for the currently regarded malicious segment
	:rtype: string
	"""
	# convert string of calls of the most malicious segment into and array and compute the Levenshtein difference to the inserted malicious behavior
	calls = entry.split(';')[0]
	callsArray = ast.literal_eval(calls)
	distance = lev.levenshtein(callsArray, malBehavior)
	# check if the most malicious segment contains the inserted malicious behavior
	if checkForBehavior(callsArray, malBehavior):
		return '1;'+str(distance)
	else:
		return '0;'+str(distance)

def checkForBehavior(calls, malBehavior):
	"""
	Check if the most malicious segment contains the inserted malicious behavior
	:param calls: the most malicious segment of a trace
	:param malBehavior: malicious behavior that was inserted into the benign traces
	:type entry: list
	:type malBehavior: list
	:return: the result of the check for the inserted malicious behavior
	:rtype: boolean
	"""
	for i in range(len(calls)-(len(malBehavior)-1)):
		count = 0
		for k in range(len(malBehavior)):
    			if calls[i+k] == malBehavior[k]:
				count = count+1
		if count == len(malBehavior):     				
			return True
  	return False

def insertIntoDatabase(expId, malBehaviorNumber, length, resultingData):
	connection = db.connect()
	# exclude the header and only insert the pure data in the database
	resultingData = resultingData[1:]
	db.insertLocalizationBrute(connection, expId, length, malBehaviorNumber, resultingData)
	db.close(connection)
