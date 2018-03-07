#!/usr/bin/python

import handleOS as system
import dictionaryMethods as dictMeth
import handleData as hdata
import database as db
import ast

def localize(pathToFolder, pathToDictionary, thresholdsAndLengths, support, confidence, allMalBehaviors, expId):
	"""
	Localize malicious segments by generating association rules on the maliciously classified files with the tool 'Apyori'
	:param pathToFolder: path to the folder containing the classification results
	:param pathToDictionary: path to the dictionary used to convert the method names of the traces into numerical values
	:param thresholdsAndLengths: list of the lengths to which the traces should be fixed with their regarding classification thresholds
	:param support: the minimum support value that the generated association rules have to fulfill
	:param confidence:  the minimum confidence value that the generated association rules have to meet
	:param allMalBehaviors: list of the defined malicious behaviors that were inserted into the benign files
	:param expId: id of the current experiment in the database
	:type pathToFolder: string
	:type pathToDictionary: string
	:type thresholdsAndLengths: list
	:type support: float
	:type confidence: float
	:type allMalBehaviors: list
	:type expId: int
	"""
	resultingData = []	
	for i in range(len(thresholdsAndLengths)):
		threshold = thresholdsAndLengths[i][0]
		fixedLength = thresholdsAndLengths[i][1]
		# create a .tsv file from the input data, because this is needed for the 'Apyori' tool
		pathToTSVFile = createTSVFile(threshold, fixedLength, pathToFolder, pathToDictionary, len(allMalBehaviors))
		# calculate the assocation rules with the 'Apyori' tool
		rules = calc(support, confidence, pathToTSVFile)
		# write rules to file and check whether the inserted malicious behaviors could be found
		foundMalBehaviors = writeRules(threshold, fixedLength, rules, pathToDictionary, pathToFolder, allMalBehaviors)
		resultingData.append([fixedLength, foundMalBehaviors])
	writeResult(resultingData, pathToFolder, expId)

def localizeRealData(pathToFolder, pathToDictionary, thresholdsAndLengths, support, confidence):
	"""
	Localize malicious segments by generating association rules on real data with the tool 'Apyori'
	:param pathToFolder: path to the folder containing the classification results
	:param pathToDictionary: path to the dictionary used to convert the method names of the traces into numerical values
	:param thresholdsAndLengths: list of the lengths to which the traces should be fixed with their regarding classification thresholds 
	:param support: the minimum support value that the generated association rules have to fulfill
	:param confidence: the minimum confidence value that the generated association rules have to meet
	:type pathToFolder: string
	:type pathToDictionary: string
	:type thresholdsAndLengths: list
	:type support: float
	:type confidence: float
	"""
	for i in range(len(thresholdsAndLengths)):
		threshold = thresholdsAndLengths[i][0]
		fixedLength = thresholdsAndLengths[i][1]
		# create a .tsv file from the input data, because this is needed for the 'Apyori' tool
		pathToTSVFile = createTSVFileRealData(threshold, fixedLength, pathToFolder, pathToDictionary)
		# calculate the assocation rules with the 'Apyori' tool and afterwards write them to the ouput files
		rules = calc(support, confidence, pathToTSVFile)
		writeRulesRealData(threshold, fixedLength, rules, pathToDictionary, pathToFolder)

def createTSVFile(threshold, length, pathToFolder, pathToDictionary, numberOfMalBehaviors):
		hdata.createTSVForFolder(threshold, length, pathToFolder, pathToDictionary, numberOfMalBehaviors)
		pathToTSVFile = pathToFolder+'assocData_'+str(length)+'_'+str(threshold)+'.tsv'
		return pathToTSVFile

def createTSVFileRealData(threshold, length, pathToLogFiles, pathToDictionary):
		hdata.createTSVForFiles(threshold, length, pathToLogFiles, pathToDictionary, False)
		pathToTSVFile = pathToLogFiles+'assocData_'+str(length)+'_'+str(threshold)+'.tsv'
		return pathToTSVFile

def calc(support, confidence, pathToData):
	results = calculateRules(support, confidence, pathToData)
	# convert the created association rules into a format that can be worked with more easily
	rules = getRules(results)
	return rules

def calculateRules(support, confidence, pathToData):
	"""
	Generating association rules with the tool 'Apyori'
	:param support: the minimum support value that the generated association rules have to fulfill
	:param confidence: the minimum confidence value that the generated association rules have to meet
	:param pathToData: path to the .tsv file containing the maliciously classified traces
	:type support: float
	:type confidence: float
	:type pathToData: string
	:return: generated association rules
	:rtype: string
	"""
	command = 'apyori-run -s '+str(support)+' -c '+str(confidence)+' < '+pathToData+''
	results = system.execute(command)
	return results

def getRules(results):
	numberOfLineBreaks = results.count('\n')
	splitted = results.split('\n')
	rules = getItemsetsAndObjectives(splitted, numberOfLineBreaks)
	return rules

def getItemsetsAndObjectives(splitted, numberOfLineBreaks):
	rules = [-1] * numberOfLineBreaks
	for i in range(0,numberOfLineBreaks):	
		# for each rule get the itemset and support value
		tmp = ast.literal_eval(splitted[i])
		itemset = tmp.get('items')
		ordered = tmp.get('ordered_statistics')
		support = round(tmp.get('support'), 4)
		rules[i] = appendBaseAndAddItemsets(ordered, [itemset, support])
	return rules

def appendBaseAndAddItemsets(ordered, rule):
	for i in range(len(ordered)):
		# for each rule get the base items and the added items as well as the confidence and lift
		itemsBase = ordered[i].get('items_base')
		itemsAdd = ordered[i].get('items_add')
		confidence = round(ordered[i].get('confidence'), 4)
		lift = round(ordered[i].get('lift'), 4)
		rule.append([itemsBase, itemsAdd, confidence, lift])
	return rule

def writeRules(threshold, fixedLength, rules, pathToDictionary, outputPath, allMalBehaviors):
	dictionary = dictMeth.getMethodDictionary(pathToDictionary)	
	allRows = ''
	allFoundMalBehaviors = []
	for i in range(len(rules)):
		# only store rules that contain more than three items, because the inserted malicious behaviors have a size of three
		if len(rules[i][0]) >= 3:
			# look up the names of the methods and check for the inserted malicious behaviors
			allRows, foundMalBehaviors = prepareAndCheckRule(rules[i], dictionary, allRows, allMalBehaviors)
			allFoundMalBehaviors.extend(foundMalBehaviors)
	system.writeFile(outputPath+'associationRules_'+str(threshold)+'_'+str(fixedLength)+'.txt', allRows)
	return allFoundMalBehaviors

def prepareAndCheckRule(rule, dictionary, allRows, allMalBehaviors):
	namedRule = lookUpNames(rule, dictionary)
	row = str(namedRule)+'\n'
	allRows = allRows+row
	# check for the malicious behaviors in each rule
	foundMalBehaviors = checkForMalBehavior(namedRule, allMalBehaviors)
	return allRows, foundMalBehaviors

def lookUpNames(currentRule, dictionary):
	newRule = currentRule
	# look up the names of the methods in the itemset of the rule in the dictionary
	newRule[0] = changeNumberToName(currentRule[0], dictionary)
	if len(currentRule) > 2:
		for j in range(2, len(currentRule)):
			# for each rule look up the names of the methods of the antecedent and the consequent
			itemset = currentRule[j]
			newRule[j][0] = changeNumberToName(itemset[0], dictionary)
			newRule[j][1] = changeNumberToName(itemset[1], dictionary)
	return newRule

def changeNumberToName(itemset, dictionary):
	data = []
	for i in range(len(itemset)):
		if itemset[i] == []:
			data.append(str(itemset[i]))
		else:
			name = dictMeth.getKeyByValue(itemset[i], dictionary)		
			data.append(str(name))
	return data

def checkForMalBehavior(rule, allMalBehaviors):
	"""
	Check if the rule eqauls one of the inserted malicious behaviors
	:param rule: association rule that is regarded in this function
	:param allMalBehaviors: list of all defined malicious behaviors
	:type rule: list
	:type allMalBehaviors: list
	:return: malicious behaviors that were found in the association rules with their support value
	:rtype: list
	"""
	foundMalBehaviors = []
	if len(rule[0]) == 3:
		for i in range(len(allMalBehaviors)):
			malBehavior = allMalBehaviors[i]
			# check if the rule contains the currently regarded malicious behavior
			count, index = findMalBehaviorInRule(rule[0], malBehavior)
			found = checkLenghtAndUniqueness(i+1, malBehavior, count, index, rule[1])
			if found != []:
				foundMalBehaviors.append(found)
	return foundMalBehaviors

def findMalBehaviorInRule(rule, malBehavior):
	count = 0
	index = [-1]*len(malBehavior)
	for i in range(len(malBehavior)):
		# check if all methods from the malicious behavior are found in the rule
		if malBehavior[i] in rule:
			count = count+1
			index[i] = rule.index(malBehavior[i])
	return count, index

def checkLenghtAndUniqueness(numberOfMalBehavior, malBehavior, count, index, support):
	foundMalBehavior = []
	# ensure that the rule equals the malicious behavior
	if count == len(malBehavior):
		if len(index) == len(set(index)):
			foundMalBehavior.append(numberOfMalBehavior)
			foundMalBehavior.append(support)
	return foundMalBehavior

def writeRulesRealData(threshold, fixedLength, rules, pathToDictionary, outputPath):
	dictionary = dictMeth.getMethodDictionary(pathToDictionary)	
	allRows = ''
	for i in range(len(rules)):
		# look up the names of the methods before writing them to the output file
		namedRule = lookUpNames(rules[i], dictionary)
		allRows = allRows+str(namedRule)+'\n'
	system.writeFile(outputPath+'associationRules_'+str(threshold)+'_'+str(fixedLength)+'.txt', allRows)

def writeResult(resultingData, outputPath, expId):
	# arrange the content for the table that displays the localization results
	data = ['fixedLength;maliciousBehaviorAppears;support']
	for i in range(len(resultingData)):
		foundBehaviors = resultingData[i][1]
		if foundBehaviors != []:
			# add the found malicious behaviors and their support value to the results
			for j in range(len(foundBehaviors)):
				entry = str(resultingData[i][0])+';'+str(foundBehaviors[j][0])+';'+str(foundBehaviors[j][1])
				data.append(entry)
	insertIntoDatabase(expId, data)
	system.writeCSVFile(outputPath+'assoc_results.csv', data)

def insertIntoDatabase(expId, data):
	connection = db.connect()
	# exclude the header and only insert the pure data
	data = data[1:]
	db.insertAssociationRules(connection, expId, data)
	db.close(connection)
