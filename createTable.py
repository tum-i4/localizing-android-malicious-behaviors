#!/usr/bin/python

import handleJsonFile as jsonf
import handleOS as system
import database as db

def createTableWithAllMetrics(pathToBenignData, pathToMaliciousData, outputPath, thresholdSteps, thresholdEnd, malBehavior, experimentId):
	"""
	Create a table with the classification metrics specificity, recall and accuracy regarding different thresholds
	:param pathToBenignData: path to the folder containing the log-likelihoods of the benign testing data set
	:param pathToMaliciousData: path to the folder containing the log-likelihoods of the malicious traces
	:param outputPath: path to the file, in which the results will be stored
	:param thresholdSteps: the steps in which the threshold increases
	:param thresholdEnd: the final threshold that is regarded for the metrics
	:param malBehavior: malicious behavior that was inserted into the benign traces
	:param experimentId: id of the current experiment in the database, set it to -1 if you do not want to store the results in the database
	:type pathToBenignData: string
	:type pathToMaliciousData: string
	:type outputPath: string
	:type thresholdSteps: int
	:type thresholdEnd: int
	:type malBehavior: int
	:type experimentId: int
	:example:

	createTable.createTableWithAllMetrics('../data/testing_data_goodware/', '../data/prob_0.1/malBehavior_1/', '../data/prob_0.1/malBehavior_1/fullTable.csv', 50, -1000, 1, 10)
	"""
	benignLogs = system.getFilenamesWithPrefix(pathToBenignData, 'logBenign_')
	maliciousLogs = system.getFilenamesWithPrefix(pathToMaliciousData, 'logMalicious_')
	fullTable = createFullTable(benignLogs, maliciousLogs, pathToBenignData, pathToMaliciousData, thresholdSteps, thresholdEnd)
	# insert results into the database, if this step should be skipped the parameter 'experimentId' is set to -1
	if experimentId != -1:
		insertIntoDatabase(experimentId, fullTable, malBehavior)
	system.writeCSVFile(outputPath, fullTable)	

def createFullTable(benignLogs, maliciousLogs, pathToBenignData, pathToMaliciousData, thresholdSteps, thresholdEnd):
	# compute the metric specificity from the benign traces
	specificities = getClassificationMetric(benignLogs, pathToBenignData, thresholdSteps, thresholdEnd, True)
	# compute the metric recall from the malicious traces
	recalls = getClassificationMetric(maliciousLogs, pathToMaliciousData, thresholdSteps, thresholdEnd, False)
	numberBenignFiles = getNumberOfFiles(pathToBenignData+'filesAtLength.txt')
	numberMaliciousFiles = getNumberOfFiles(pathToMaliciousData+'filesAtLength.txt')
	# generate table that contains specificity,recall and accuracy
	fullTable = generateFullTable(specificities, numberBenignFiles, recalls, numberMaliciousFiles)
	return fullTable

def getClassificationMetric(logs, pathToData, thresholdSteps, thresholdEnd, isBenignData):
	metric = {}	
	for i in range(len(logs)):
		fileName = logs[i]
		# calculate the specificity or recall results for all thresholds regarding the kind of data
		results = calculateMetricForThresholds(pathToData+fileName, thresholdSteps, thresholdEnd, isBenignData)
		maxLength = fileName[fileName.index('_')+1:fileName.index('.')]
		metric[int(maxLength)] = results
	return metric	
	
def getNumberOfFiles(path):
	data = system.readFile(path)
	data = data.split('\n')
	numbers = []
	for i in range(len(data)):
		if data[i] != '':
			entry = data[i].rsplit(' ', 1)[1]
			numbers.append(entry)
	return numbers

def generateFullTable(specificities, numberBenignFiles, recalls, numberMaliciousFiles):
	specTable = changeToTableFormat(specificities)
	recallTable = changeToTableFormat(recalls)
	fullTable = specTable
	for i in range(len(specTable)):
		if i != 0:
			# calculate accuarcy from the specificity and recall and add it to the table
			fullTable[i] = addAccuracy(specTable[i], numberBenignFiles, recallTable[i], numberMaliciousFiles)
	return fullTable
	
def changeToTableFormat(metric):
	keys = sorted(metric.keys())
	table = [-1] * (len(metric[keys[0]])+1)
	table[0] = 't'
	table = fillTable(table, metric, keys)
	return table

def addAccuracy(specificityEntry, numberBenignFiles, recallEntry, numberMaliciousFiles):
	splittedSpec = specificityEntry.split(';')
	splittedRecall = recallEntry.split(';')
	fullRow = ''
	for i in range(len(splittedSpec)):
		if i == 0:
			fullRow = fullRow+splittedSpec[i]
		else:
			specificity = float(splittedSpec[i])
			recall = float(splittedRecall[i])
			# recall = TP / P
			truePositive = recall*int(numberMaliciousFiles[i-1])
			# specificity = TN / N
			trueNegative = specificity*int(numberBenignFiles[i-1])
			# accuarcy = TP + TN / P + N
			accuracy = round((truePositive+trueNegative)/(int(numberMaliciousFiles[i-1])+int(numberBenignFiles[i-1])), 2)
			fullRow = fullRow+';'+str(round(specificity,2))+'/'+str(round(recall, 2))+'/'+str(accuracy)
	return fullRow

def insertIntoDatabase(experimentId, fullTable, malBehavior):
	connection = db.connect()
	db.insertClassification(connection, experimentId, malBehavior, fullTable)
	db.close(connection)

def create(filepath, thresholdSteps, thresholdEnd, isBenignData, experimentId):
	"""
	Create a table of the percentage of correctly classified traces regarding different thresholds
	:param filepath: path to the data folder containing the log-likelihood value calculated in the classification step
	:param thresholdSteps: the steps in which the threshold increases
	:param thresholdEnd: the final threshold that is regarded for the metrics
	:param isBenignData: boolean value that states if the current log-likelihoods are from benign or malicious files
	:param experimentId: id of the current experiment in the database
	:type filepath: string
	:type thresholdSteps: int
	:type thresholdEnd: int
	:type isBenignData: boolean
	:type experimentId: int
	"""
	prefix, outputFile = getPrefix(isBenignData)
	logs = system.getFilenamesWithPrefix(filepath, prefix)
	# calculate the percentage of correctly classified files for all threshold
	dictThresholds = getDictWithThresholds(logs, filepath, thresholdSteps, thresholdEnd, isBenignData)
	if experimentId != -1:
		insertSingleMetricIntoDatabase(experimentId, dictThresholds, isBenignData, filepath)
	writeToCSVFile(filepath+outputFile, dictThresholds)

def getPrefix(isBenignData):
	if isBenignData:
		return 'logBenign_', 'benignTable.csv'
	else:
		return 'logMalicious_', 'maliciousTable.csv'

def getDictWithThresholds(logs, filepath, thresholdSteps, thresholdEnd, isBenignData):
	dictThresholds = {}
	for i in range(len(logs)):
		filename = logs[i]
		# compute the metric results for thresholds increasing in steps of 'thresholdSteps' and ending at 'thresholdEnd'
		thresholds = calculateMetricForThresholds(filepath+filename, thresholdSteps, thresholdEnd, isBenignData)
		maxLength = filename[filename.index('_')+1:filename.index('.')]
		dictThresholds[int(maxLength)] = thresholds
	return dictThresholds	

def calculateMetricForThresholds(filepath, thresholdSteps, thresholdEnd, isBenignData):
	data = getData(filepath)
	allThresholds = []
	if data:
		allThresholds = getResultsForAllThresholds(data, thresholdSteps, thresholdEnd, isBenignData)
	return allThresholds

def getData(filepath):
	data = []
	if system.exists(filepath):
		data = jsonf.getData(filepath)
	else:
		print 'No such file exists'
	return data

def getResultsForAllThresholds(data, thresholdSteps, thresholdEnd, isBenignData):
	allThresholds = []	
	lengthData = len(data)
	for i in range(1, (abs(thresholdEnd)/thresholdSteps)+1):
		# threshold are negative due to the logarithmic scale
		threshold = (-1)*thresholdSteps*i
		# count the number of correctly classified files regarding the current threshold
		counter = countForThreshold(lengthData, data, threshold, isBenignData)
		# specificity/recall: correctly classified files divided by number of files
		value = round(float(counter)/float(lengthData), 4)
		allThresholds.append([threshold, value])
	return allThresholds

def countForThreshold(lengthData, data, threshold, isBenignData):
	counter = 0
	for j in range(lengthData):
		# a benign sequence is classified correctly when the log-likelihood of it is nearer to zero than the threshold
		if isBenignData:
			if data[j] > threshold:
				counter = counter+1
		# a malicious sequence is classified correctly when the log-likelihood of it is more away from zero than the threshold
		else:
			if data[j] < threshold:
				counter = counter+1
	return counter

def writeToCSVFile(path, allThresholds):
	keys = sorted(allThresholds.keys())
	table = [-1] * (len(allThresholds[keys[0]])+1)
	table[0] = 't'
	# convert results into a table format 
	table = fillTable(table, allThresholds, keys)
	system.writeCSVFile(path, table)

def fillTable(table, allThresholds, keys):
	for i in range(len(keys)):
		table[0] = table[0]+';'+str(keys[i])
		values = allThresholds[keys[i]]
		table = addValuesToTable(table, values)
	return table
	
def addValuesToTable(table, values):
	for j in range(len(values)):
		if table[j+1] == -1:
			# at the beginning of each row add the threshold value and the first value 
			table[j+1] = str(values[j][0])+';'+str(values[j][1])
		else:
			# afterwards just append the current value
			table[j+1] = table[j+1]+';'+str(values[j][1])
	return table

def insertSingleMetricIntoDatabase(experimentId, dictThresholds, isBenignData, filepath):
	if isBenginData:
		insertBenignClassificationIntoDatabase(experimentId, dictThresholds)
	else:
		malBehavior = int(filepath.rsplit('_', 1)[1].split('/')[0])
		insertMalClassificationIntoDatabase(experimentId, malBehavior, dictThresholds)

def insertBenignClassificationIntoDatabase(experimentId, dictThresholds):
	connection = db.connect()
	db.insertBenignClassification(connection, experimentId, dictThresholds)
	db.close(connection)

def insertMalClassificationIntoDatabase(experimentId, malBehavior, dictThresholds):
	connection = db.connect()
	db.insertMalClassification(connection, experimentId, malBehavior, dictThresholds)
	db.close(connection)
