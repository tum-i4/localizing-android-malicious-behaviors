#!/usr/bin/python

import handleOS as system
import handleData as hdata
import generateRepackagedMalware as genMal
import classification as clf
import createTable as table
import localizationAssoc as assoc
import localizationBrute as bruteF
import database as db
import random

def testApproach(pathToData, outputFolder, prob, fixedLengthArray, steps, thrEnd, support, confidence):
	"""
	Genreate repackaged malware, classify these traces and localize malicious segments in them
	:param pathToData: path to the folder containing the folders for the testing and training dataset and the dictionary
	:param outputFolder: path to the folder, in which the output files will be stored
	:param prob: the malicious behaviors will be inserted with this probabitlity while generating repackaged traces
	:param fixedLengthArray: the traces will be fixed to the lengths contained in this list
	:param steps: the thresholds for the classification results increment in steps of this parameter
	:param thrEnd: the last threshold that is considered for the classification results
	:param support: the minimum support value that the generated association rules have to fulfill
	:param confidence: the minimum confidence value that the generated association rules have to meet
	:type pathToData: string
	:type outputFolder: string
	:type prob: float
	:type fixedLengthArray: list
	:type steps: int
	:type thrEnd: int
	:type support: float
	:type confidence: float
	:example:

	workflow.testApproach('../../input_data/', '../data/', 0.75, [50,100,200,300,500], 50, -1000, 0.1, 0.1)
	"""
	# if you use new data, remember to update the dictionary first
	pathGoodware = pathToData+'google_play_goodware/'	
	pathTrainingData = pathToData+'google_play_train/'
	pathTestingData = pathToData+'google_play_test/'
	outputPathTestingData = outputFolder+'testing_data_goodware/'
	pathToDictionary = pathToData+'dictionary.txt'

	# if needed, split the goodware first into training and testing data set: 
	# splitGoodwareIntoTrainingAndTestData(pathGoodware, pathTrainingData, pathTestingData)

	# load the specified malicious behaviors and train HMMs for each length from 'fixedLengthArray
	allMaliciousBehaviors = hdata.getDefinedMaliciousBehavior(pathToData)
	modelsArray = getModelsForFixedLengths(fixedLengthArray, pathTrainingData, pathToDictionary)		

	# connect to the database and insert the experiment
	experimentId = insertExperimentIntoDatabase(prob)
	
	# classify the benign testing data with Hidden Markov Models
	classifyTestingData(modelsArray, pathTestingData, outputPathTestingData, pathToDictionary, fixedLengthArray, steps, thrEnd)

	# generate repackaged malware, classify it and localize it
	workWithMalware(allMaliciousBehaviors, prob, pathToData, modelsArray, outputFolder, pathToDictionary, pathTestingData, outputPathTestingData, fixedLengthArray, steps, thrEnd, support, confidence, experimentId)

def runRealData(pathToData, pathToMalware, outputFolder, fixedLengthArray, steps, thrEnd, support, confidence):
	"""
	Classify repackaged traces and localize malicious segments in real data
	:param pathToData: path to the folder containing the folders for the testing and training dataset and the dictionary
	:param pathToMalware: path to the folder containing the malicious traces
	:param outputFolder: path to the folder, in which the output files will be stored
	:param fixedLengthArray: the traces will be fixed to the lengths contained in this list
	:param steps: the thresholds for the classification results increment in steps of this parameter
	:param thrEnd: the last threshold that is considered for the classification results
	:param support: the minimum support value that the generated association rules have to fulfill
	:param confidence: the minimum confidence value that the generated association rules have to meet
	:type pathToData: string
	:type pathToMalware: string
	:type outputFolder: string
	:type fixedLengthArray: list
	:type steps: int
	:type thrEnd: int
	:type support: float
	:type confidence: float
	:example:

	workflow.runRealData('../../input_data/', '../../input_data/piggybacked_malware/', '../data/', [50,100,200,300,500], 50, -1000, 0.7, 0.7)
	"""

	# if you use new data, remember to update the dictionary first
	pathToGoodware = pathToData+'piggybacked_goodware/'
	pathTrainingData = pathToData+'piggybacked_train/'
	pathTestingData = pathToData+'piggybacked_test/'
	pathToDictionary = pathToData+'dictionary.txt'
	outputPath = outputFolder+'piggybacked_malware/'
	outputPathTestingData = outputFolder+'testing_data_piggybacked/'
	outputPathClassificationMetrics = outputPath+'fullTable.csv'
	createFilesAtLengthFile(outputPath)

	# split benign traces into a training and a testing data set
	splitGoodwareIntoTrainingAndTestData(pathToGoodware, pathTrainingData, pathTestingData)

	# train Hidden Markov Models for the lengths specified in 'fixedLengthArray'
	modelsArray = getModelsForFixedLengths(fixedLengthArray, pathTrainingData, pathToDictionary)

	# classify testing data set
	classifyTestingData(modelsArray, pathTestingData, outputPathTestingData, pathToDictionary, fixedLengthArray, steps, thrEnd)

	# classify the malicious traces with Hidden Markov Models
	clf.computeAllLogs(modelsArray, pathToMalware, outputPath, pathToDictionary, fixedLengthArray, False)
	table.createTableWithAllMetrics(outputPathTestingData, outputPath, outputPathClassificationMetrics, steps, thrEnd, -1, -1)
	thresholdsAndLength = getThresholdsFromAccuracy(outputPathClassificationMetrics, thrEnd)

	# localize malicious segments in the traces with Association Rules
	assoc.localizeRealData(outputPath, pathToDictionary, thresholdsAndLength, support, confidence)

	# localize malicious segments with Hidden Makov Models with minimum block length of 3
	bruteF.localizeRealData(outputPath, modelsArray, pathToDictionary, thresholdsAndLength, 3)

def splitGoodwareIntoTrainingAndTestData(pathGoodware, pathTrainingData, pathTestingData):
	# split goodware into training and testing data set and store the files in the folders 'pathTrainingData' and 'pathTestingData'
	if system.exists(pathTrainingData):
		system.deleteAllFilesInFolder(pathTrainingData)
	else:
		system.createOutputFolder(pathTrainingData)
	if system.exists(pathTestingData):
		system.deleteAllFilesInFolder(pathTestingData)
	else:
		system.createOutputFolder(pathTestingData)
	distributeGoodware(pathGoodware, pathTrainingData, pathTestingData)

def distributeGoodware(pathGoodware, pathTrainingData, pathTestingData):
	files = system.getAllFilesInFolder(pathGoodware)
	for i in range(len(files)):	
		# store two third of the data in the training data folder and one third in the testing data folder
		if random.random() < (float(2)/float(3)):
			system.copyFileToNewDirectory(pathGoodware+files[i], pathTrainingData)
    		else:
			system.copyFileToNewDirectory(pathGoodware+files[i], pathTestingData)

def getModelsForFixedLengths(fixedLengthArray, pathTrainingData, pathToDictionary):
	allModelsAndSigmas = []
	for i in range(len(fixedLengthArray)):
		# for each length train a Hidden Markov Model with traces of this fixed length
		model, sigma = clf.train(fixedLengthArray[i], pathTrainingData, pathToDictionary)
		allModelsAndSigmas.append([model, sigma])
	return allModelsAndSigmas

def insertExperimentIntoDatabase(prob):
	connection = db.connect()
	# insert a new experiment into the database with the insertion probability 'prob'
	expId = db.insertExperiment(connection, prob)
	db.close(connection)
	return expId

def classifyTestingData(modelsArray, pathTestingData, outputPathTestingData, pathToDictionary, fixedLengthArray, steps, thrEnd):
	createFilesAtLengthFile(outputPathTestingData)
	clf.computeAllLogs(modelsArray, pathTestingData, outputPathTestingData, pathToDictionary, fixedLengthArray, True)

def getThresholdsFromAccuracy(outputPath, thrEnd):
	data = system.readCSVFile(outputPath)
	thresholdsAndLength = clf.getThresholdsForEachLength(data, thrEnd)
	return thresholdsAndLength

def workWithMalware(allMaliciousBehaviors, prob, pathToData, modelsArray, outputFolder, pathToDictionary, pathTestingData, pathToBenignData, fixedLengthArray, steps, thrEnd, support, confidence, experimentId):

	allThresholds = []

	for i in range(len(allMaliciousBehaviors)):
		# the defined malicious behaviors are numbered beginning at 1
		malBehaviorNumber = i+1
		outputPath = outputFolder+'prob_'+str(prob)+'/malBehavior_'+str(malBehaviorNumber)+'/'
		outputPathClassificationMetrics = outputPath+'fullTable.csv'
		createFilesAtLengthFile(outputPath)

		# generate repackaged malware by inserting the malicious behavior with the insertion probability 'prob' into the benign traces
		pathToMalware = genMal.generate(prob, malBehaviorNumber, pathToData, pathTestingData)

		# classify the generated repackaged traces with Hidden Markov Models
		clf.computeAllLogs(modelsArray, pathToMalware, outputPath, pathToDictionary, fixedLengthArray, False)
		table.createTableWithAllMetrics(pathToBenignData, outputPath, outputPathClassificationMetrics, steps, thrEnd, malBehaviorNumber, experimentId)
		thresholdsAndLength = getThresholdsFromAccuracy(outputPathClassificationMetrics, thrEnd)
		allThresholds.append(thresholdsAndLength)

		# localize malicious segments with Hidden Markov Models
		bruteF.localize(outputPath, modelsArray, pathToDictionary, thresholdsAndLength, 3, allMaliciousBehaviors[i], experimentId, malBehaviorNumber)

	# localize malicious segments with Association Rules
	thresholds = clf.getMediumThresholds(allThresholds)
	assoc.localize(outputFolder+'prob_'+str(prob)+'/', pathToDictionary, thresholds, support, confidence, allMaliciousBehaviors, experimentId)

def createFilesAtLengthFile(outputPath):
	if not system.exists(outputPath):
		system.createOutputFolder(outputPath)
	open(outputPath+'filesAtLength.txt', 'w').close()
