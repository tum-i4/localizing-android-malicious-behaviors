#!/usr/bin/python

import psycopg2
import re

def connect():
	"""
	Connect to the database
	:return: a connection object for the current database session
	:rtype: connection object
	"""
	conn = None
	try:	
		conn = psycopg2.connect('dbname=thesis_results user=tabea password=tabea')
		print 'Connected to database thesis_results'
	except (Exception, psycopg2.DatabaseError) as error:
        	print error

	return conn

def insertExperiment(connection, prob):
	"""
	inserts data into the table 'experiment', which has the scheme: id, probinsertion
	:param connection: current database session
	:param prob: the insertion probability of malicious behaviors in the current experiment
	:type connection: connection object
	:type prob: float
	:return: the id of the inserted experiment
	:rtype: int
	"""
	sql = 'INSERT INTO experiment (probinsertion) VALUES ('+str(prob)+');'
	insertStatement(connection, sql)
	sql2 = 'SELECT max(id) from experiment;'
	expId = selectStatement(connection, sql2)
	print 'new experiment in database inserted'
	return expId

def insertBenignClassification(connection, experimentId, dataDict):
	"""
	inserts data into the table 'benignClassification', which has the scheme: expid, length, threshold, percentage
	:param connection: current database session
	:param experimentId: id of the experiment, in which the data was generated
	:param dataDict: dictionary containing the data to insert into the table
	:type connection: connection object
	:type experimentId: int
	:type dataDict: dictionary
	"""
	for key, value in dataDict.items():
		length = key
		for i in range(len(value)):
			threshold = value[i][0]
			percentage = value[i][1]
			sql = 'INSERT INTO benignClassification VALUES ('+str(experimentId)+','+str(length)+','+str(threshold)+','+str(percentage)+');'
			insertStatement(connection, sql)
	print 'new benign classification in database inserted'

def insertMalClassification(connection, experimentId, malBehavior, dataDict):
	"""
	inserts data into the table 'malClassification', which has the scheme: expid, length, malBehavior, threshold, percentage
	:param connection: current database session
	:param experimentId: id of the experiment, in which the data was generated
	:param malBehavior: id of the malicious behavior that was inserted into the benign traces in the current experiment
	:param dataDict: dictionary containing the data to insert into the table
	:type connection: connection object
	:type experimentId: int
	:type malBehavior: int
	:type dataDict: dictionary
	"""
	for key, value in dataDict.items():
		length = key
		for i in range(len(value)):
			threshold = value[i][0]
			percentage = value[i][1]
			sql = 'INSERT INTO malClassification VALUES ('+str(experimentId)+','+str(length)+','+str(malBehavior)+','+str(threshold)+','+str(percentage)+');'
			insertStatement(connection, sql)
	print 'new malicious classification in database inserted'

def insertClassification(connection, experimentId, malBehavior, table):
	"""
	inserts data into the table 'classification', which has the scheme: expid, length, malBehavior, threshold, metrics_sra
	:param connection: current database session
	:param experimentId: id of the experiment, in which the data was generated
	:param malBehavior: id of the malicious behavior that was inserted into the benign traces in the current experiment
	:param table: table containing the results for the classification metrics specificity, recall, accuracy
	:type connection: connection object
	:type experimentId: int
	:type malBehavior: int
	:type table: list
	"""
	lengths = table[0].split(';')
	for i in range(1, len(table)):
		splitted = table[i].split(';')
		threshold = splitted[0]
		for j in range(1, len(splitted)):
			metrics_sra = splitted[j]
			length = lengths[j]
			sql = 'INSERT INTO classification VALUES ('+str(experimentId)+','+length+','+str(malBehavior)+','+threshold+",'"+metrics_sra+"');"
			insertStatement(connection, sql)
	print 'new classification metrics inserted in database'

def insertLocalizationBrute(connection, expId, length, malBehaviorNumber, data):
	"""
	inserts data into the table 'localizationBrute', which has the scheme: expid, length, malBehavior, malCalls, percentage, appearance, difference
	:param connection: current database session
	:param expId: id of the experiment, in which the data was generated
	:param length: fixed length of the traces for the localization
	:param malBehaviorNumber: id of the malicious behavior that was inserted into the benign traces in the current experiment
	:param data: list containing the results for the localization with Hidden Markov Models
	:type connection: connection object
	:type expId: int
	:type length: int
	:type malBehaviorNumber: int
	:type data: list
	"""
	for i in range(len(data)):
		splitted = data[i].split(';')
		malCallsWithBrackets = splitted[0]
		malCalls = re.sub("['\[\]]", '', malCallsWithBrackets)
		percentage = splitted[1]
		appearance = splitted[2] 
		difference = splitted[3]
		sql = 'INSERT INTO bruteForce VALUES ('+expId+','+str(length)+','+str(malBehaviorNumber)+",'"+malCalls+"',"+percentage+','+appearance+','+difference+');'
		insertStatement(connection, sql)
	print 'new localization brute force in database inserted'

def insertAssociationRules(connection, expId, data):
	"""
	inserts data into the table 'associationRules', which has the scheme: expid, length, malBehavior, appearance, support
	:param connection: current database session
	:param expId: id of the experiment, in which the data was generated
	:param data: data containing the results for the localization using Association Rules
	:type connection: connection object
	:type expId: int
	:type data: list
	"""
	for i in range(len(data)):
		splitted = data[i].split(';')
		length = splitted[0]
		malBehavior = splitted[1]
		support = splitted[2]
		sql = 'INSERT INTO assocRules VALUES ('+str(expId)+','+length+','+malBehavior+','+support+');'
		insertStatement(connection, sql)
	print 'new association rules in database inserted'

def insertStatement(connection, sql):
	try:	
		cur = connection.cursor()
		cur.execute(sql);
		connection.commit()
	except (Exception, psycopg2.DatabaseError) as error:
        	print error

def selectStatement(connection, sql):	
	result = ''	
	try:	
		cur = connection.cursor()
		cur.execute(sql);
		result = str(cur.fetchone()[0])
	except (Exception, psycopg2.DatabaseError) as error:
        	print error

	return result

def close(connection):
	"""
	Close the connection to the database
	:param connection: current database session
	:type connection: connection object
	"""
	try:	
		connection.close()
	except (Exception, psycopg2.DatabaseError) as error:
        	print error

