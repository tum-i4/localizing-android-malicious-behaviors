# WikiBooks. Algorithm Implementation/Strings/Levenshtein distance. URL: https://en.wikibooks.org/wiki/Algorithm_Implementation/Strings/Levenshtein_distance#Python (visited on 11/24/2017)

def levenshtein(s1, s2):
	"""
	Calculate the Levenshtein distance between two elements
	:param s1: first element for the comparison
	:param s2: second element for the comparison
	:type s1: list
	:type s2: list
	:return: computed distance of the two elements
	:rtype: int
	:example:

	levenshtein.levenshtein(['httpGet', 'httpPost', 'startService', 'registerReceiver'], ['httpGet', 'update', 'startService'])
	"""
	
	# ensure that s1 is bigger than s2
	if len(s1) < len(s2):
		return levenshtein(s2, s1)

	# if s2 is empty, all elements from s1 have to be added and therefore the distance will be the length of s1
	if len(s2) == 0:
		return len(s1)

	previous_row = range(len(s2) + 1)
	for i, c1 in enumerate(s1):
		current_row = [i + 1]
		for j, c2 in enumerate(s2):
			# if a new element has to be inserted, the distance increases by 1
			insertions = previous_row[j + 1] + 1 
			# if an element has to be deleted, the distance increases by 1
			deletions = current_row[j] + 1   
			# if an element has to be switched, there are two possible outcomes:
			# if the two currently regarded elements are the same the distance stays the same, otherwise it is increases by 1     
			substitutions = previous_row[j] + (c1 != c2)
			# the minimum of the three numbers is appended to the current row
			current_row.append(min(insertions, deletions, substitutions))
		previous_row = current_row
	
	# return the last element of the last row, this is the calculated levenshtein distance    
	return previous_row[-1]
