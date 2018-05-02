# localizing-android-malicious-behaviors

The lack of ground truth about malicious behaviors exhibited by current Android malware forces researchers to embark upon a
lengthy process of manually analyzing malware instances. This repository contains our initial implementation of a method to automatically localize malicious behaviors from representations of apps’ runtime behaviors. We are currently enhancing the code and adding more features to it. You can find the enhanced code under [trout-catchers](https://github.com/tum-i22/troutcatchers).

## Dependencies
The current implementation depends on the following tools:
* [ghmm](http://ghmm.org/): The General Hidden Markov Model library (GHMM) is a C library, which includes Python wrappers. It is freely available and licensed under the LGPL. With the tool we can build and train Hidden Markov Models with discrete and continuous emissions.
* [Apyori](https://pypi.python.org/pypi/apyori/1.0.0): The tool Apyori is a simple Python implementation of the Apriori algorithm.

## Workflow (User Manual) and Documentation

The module `workflow.py` includes the procedure for the proof of concept experiments and for handling real data. These two functions are called `testApproach` and `runRealData`.

* ```testApproach(pathToData, outputFolder, prob, fixedLengthArray, steps, thrEnd, support, confidence)```
  * This function obtains the needed paths to the training and testing data set as well as to the dictionary and the defined malicious behaviors by using the parameter `pathToData`.
  * The dictionary is stored in a file called ’dictionary.txt’ next to the data and includes all method names and therefore the possible observations for the Hidden Markov Model. 
  * When new benign data is used for the firsttime, the dictionary should be updated before calling this function.
  * The malicious behaviors are defined in a file named ’definedMalicious.txt’ next to the data.
  * The parameter `fixedLengthArray` includes the different lengths to which the traces should be fixed. In the next step we train the Hidden Markov Models with the training data for the specified lengths.
  * The results are stored in the folder defined by the parameter `outputFolder`.
  * In the next phase we generate malicious traces for each defined malicious behavior by using the parameter `prob` as the
insertion probability.
  * We classify these malicious traces with the trained models and for the lengths from `fixedLengthArray`.
  * For computing the metrics, we consider classification thresholds beginning from steps and incrementing in strides of steps until we reach `thrEnd`.
  * Afterwards, we try to localize each of the inserted malicious behaviors with Hidden Markov Models using the trained models.
  * The last step of this function deals with localizing malicious segments with Association Rules. Therefore, we use support and confidence as the parameters `minsup` and `minconf`, which the generated association rules have to fulfill.

* ```runRealData(pathToData, pathToMalware, outputFolder, fixedLengthArray, steps, thrEnd, support, confidence)```
  * In this function we use the parameter `pathToData` to find the dictionary with the possible observations for the Hidden Markov Model and to locate the benign training data.
  * Afterwards, we train the models with these benign traces fixed to the lengths provided in `fixedLengthArray`.
  * In the next step we classify the malicious traces that are stored in the folder `pathToMalware`.
  * We store all generated files from the operations in this function in the folder specified by the parameter `outputFolder`.
  * For different classification thresholds we compute the classification metrics specificity, recall and accuracy.
  * These thresholds range from 0 to `thrEnd` excluding 0 and increment by the parameter steps.
  * The next phase in this function focuses on the localization of malicious segments with Association Rules.
  * Therefore, we need the parameters `support` and `confidence`.
  * The last part of this function regards the localization with Hidden Markov Models that uses the trained models.

### Data Generation

The module `generateRepackagedMalware.py` handles the **generation** of repackaged malware by inserting the defined malicious behaviors into benign traces. The main function in this module is called `generate`.

* ```generate(prob, maliciousBehavior, pathToData, pathToBenignData)```
* ```checkProbabilityAndInsert(prob, benignElement, maliciousBehavior, newData, callId)```

### Classification

The **classification** process of API traces can be found in the file `classification.py`. In this module the function `train` offers the possibility to train a Hidden Markov Model and the function `computeAllLogs` can calculate the log-likelihood values of a set of sample using the trained model. This function contains the method `computeLogForOneSample`, which we can use for the computation of the log-likelihood of a single input sample.

* ```computeAllLogs(modelsArray, pathDataToClassify, outputPath, pathToDictionary, fixedLengthArray, isBenignData)```
* ```train(fixedLength, pathToGoodware, pathToDictionary)```
* ```computeLogForOneSample(model, sigma, sample)```

### Localization of Malicious Behaviors
#### Using Association Rules
The **localization** of malicious segments with Association Rules is covered by the module `localizationAssoc.py`. In this module the localization takes place in the functions `localize` and `localizeRealData` depending on which data set we use. We apply the third-party too *Apyori* to generate association rules in the function `calculateRules`. For the measurement of the method we calculate the metric `appearance` in the function `checkForMalBehavior`.

* ```localize(pathToFolder, pathToDictionary, thresholdsAndLengths, support, confidence, allMalBehaviors, expId)```
* ```localizeRealData(pathToFolder, pathToDictionary, thresholdsAndLengths, support, confidence)```
* ```calculateRules(support, confidence, pathToData)```

#### Using Hidden Markov Models

The module `localizationBrute.py` handles the localization of malevolent segments in the traces by using Hidden Markov Models. The functions `localize` and `localizeRealData` contain the main process of localization on the different kinds of data sets. We calculate these two metrics that check whether the malicious behaviors have been localized and how different is the recovered behavior from the one inserted in the API call trace in the functions `checkForBehavior` and `computeDifference`, respectively.

* ```localize(pathToLogFiles, modelsArray, pathToDictionary, thresholdsAndLengths, minLengthBlocks, malBehavior, expId, malBehaviorNumber)```
* ```localizeRealData(pathToLogFiles, modelsArray, pathToDictionary, thresholdsAndLengths, minLengthBlocks)```
* ```computeDifference(entry, malBehavior)```
* ```checkForBehavior(calls, malBehavior)```

## Citation and Contact

For more information about the design and implementation of the tool, please refer to the paper cited below. Kindly consider citing our GoldRusher paper, if you find it useful in your research.

```
Coming Soon
```

We are constantly updating the source code and its corresponding documentation. However, should you have any inquiries about installing and using the code, please contact us:

Alei Salem (salem@in.tum.de) and Tabea Schmidt (tabea.schmidt@tum.de)
