import math

encrypted = open(encryptedFile).read().replace("\n", "")
alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'


def decrypt(characterMatrix, key):
    decrypted = ""
    for col in range(len(characterMatrix[0])):
        for row in range(len(characterMatrix)):
            if col == len(characterMatrix[row]):
                break
            else:
                decrypted += alphabet[(alphabet.index(characterMatrix[row][col]) - alphabet.index(key[row])) % len(alphabet)]
    return decrypted

def write(decrypted, key):
    with open("key = " + key + ".txt", 'w') as f:
        f.write(decrypted)

def decryptUsingKey(key): # decrypts, assuming key was used to encrypt
    characterMatrix = [[] for _ in range(len(key))]
    characterMatrix, _ = read(encrypted, len(key))
    decrypted = decrypt(characterMatrix, key)
    write(decrypted, key)

def calculateICs(text):
    keylenToCoincidence = {}
    for keylen in range(10, 51):
        distributionMatrix = [{} for _ in range(keylen)]

        for pos, char in enumerate(text): #for each group encrypted using the same part of the key, determine each letters frequency
            index = pos % keylen
            if char in distributionMatrix[index]:
                distributionMatrix[index][char] += 1
            else: 
                distributionMatrix[index][char] = 1
        
        coincidence = 0
        for index in range(keylen): #calculate IOC
            sum = 0
            for value in distributionMatrix[index].values():
                sum += value
            for value in distributionMatrix[index].values():
                coincidence += (value * (value-1)) / (sum * (sum-1)) 
        coincidence = coincidence / keylen # average IOC among the groups
        keylenToCoincidence[keylen] = coincidence
    return keylenToCoincidence          


def guessKeylength(coincidenceList):
    guess = min(coincidenceList, key=lambda k: abs(coincidenceList[k] - 0.068)) #returns keylength with IOC closest to expectation
    return guess

def read(text, keylength):
    characterMatrix = [[] for _ in range(keylength)]
    distributionMatrix = [{} for _ in range(keylength)]
    for pos, char in enumerate(text):
        index = pos % keylength
        if char in distributionMatrix[index]:
            distributionMatrix[index][char] += 1
        else: 
            distributionMatrix[index][char] = 1
        characterMatrix[index].append(char)
    return characterMatrix, distributionMatrix

def expected(length):
    base =  {
        "A": 0.082,
        "B": 0.015,
        "C": 0.028,
        "D": 0.043,
        "E": 0.127,
        "F": 0.022,
        "G": 0.02,
        "H": 0.061,
        "I": 0.07,
        "J": 0.0015,
        "K": 0.0077,
        "L": 0.04,
        "M": 0.024,
        "N": 0.067,
        "O": 0.075,
        "P": 0.019,
        "Q": 0.00095,
        "R": 0.06,
        "S": 0.063,
        "T": 0.091,
        "U": 0.028,
        "V": 0.0098,
        "W": 0.024,
        "X": 0.0015,
        "Y": 0.02,
        "Z": 0.00074
    }

    expected = {}
    for key, value in base.items():
        expected[key] = value * length

    return expected

def decryptDistribution(distribution, key):
    decryptedDistribution = {}
    for letter, occurences in distribution.items():
        decryptedDistribution[alphabet[(alphabet.index(letter) - key) % 26]] = occurences
    return decryptedDistribution


def guessPartOfKey(distribution, textlength):
    expectedDistribution = expected(textlength) #returns expected frequencies for each letter
    chiSquaredScores = []
    for key in range(len(alphabet)): 
        decryptedDistribution = decryptDistribution(distribution, key) #assuming key was the actual key, calculate the supposedly decrypted letter frequencies
        normalizedSquaredErrorDistribution = {}
        for char, occurences in expectedDistribution.items():
             normalizedSquaredErrorDistribution[char] = math.pow(decryptedDistribution.get(char, 0) - occurences,2) / occurences  #calculate each letter's frequencies Chi^2 normalized deviation compared to expected distribution
        
        chiSquaredScore = 0
        for value in normalizedSquaredErrorDistribution.values(): #calculate total Chi^2 normalized deviation from expected
            chiSquaredScore += value 
        chiSquaredScores.append(chiSquaredScore)
    
    bestScore = chiSquaredScores.index(min(chiSquaredScores)) #determine key with best (= lowest) Chi^2 normalized score
    key = alphabet[bestScore] 

    return key



coincidences = calculateICs(encrypted) # calculates index of coincidence for each possible keylength
keylength = guessKeylength(coincidences) # returns keylength with index of coincidence closest to expected
characterMatrix, distributionMatrix = read(encrypted, keylength) # reads encrypted text into groups that were encrypted using the same key. Also keeps track of letter frequencies
key = ""
for i in range(keylength):
    key += guessPartOfKey(distributionMatrix[i], len(characterMatrix[i])) #concatenates key used to encrypt the i-th group of letters to current key

print("Key :" + key)

#decryptUsingKey(key) writes decrypted file into current directory
