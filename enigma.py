#Settings that can be changed
rotors = ("I","II","III")
reflector = "UKW-B"
ringSettings ="AAA"
ringPositions = "AAA" 
plugboard = "bq cr di ej kw mt os px uz gh"

#Caesar shift for rotor settings based on the ring settings of the Enigma machine
def caesarShift(text, shift_amount):
    shifted_text = ""
    for char in text:
        char_code = ord(char)
        if 65 <= char_code <= 90:  # Check if the character is uppercase
            new_char = chr(((char_code - 65 + shift_amount) % 26) + 65)
        else:
            new_char = char  # Non-alphabetic characters remain unchanged
        shifted_text += new_char
    return shifted_text
  
def encode(plaintext):
  #rotors
  rotors = {
    'I': ('EKMFLGDQVZNTOWYHXUSPAIBRCJ', 'Q'),
    'II': ('AJDKSIRUXBLHWTMCQGZNPYFVOE', 'E'),
    'III': ('BDFHJLCPRTXVZNYEIWGAKMUSQO', 'V'),
    'IV': ('ESOVPZJAYQUIRHXLNFTGKDCMWB', 'J'),
    'V': ('VZBRGITYUPSDNHLXAWMJQOFECK', 'Z')
  }
  #only using reflector B for this demo
  reflectorB = {"A":"Y","Y":"A","B":"R","R":"B","C":"U","U":"C","D":"H","H":"D","E":"Q","Q":"E","F":"S","S":"F","G":"L","L":"G","I":"P","P":"I","J":"X","X":"J","K":"N","N":"K","M":"O","O":"M","T":"Z","Z":"T","V":"W","W":"V"}

  alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  rotorANotch = False
  rotorBNotch = False
  rotorCNotch = False

def encode(plaintext):
    global rotors, reflector, ringSettings, ringPositions, plugboard
    
    #Rotors
    rotors_map = {
        'I': ('EKMFLGDQVZNTOWYHXUSPAIBRCJ', 'Q'),
        'II': ('AJDKSIRUXBLHWTMCQGZNPYFVOE', 'E'),
        'III': ('BDFHJLCPRTXVZNYEIWGAKMUSQO', 'V'),
        'IV': ('ESOVPZJAYQUIRHXLNFTGKDCMWB', 'J'),
        'V': ('VZBRGITYUPSDNHLXAWMJQOFECK', 'Z')
    }

    #Extract rotor wirings and notches
    rotorDict = {
        'I': rotors_map['I'][0],
        'II': rotors_map['II'][0],
        'III': rotors_map['III'][0],
        'IV': rotors_map['IV'][0],
        'V': rotors_map['V'][0]
    }
    rotorNotchDict = {
        'I': rotors_map['I'][1],
        'II': rotors_map['II'][1],
        'III': rotors_map['III'][1],
        'IV': rotors_map['IV'][1],
        'V': rotors_map['V'][1]
    }

    #only using reflector B for this demo
    reflectorB = {"A":"Y","Y":"A","B":"R","R":"B","C":"U","U":"C","D":"H","H":"D",
                  "E":"Q","Q":"E","F":"S","S":"F","G":"L","L":"G","I":"P","P":"I",
                  "J":"X","X":"J","K":"N","N":"K","M":"O","O":"M","T":"Z","Z":"T",
                  "V":"W","W":"V"}

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    #A = Left, B = Mid, C = Right
    rotorA = rotorDict[rotors[0]]
    rotorB = rotorDict[rotors[1]]
    rotorC = rotorDict[rotors[2]]
    rotorANotch = rotorNotchDict[rotors[0]]
    rotorBNotch = rotorNotchDict[rotors[1]]
    rotorCNotch = rotorNotchDict[rotors[2]]

    #Set initial rotor positions
    rotorALetter = ringPositions[0]
    rotorBLetter = ringPositions[1]
    rotorCLetter = ringPositions[2]

    #Apply ring settings
    rotorASetting = ringSettings[0]
    rotorBSetting = ringSettings[1]
    rotorCSetting = ringSettings[2]
    
    offsetASetting = alphabet.index(rotorASetting)
    offsetBSetting = alphabet.index(rotorBSetting)
    offsetCSetting = alphabet.index(rotorCSetting)

    rotorA = caesarShift(rotorA, offsetASetting)
    rotorB = caesarShift(rotorB, offsetBSetting)
    rotorC = caesarShift(rotorC, offsetCSetting)

    if offsetASetting > 0:
        rotorA = rotorA[26-offsetASetting:] + rotorA[0:26-offsetASetting]
    if offsetBSetting > 0:
        rotorB = rotorB[26-offsetBSetting:] + rotorB[0:26-offsetBSetting]
    if offsetCSetting > 0:
        rotorC = rotorC[26-offsetCSetting:] + rotorC[0:26-offsetCSetting]

    #Setup plugboard
    plugboardConnections = plugboard.upper().split(" ")
    plugboardDict = {}
    for pair in plugboardConnections:
        if len(pair) == 2:
            plugboardDict[pair[0]] = pair[1]
            plugboardDict[pair[1]] = pair[0]

    #Process text
    ciphertext = ""
    plaintext = plaintext.upper()

    for letter in plaintext:
        encryptedLetter = letter

        if letter in alphabet:
            #Rotate rotors
            rotorTrigger = False
            
            #Third rotor rotates by 1 for every key press
            if rotorCLetter == rotorCNotch:
                rotorTrigger = True
            rotorCLetter = alphabet[(alphabet.index(rotorCLetter) + 1) % 26]
            
            #Check if rotorB needs to rotate
            if rotorTrigger:
                rotorTrigger = False
                if rotorBLetter == rotorBNotch:
                    rotorTrigger = True
                rotorBLetter = alphabet[(alphabet.index(rotorBLetter) + 1) % 26]

                #Check if rotorA needs to rotate
                if rotorTrigger:
                    rotorTrigger = False
                    rotorALetter = alphabet[(alphabet.index(rotorALetter) + 1) % 26]
            else:
                #Check for double step sequence
                if rotorBLetter == rotorBNotch:
                    rotorBLetter = alphabet[(alphabet.index(rotorBLetter) + 1) % 26]
                    rotorALetter = alphabet[(alphabet.index(rotorALetter) + 1) % 26]

            #First pass through plugboard
            if letter in plugboardDict.keys():
                if plugboardDict[letter] != "":
                    encryptedLetter = plugboardDict[letter]

            #Get rotor offsets
            offsetA = alphabet.index(rotorALetter)
            offsetB = alphabet.index(rotorBLetter)
            offsetC = alphabet.index(rotorCLetter)

            #Forward through rotors
            #Wheel 3
            pos = alphabet.index(encryptedLetter)
            let = rotorC[(pos + offsetC) % 26]
            pos = alphabet.index(let)
            encryptedLetter = alphabet[(pos - offsetC + 26) % 26]

            #Wheel 2
            pos = alphabet.index(encryptedLetter)
            let = rotorB[(pos + offsetB) % 26]
            pos = alphabet.index(let)
            encryptedLetter = alphabet[(pos - offsetB + 26) % 26]

            #Wheel 1
            pos = alphabet.index(encryptedLetter)
            let = rotorA[(pos + offsetA) % 26]
            pos = alphabet.index(let)
            encryptedLetter = alphabet[(pos - offsetA + 26) % 26]

            #Through reflector
            if encryptedLetter in reflectorB.keys():
                if reflectorB[encryptedLetter] != "":
                    encryptedLetter = reflectorB[encryptedLetter]

            #Backward through rotors
            #Wheel 1
            pos = alphabet.index(encryptedLetter)
            let = alphabet[(pos + offsetA) % 26]
            pos = rotorA.index(let)
            encryptedLetter = alphabet[(pos - offsetA + 26) % 26]

            #Wheel 2
            pos = alphabet.index(encryptedLetter)
            let = alphabet[(pos + offsetB) % 26]
            pos = rotorB.index(let)
            encryptedLetter = alphabet[(pos - offsetB + 26) % 26]

            #Wheel 3
            pos = alphabet.index(encryptedLetter)
            let = alphabet[(pos + offsetC) % 26]
            pos = rotorC.index(let)
            encryptedLetter = alphabet[(pos - offsetC + 26) % 26]

            #Second pass through plugboard
            if encryptedLetter in plugboardDict.keys():
                if plugboardDict[encryptedLetter] != "":
                    encryptedLetter = plugboardDict[encryptedLetter]

        ciphertext = ciphertext + encryptedLetter

    return ciphertext

if __name__ == "__main__":
    print("Enigma M3 Machine")
    print("")
    plaintext = input("Enter text to encode or decode:\n")
    ciphertext = encode(plaintext)
    print("\nEncoded text:\n" + ciphertext)
