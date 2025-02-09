
#========================================
# base-16 implementation of Enigma in Python
# Based off of enigma.py
# Created by: wyn-cmd
#========================================


# Settings that can be changed
rotors = ("I", "II", "III")
reflector = "UKW-B"
ringSettings = "000"  # Changed to valid hex characters (0-9, a-f)
ringPositions = "000"  # Same as above
plugboard = "01 23 45 67 89 ab cd ef"  # Plugboard for hexadecimal pairs

# 16-character alphabet (instead of the original 26-character alphabet)
alphabet = "0123456789abcdef"

# Caesar shift for rotor settings based on the ring settings of the Enigma machine
def caesarShift(text, shift_amount):
    shifted_text = ""
    for char in text:
        char_code = alphabet.index(char)
        new_char = alphabet[(char_code + shift_amount) % 16]
        shifted_text += new_char
    return shifted_text

def encode(plaintext):
    global rotors, reflector, ringSettings, ringPositions, plugboard

    # Rotor settings for 16-letter alphabet (each rotor wiring maps characters in the 16-char alphabet)
    rotors_map = {
        'I': ('0123456789abcdef', 'a'),
        'II': ('89abcdef01234567', 'f'),
        'III': ('abcdef0123456789', 'b'),
        'IV': ('fedcba9876543210', 'd'),
        'V': ('0123456789abcdef', 'a')
    }

    # Extract rotor wirings and notches
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

    # Reflector for 16-letter alphabet
    reflectorB = {
        '0': 'f', '1': 'a', '2': 'e', '3': 'b', '4': 'd', '5': 'c',
        '6': '9', '7': '8', '8': '7', '9': '6', 'a': '1', 'b': '3',
        'c': '5', 'd': '4', 'e': '2', 'f': '0'
    }

    # A = Left, B = Mid, C = Right
    rotorA = rotorDict[rotors[0]]
    rotorB = rotorDict[rotors[1]]
    rotorC = rotorDict[rotors[2]]
    rotorANotch = rotorNotchDict[rotors[0]]
    rotorBNotch = rotorNotchDict[rotors[1]]
    rotorCNotch = rotorNotchDict[rotors[2]]

    # Set initial rotor positions
    rotorALetter = ringPositions[0]
    rotorBLetter = ringPositions[1]
    rotorCLetter = ringPositions[2]

    # Apply ring settings
    rotorASetting = ringSettings[0]
    rotorBSetting = ringSettings[1]
    rotorCSetting = ringSettings[2]

    # Ensure ringSettings values are within the allowed alphabet range (0-9, a-f)
    if rotorASetting not in alphabet or rotorBSetting not in alphabet or rotorCSetting not in alphabet:
        raise ValueError(f"Invalid ring setting. Must be one of {alphabet}")

    offsetASetting = alphabet.index(rotorASetting)
    offsetBSetting = alphabet.index(rotorBSetting)
    offsetCSetting = alphabet.index(rotorCSetting)

    rotorA = caesarShift(rotorA, offsetASetting)
    rotorB = caesarShift(rotorB, offsetBSetting)
    rotorC = caesarShift(rotorC, offsetCSetting)

    # Setup plugboard
    plugboardConnections = plugboard.upper().split(" ")
    plugboardDict = {}
    for pair in plugboardConnections:
        if len(pair) == 2:
            plugboardDict[pair[0]] = pair[1]
            plugboardDict[pair[1]] = pair[0]

    # Process text
    ciphertext = ""
    plaintext = plaintext.lower()

    for letter in plaintext:
        encryptedLetter = letter

        if letter in alphabet:
            # Rotate rotors
            rotorTrigger = False

            # Third rotor rotates by 1 for every key press
            if rotorCLetter == rotorCNotch:
                rotorTrigger = True
            rotorCLetter = alphabet[(alphabet.index(rotorCLetter) + 1) % 16]

            # Check if rotorB needs to rotate
            if rotorTrigger:
                rotorTrigger = False
                if rotorBLetter == rotorBNotch:
                    rotorTrigger = True
                rotorBLetter = alphabet[(alphabet.index(rotorBLetter) + 1) % 16]

                # Check if rotorA needs to rotate
                if rotorTrigger:
                    rotorTrigger = False
                    rotorALetter = alphabet[(alphabet.index(rotorALetter) + 1) % 16]
            else:
                # Check for double-step sequence
                if rotorBLetter == rotorBNotch:
                    rotorBLetter = alphabet[(alphabet.index(rotorBLetter) + 1) % 16]
                    rotorALetter = alphabet[(alphabet.index(rotorALetter) + 1) % 16]

            # First pass through plugboard
            if letter in plugboardDict.keys():
                if plugboardDict[letter] != "":
                    encryptedLetter = plugboardDict[letter]

            # Get rotor offsets
            offsetA = alphabet.index(rotorALetter)
            offsetB = alphabet.index(rotorBLetter)
            offsetC = alphabet.index(rotorCLetter)

            # Forward through rotors
            pos = alphabet.index(encryptedLetter)
            let = rotorC[(pos + offsetC) % 16]
            pos = alphabet.index(let)
            encryptedLetter = alphabet[(pos - offsetC + 16) % 16]

            pos = alphabet.index(encryptedLetter)
            let = rotorB[(pos + offsetB) % 16]
            pos = alphabet.index(let)
            encryptedLetter = alphabet[(pos - offsetB + 16) % 16]

            pos = alphabet.index(encryptedLetter)
            let = rotorA[(pos + offsetA) % 16]
            pos = alphabet.index(let)
            encryptedLetter = alphabet[(pos - offsetA + 16) % 16]

            # Through reflector
            if encryptedLetter in reflectorB.keys():
                if reflectorB[encryptedLetter] != "":
                    encryptedLetter = reflectorB[encryptedLetter]

            # Backward through rotors
            pos = alphabet.index(encryptedLetter)
            let = alphabet[(pos + offsetA) % 16]
            pos = rotorA.index(let)
            encryptedLetter = alphabet[(pos - offsetA + 16) % 16]

            pos = alphabet.index(encryptedLetter)
            let = alphabet[(pos + offsetB) % 16]
            pos = rotorB.index(let)
            encryptedLetter = alphabet[(pos - offsetB + 16) % 16]

            pos = alphabet.index(encryptedLetter)
            let = alphabet[(pos + offsetC) % 16]
            pos = rotorC.index(let)
            encryptedLetter = alphabet[(pos - offsetC + 16) % 16]

            # Second pass through plugboard
            if encryptedLetter in plugboardDict.keys():
                if plugboardDict[encryptedLetter] != "":
                    encryptedLetter = plugboardDict[encryptedLetter]

        ciphertext += encryptedLetter

    return ciphertext

# Example Usage
if __name__ == "__main__":
    print("Enigma M3 Machine for Hexadecimal (Base16)")
    plaintext = input("Enter text to encode or decode (hexadecimal 0-9, a-f):\n")
    ciphertext = encode(plaintext.lower())  # Ensure input is lowercase for consistency
    print("\nEncoded text:\n" + ciphertext)
