#Settings that can be changed
rotors = ("I","II","III")
reflector = "UKW-B"
ringSettings ="AAA"
ringPositions = "AAA" 
plugboard = "bq cr di ej kw mt os px uz gh"

print("Enigma M3 Machine")
print("")
plaintext = input("Enter text to encode or decode:\n")

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
  

#TODO: Encode Function
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
