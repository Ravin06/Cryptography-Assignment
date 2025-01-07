import random, array

''' References:
- http://www.crypto-it.net/eng/symmetric/rc2.html
- https://people.csail.mit.edu/rivest/pubs/KRRR98.pdf
- https://www.rfc-editor.org/rfc/rfc2268    
- https://www.cryptrec.go.jp/exreport/cryptrec-ex-1042-2001.pdf
- https://datatracker.ietf.org/doc/draft-rivest-rc2desc/00/
- https://www.geeksforgeeks.org/block-cipher-modes-of-operation/
- https://www.rfc-editor.org/rfc/rfc8018#appendix-B.2.3

Reference code:
- https://github.com/0xEBFE/RC2-python
'''

#---------------------
BLOCK_SIZE = 8
MODE_ECB = 0
MODE_CBC = 1
PADDING_PKCS5 = 1
#---------------------
'''
MODE_CBC(Cipher Block Chaining) : 
    - variable key length from 1 - 128 bytes
    - seperate effective key bits from 1 - 1024 bits that limits
    the effective search space independent of the key length and 
    an 8 byte 
    Parameters : 
        - Initalisation vector of 8 bytes
        - Version number in the range 1 - 1024 which specifies 
        in a roundabout manner the number of effective key bits
        to be used for the RC2 encryption/ decryption

        The correspondence between effective key bits and version number is
   as follows:

   1. If the number EKB of effective key bits is in the range 1-255,
      then the version number is given by Table[EKB], where the 256-byte
      translation table Table[] is specified below. Table[] specifies a
      permutation on the numbers 0-255; note that it is not the same
      table that appears in the key expansion phase of RC2.

   2. If the number EKB of effective key bits is in the range
      256-1024, then the version number is simply EKB.

      The default number of effective key bits for RC2 is 32. If RC2-CBC
      is being performed with 32 effective key bits, the parameters
      should be supplied as a simple IV, rather than as a SEQUENCE
      containing a version and an IV.


MODE_ECB : - Electronic Code Book - a block cipher mode that divides the message into 
equal sized blocks, encrypted and then concatenated

'''

# RC2 Characteristics
# Block Lnegth = 8 bytes (64 bits)
# Key Length = 1 - 128 bytes

class RC2():

    def __init__(self,key):
        

        self.key = key
        self.ks = len(self.key)

        # kBit : key bit limit - determines maximum effective key size in bits
        # kByte : key byte limit = (kBit + 7) / 8
        # kMask : to ensure only that many bytes will be used
        self.kBit = 128
        self.kByte = (self.kBit + 7) // 8
        self.kMask = 255%(2**(8+self.kBit - 8*self.kByte))

        ''' 
        tPl : Table PL - a fixed array that contains 256 elements,
        using during key expansion operations. It is filled with numbers 
        which are a random permutations of all possible byte values
        from 0 to 255. Order of numbers is based on the digits of pi
        '''

        tPl = [0xD9, 0x78, 0xF9, 0xC4, 0x19, 0xDD, 0xB5, 0xED, 0x28, 0xE9, 0xFD, 0x79, 0x4A, 0xA0, 0xD8, 0x9D,
            0xC6, 0x7E, 0x37, 0x83, 0x2B, 0x76, 0x53, 0x8E, 0x62, 0x4C, 0x64, 0x88, 0x44, 0x8B, 0xFB, 0xA2,
            0x17, 0x9A, 0x59, 0xF5, 0x87, 0xB3, 0x4F, 0x13, 0x61, 0x45, 0x6D, 0x8D, 0x09, 0x81, 0x7D, 0x32,
            0xBD, 0x8F, 0x40, 0xEB, 0x86, 0xB7, 0x7B, 0x0B, 0xF0, 0x95, 0x21, 0x22, 0x5C, 0x6B, 0x4E, 0x82,
            0x54, 0xD6, 0x65, 0x93, 0xCE, 0x60, 0xB2, 0x1C, 0x73, 0x56, 0xC0, 0x14, 0xA7, 0x8C, 0xF1, 0xDC,
            0x12, 0x75, 0xCA, 0x1F, 0x3B, 0xBE, 0xE4, 0xD1, 0x42, 0x3D, 0xD4, 0x30, 0xA3, 0x3C, 0xB6, 0x26,
            0x6F, 0xBF, 0x0E, 0xDA, 0x46, 0x69, 0x07, 0x57, 0x27, 0xF2, 0x1D, 0x9B, 0xBC, 0x94, 0x43, 0x03,
            0xF8, 0x11, 0xC7, 0xF6, 0x90, 0xEF, 0x3E, 0xE7, 0x06, 0xC3, 0xD5, 0x2F, 0xC8, 0x66, 0x1E, 0xD7,
            0x08, 0xE8, 0xEA, 0xDE, 0x80, 0x52, 0xEE, 0xF7, 0x84, 0xAA, 0x72, 0xAC, 0x35, 0x4D, 0x6A, 0x2A,
            0x96, 0x1A, 0xD2, 0x71, 0x5A, 0x15, 0x49, 0x74, 0x4B, 0x9F, 0xD0, 0x5E, 0x04, 0x18, 0xA4, 0xEC,
            0xC2, 0xE0, 0x41, 0x6E, 0x0F, 0x51, 0xCB, 0xCC, 0x24, 0x91, 0xAF, 0x50, 0xA1, 0xF4, 0x70, 0x39,
            0x99, 0x7C, 0x3A, 0x85, 0x23, 0xB8, 0xB4, 0x7A, 0xFC, 0x02, 0x36, 0x5B, 0x25, 0x55, 0x97, 0x31,
            0x2D, 0x5D, 0xFA, 0x98, 0xE3, 0x8A, 0x92, 0xAE, 0x05, 0xDF, 0x29, 0x10, 0x67, 0x6C, 0xBA, 0xC9,
            0xD3, 0x00, 0xE6, 0xCF, 0xE1, 0x9E, 0xA8, 0x2C, 0x63, 0x16, 0x01, 0x3F, 0x58, 0xE2, 0x89, 0xA9,
            0x0D, 0x38, 0x34, 0x1B, 0xAB, 0x33, 0xFF, 0xB0, 0xBB, 0x48, 0x0C, 0x5F, 0xB9, 0xB1, 0xCD, 0x2E,
            0xC5, 0xF3, 0xDB, 0x47, 0xE5, 0xA5, 0x9C, 0x77, 0x0A, 0xA6, 0x20, 0x68, 0xFE, 0x7F, 0xC1, 0xAD]
        
        # self.L : array of length 128 with single byte
        self.L = bytearray(128)
        for i in range(self.ks): self.L[i] = self.key[i]

        # Steps performed on key

        # Step 1 : Expand the key to a full 128 bytes, using non-linear
        # byte wide shift register approach

        for i in range(self.ks, 128, 1):

            self.L[i] = tPl[ (self.L[i - 1] + self.L[i - self.ks]) %256]

        # Step 2 : Set value of last element in array
        self.L[128 - self.kByte] = tPl[ self.L[128 - self.kByte] & self.kMask]

        # Step 3 : Change value of byte using tPl and XOR operation

        for i in range(127-self.ks,-1,-1):
            self.L[i] = tPl[ (self.L[i+1] ^ self.L[i + self.ks]) & 0xff]
 

        # self.K : array of whole words 
        self.K = [self.L[a*2] + 256 * self.L[2*a + 1] for a in range(64)]

    def ROL16(self, a, b):
        # add bits of length s[i] to the end of the number 
        return ((a << b) | (a >> (16 - b)) )&0xffff
    
    def ROR16(self, r, s):
        # remove bits of length s[i] at the end of the number
        return ((r >> s) | (r << (16 - s)))&0xffff

    def mix(self,R,round):

        j = round*4
        s = [1,2,3,5]

        for i in range(4):
            # (self.R[(i+2) % 4] & self.R[(i+3) % 4]) : performs and operation with
            # the third and 4th item infront 

            R[i] = (R[i] + self.K[j] + (R[(i+2) % 4] & R[(i+3) % 4])+\
                (~R[(i+3) % 4] & R[(i+1) % 4])) & 0xffff
            
            # add bits of length s[i] to the end of the number 
            R[i] = self.ROL16(R[i], s[i])
            
            j+=1

        return R
    
    def reverse_mix(self,R,round):

        j = round * 4 + 3
        s = [1,2,3,5]

        for i in range(3,-1,-1):
            # (self.R[(i+2) % 4] & self.R[(i+3) % 4]) : performs and operation with
            # the third and 4th item infront 
            R[i] = self.ROR16(R[i], s[i])

            R[i] = (R[i] - self.K[j] - \
                ((R[(i+2) % 4]) & (R[(i+3) % 4])) - \
                ((~R[(i+3) % 4]) & (R[(i+1) % 4]))\
                ) & 0xffff
            
            # add bits of length s[i] to the end of the number 
            j-=1

        return R
    
    def mash(self,R):

        for i in range(4):
            # self.K[self.R[(i+3) % 4] & 63] : takes the previous item and use it
            # to index value in key 
            R[i] = (R[i] + self.K[R[(i+3) % 4] & 63]) & 0xffff

        return R 
    
    def reverse_mash(self,R):

        for i in range(3,-1,-1):
            # self.K[self.R[(i+3) % 4] & 63] : takes the previous item and use it
            # to index value in key 
            R[i] = (R[i] - self.K[R[(i+3) % 4] & 63]) & 0xffff

        return R 
    
    def block_enc(self, input_buffer):

        R = array.array('H')
        R.frombytes(input_buffer)

        # 5 rounds of mixing
        R = self.mix(R, 0)
        R = self.mix(R, 1)
        R = self.mix(R, 2)
        R = self.mix(R, 3)
        R = self.mix(R, 4)

        # 1 round of mashing
        R = self.mash(R)

        # 6 rounds of mixing
        R = self.mix(R, 5)
        R = self.mix(R, 6)
        R = self.mix(R, 7)
        R = self.mix(R, 8)
        R = self.mix(R, 9)
        R = self.mix(R, 10)

        # 1 round of mashing
        R = self.mash(R)

        # 5 rounds of mixing
        R = self.mix(R, 11)
        R = self.mix(R, 12)
        R = self.mix(R, 13)
        R = self.mix(R, 14)
        R = self.mix(R, 15)

        return R.tobytes()
    
    def block_dec(self,input_buffer):

        R = array.array('H')
        R.frombytes(input_buffer)

        # 5 rounds of reverse mixing
        R = self.reverse_mix(R, 15)
        R = self.reverse_mix(R, 14)
        R = self.reverse_mix(R, 13)
        R = self.reverse_mix(R, 12)
        R = self.reverse_mix(R, 11)

        # 1 round of reverse mashing
        R = self.reverse_mash(R)

        # 6 rounds of reverse mixing
        R = self.reverse_mix(R, 10)
        R = self.reverse_mix(R, 9)
        R = self.reverse_mix(R, 8)
        R = self.reverse_mix(R, 7)
        R = self.reverse_mix(R, 6)
        R = self.reverse_mix(R, 5)

        # 1 round of reversemashing
        R = self.reverse_mash(R)

        # 5 rounds of reverse mixing
        R = self.reverse_mix(R, 4)
        R = self.reverse_mix(R, 3)
        R = self.reverse_mix(R, 2)
        R = self.reverse_mix(R, 1)
        R = self.reverse_mix(R, 0)
        

        return R.tobytes()
    
    def encrypt(self, plain_text, mode, IV = None, padding = None):
        # IV : Initialisation Vector is an 8 byte array in which the 

        # check if length is multiple of 8 (ie block size)
        # as well as if padding is present
        enc_size = len(plain_text)

        if (enc_size % BLOCK_SIZE) == 0 and padding != None:
            enc_size = enc_size
        else: 
            enc_size = ((enc_size // BLOCK_SIZE) + 1) * BLOCK_SIZE
        
        # Array of length enc_size
        enc_buffer = bytearray(enc_size)

        # Filling the buffer with plaintext, else add padding

        for i in range(enc_size):

            if len(plain_text) > i:

                enc_buffer[i] = plain_text[i]
            elif padding == PADDING_PKCS5:
                enc_buffer[i] = (BLOCK_SIZE - (len(plain_text) % BLOCK_SIZE)) & 0xFF
        
        # encrypting the plain_text in blocks

        result = bytearray()

        for block_count in range(enc_size // BLOCK_SIZE):

            block = enc_buffer[block_count * BLOCK_SIZE : (block_count + 1) * BLOCK_SIZE ]

            if block_count == 0:
                if mode == MODE_CBC and IV is not None:
                    for i in range(BLOCK_SIZE):
                        block[i] = block[i] ^ IV[i]

            else:
                if mode == MODE_CBC:
                    for i in range(BLOCK_SIZE):
                        # performs XOR operation
                        block[i] = block[i] ^ block_result[i]
            
            block_result = self.block_enc(block)

            result += block_result

        return result
    
    def decrypt(self, cipher_text, mode, IV = None, padding = None):

        decode_size = len(cipher_text)
        decode_buffer = bytearray(decode_size)

        for i in range(decode_size):

            decode_buffer[i] = cipher_text[i]
        
        for block_count in range(decode_size//BLOCK_SIZE):

            block =  decode_buffer[block_count * BLOCK_SIZE : block_count * BLOCK_SIZE + BLOCK_SIZE]
            block_result = self.block_dec(block)
            
            if mode == MODE_CBC:
                if block_count == 0:
                    if IV is not None:
                        for i in range(BLOCK_SIZE):
                            decode_buffer[block_count * BLOCK_SIZE + i] = block_result[i] ^ IV[i]
                    else:
                        for i in range(BLOCK_SIZE):
                            decode_buffer[block_count * BLOCK_SIZE + i] = block_result[i]
                else:
                    for i in range(BLOCK_SIZE):
                        decode_buffer[block_count * BLOCK_SIZE + i] = block_result[i] ^ previous_block[i]
            else:
                for i in range(BLOCK_SIZE):
                    decode_buffer[block_count * BLOCK_SIZE + i] = block_result[i]
            
            previous_block = block

        if padding == PADDING_PKCS5:
            decode_buffer = decode_buffer[:-decode_buffer[decode_size - 1]]

        return decode_buffer
    
def check():

    a = bytearray('test', 'ascii')
    b = RC2(a)
    message = bytearray('hell', 'utf-8')
    enc_1 = [ x for x in b.encrypt(message,MODE_ECB) ]
    dec_1 = [ z for z in b.decrypt(bytearray(enc_1), MODE_ECB)]


    # enc_2 = b.encrypt(message, MODE_ECB)
    # dec_2 = b.decrypt(enc_1,MODE_ECB)
    
    print(enc_1)
    print(''.join( chr(k) for k in dec_1))

check()


