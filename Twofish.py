#========================================
# Twofish implementation in Python
# Created by: wyn-cmd
#========================================




import struct
import hashlib
import numpy as np
from math import ceil
from tqdm import tqdm  # Import tqdm for progress bars






# Utility functions
def rotate_left(val, r_bits, max_bits=32):
    # Optimized left circular rotation using bitmasking.
    mask = (1 << max_bits) - 1
    r_bits %= max_bits
    return ((val << r_bits) & mask) | ((val & mask) >> (max_bits - r_bits))


def xor_bytes(a, b):

    return (np.frombuffer(a, dtype=np.uint8) ^ np.frombuffer(b, dtype=np.uint8)).tobytes()

def bytes_to_words(data):
    # Convert 16 bytes into four 32-bit words using numpy.
    return np.frombuffer(data, dtype=">u4")


def words_to_bytes(words):
    # Convert four 32-bit words into 16 bytes using numpy.
    return np.array(words, dtype=">u4").tobytes()





# Padding and unpadding functions
def pkcs7_pad(data, block_size=16):
    # Calculate padding length and append the padding in one step.
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data, block_size=16):
    # Remove padding by checking the last byte
    pad_len = data[-1]
    return data[:-pad_len]







# Key schedule
def key_schedule(key):
    # Simplified key schedule for subkeys and S-boxes.

    # Split the key into 32-bit words
    k = np.frombuffer(key, dtype=np.uint32)  # Using numpy for efficient word conversion

    # Precompute rotation results and subkeys
    subkeys = np.zeros(40, dtype=np.uint32)  # Preallocate array for subkeys
    
    # Generate 40 subkeys (simplified version)
    for i in range(40):
        # Use moduler operations to avoid recalculating the same values
        j = i % 4
        subkeys[i] = (k[j] ^ rotate_left(k[(j + 1) % 4], i)) & 0xFFFFFFFF
    
    # Generate S-boxes
    s_boxes = k & 0xFF  # Efficient computation of S-boxes
    
    return subkeys.tolist(), s_boxes.tolist()  # Convert to list before returning (to match original return type)





# Feistel function (F)
def feistel_function(right, s_boxes, round_key):
    # Split into two 16-bit halves
    r0 = (right >> 16) & 0xFFFF
    r1 = right & 0xFFFF

    # Apply S-boxes (simplified substitution)
    r0 = s_boxes[r0 % 4]
    r1 = s_boxes[r1 % 4]

    # Combine with round key
    result = (r0 << 16 | r1) ^ round_key
    return result







# Twofish encryption
def twofish_encrypt(plaintext, key):
    # Encrypt a 128-bit block using Twofish.

    # Generate subkeys and S-boxes
    subkeys, s_boxes = key_schedule(key)

    # Split plaintext into four 32-bit words
    L0, L1, R0, R1 = bytes_to_words(plaintext)

    # Pre-whitening
    L0 ^= subkeys[0]
    L1 ^= subkeys[1]
    R0 ^= subkeys[2]
    R1 ^= subkeys[3]

    # 16 Feistel rounds
    for round in range(16):
        # Apply Feistel function to R0 and R1
        F0 = feistel_function(R0, s_boxes, subkeys[4 + round * 2])
        F1 = feistel_function(R1, s_boxes, subkeys[5 + round * 2])

        # XOR with left halves
        L0, L1, R0, R1 = R0, R1, L0 ^ F0, L1 ^ F1

    # Post-whitening
    R0 ^= subkeys[36]
    R1 ^= subkeys[37]
    L0 ^= subkeys[38]
    L1 ^= subkeys[39]

    # Combine into ciphertext
    return words_to_bytes([R0, R1, L0, L1])








# Twofish decryption
def twofish_decrypt(ciphertext, key):
    # Decrypt a 128-bit block using Twofish.

    # Generate subkeys and S-boxes
    subkeys, s_boxes = key_schedule(key)

    # Split ciphertext into four 32-bit words
    R0, R1, L0, L1 = bytes_to_words(ciphertext)

    # Post-whitening
    R0 ^= subkeys[36]
    R1 ^= subkeys[37]
    L0 ^= subkeys[38]
    L1 ^= subkeys[39]

    # 16 Feistel rounds (in reverse)
    for round in range(15, -1, -1):
        # Apply Feistel function to L0 and L1
        F0 = feistel_function(L0, s_boxes, subkeys[4 + round * 2])
        F1 = feistel_function(L1, s_boxes, subkeys[5 + round * 2])

        # XOR with right halves
        R0, R1, L0, L1 = L0, L1, R0 ^ F0, R1 ^ F1

    # Pre-whitening
    L0 ^= subkeys[0]
    L1 ^= subkeys[1]
    R0 ^= subkeys[2]
    R1 ^= subkeys[3]

    # Combine into plaintext
    return words_to_bytes([L0, L1, R0, R1])








# Twofish encryption for multiple blocks with progress bar
def twofish_encrypt_blocks(plaintext, key):
    # Encrypt data using Twofish in 16-byte blocks.
    # Pad plaintext to be a multiple of the block size
    plaintext = pkcs7_pad(plaintext, block_size=16)

    # Pre-allocate the list to hold encrypted blocks
    ciphertext_blocks = []
    num_blocks = len(plaintext) // 16

    # Encrypt each 16-byte block, using tqdm for progress tracking
    for i in tqdm(range(0, len(plaintext), 16), desc="Encrypting", total=num_blocks):
        block = plaintext[i:i+16]
        encrypted_block = twofish_encrypt(block, key)
        ciphertext_blocks.append(encrypted_block)

    # Join all encrypted blocks into a single bytes object
    ciphertext = b''.join(ciphertext_blocks)

    return ciphertext



# Twofish decryption for multiple blocks with progress bar
def twofish_decrypt_blocks(ciphertext, key):
    # Ensure ciphertext length is a multiple of the block size
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of the block size.")

    # Pre-allocate the list to hold decrypted blocks
    plaintext_blocks = []
    num_blocks = len(ciphertext) // 16

    # Decrypt each 16-byte block, using tqdm for progress tracking
    for i in tqdm(range(0, len(ciphertext), 16), desc="Decrypting", total=num_blocks):
        block = ciphertext[i:i+16]
        decrypted_block = twofish_decrypt(block, key)
        plaintext_blocks.append(decrypted_block)

    # Join all decrypted blocks into a single bytes object
    plaintext = b''.join(plaintext_blocks)

    # Remove padding from plaintext
    plaintext = pkcs7_unpad(plaintext, block_size=16)
    
    return plaintext








# Example usage
if __name__ == "__main__":
    password = input('Enter key: ')  # 16-byte key derived using an md5 hash
    plaintext = b"This is a test message for my Twofish encryption algorithmn implementation in Python.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                "

    key = hashlib.md5(password.encode()).digest()

    print("\nKey:", password)
    print("\nPlaintext:", plaintext.decode())

    ciphertext = twofish_encrypt_blocks(plaintext, key)
    print("\nCiphertext:", ciphertext.hex())

    decrypted = twofish_decrypt_blocks(ciphertext, key)
    print("\nDecrypted:", decrypted.decode())

