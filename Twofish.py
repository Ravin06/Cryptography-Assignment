#========================================
# Twofish implementation in Python
# Created by: wyn-cmd
#========================================




import struct
import hashlib
from math import ceil
from tqdm import tqdm  # Import tqdm for progress bars






# Utility functions
def rotate_left(val, r_bits, max_bits=32):
    # Left circular rotation of a 32-bit integer.
    r_bits %= max_bits  # Ensure rotation count is within a valid range
    return ((val << r_bits) & (2**max_bits - 1)) | (val >> (max_bits - r_bits))

def xor_bytes(a, b):
    # XOR two byte sequences.
    return bytes(x ^ y for x, y in zip(a, b))

def bytes_to_words(data):
    # Convert 16 bytes into four 32-bit words.
    return struct.unpack(">4I", data)

def words_to_bytes(words):
    # Convert four 32-bit words into 16 bytes.
    return struct.pack(">4I", *words)




# Padding and unpadding functions
def pkcs7_pad(data, block_size=16):
    # Add PKCS7 padding to the data.
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data, block_size=16):
    # Remove PKCS7 padding from the data.
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding.")
    return data[:-pad_len]







# Key schedule
def key_schedule(key):
    # Simplified key schedule for subkeys and S-boxes.

    # Split the key into 32-bit words
    k = bytes_to_words(key)

    # Generate 40 subkeys (simplified version)
    subkeys = [(k[i % 4] ^ rotate_left(k[(i + 1) % 4], i)) & 0xFFFFFFFF for i in range(40)]

    # Generate S-boxes
    s_boxes = [k[i % 4] & 0xFF for i in range(4)]
    return subkeys, s_boxes






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

    # Encrypt each 16-byte block
    ciphertext = b""
    num_blocks = len(plaintext) // 16
    for i in tqdm(range(0, len(plaintext), 16), desc="Encrypting", total=num_blocks):
        block = plaintext[i:i+16]
        ciphertext += twofish_encrypt(block, key)

    return ciphertext



# Twofish decryption for multiple blocks with progress bar
def twofish_decrypt_blocks(ciphertext, key):
    # Decrypt data using Twofish in 16-byte blocks.
    # Ensure ciphertext length is a multiple of the block size
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of the block size.")

    # Decrypt each 16-byte block
    plaintext = b""
    num_blocks = len(ciphertext) // 16
    for i in tqdm(range(0, len(ciphertext), 16), desc="Decrypting", total=num_blocks):
        block = ciphertext[i:i+16]
        plaintext += twofish_decrypt(block, key)

    # Remove padding from plaintext
    plaintext = pkcs7_unpad(plaintext, block_size=16)
    return plaintext








# Example usage
if __name__ == "__main__":
    password = input('Enter key: ')  # 16-byte key derived using an md5 hash
    plaintext = b"This is a test message for my Twofish encryption algorithmn implementation in Python."

    key = hashlib.md5(password.encode()).digest()

    print("\nKey:", password)
    print("\nPlaintext:", plaintext.decode())

    ciphertext = twofish_encrypt_blocks(plaintext, key)
    print("\nCiphertext:", ciphertext.hex())

    decrypted = twofish_decrypt_blocks(ciphertext, key)
    print("\nDecrypted:", decrypted.decode())

