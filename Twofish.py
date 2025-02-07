#========================================
# Twofish implementation in Python
# Created by: wyn-cmd
#========================================




import struct
import hashlib
import numpy as np
from math import ceil
from tqdm import tqdm  # Import tqdm for progress bars





# Full S-boxes for 16-bit substitution
S_box_0 = [
    0x32C0, 0xDE9A, 0x9A54, 0x8F01, 0xB6A1, 0x85A0, 0x4D9F, 0x7D5B,
    0x3203, 0x6A94, 0x9C92, 0x4823, 0x1F07, 0x7034, 0xF4B2, 0x5EC3,
    0xB132, 0xD9A7, 0x56D7, 0x8B92, 0xD752, 0x6BC4, 0x1E91, 0x50F5,
    0x5D6A, 0x123D, 0xC7D6, 0x5037, 0x9A0C, 0x7840, 0x2198, 0x87B3,
    0x79EC, 0x0F23, 0x67E3, 0x4B3C, 0x950D, 0xB7C7, 0x8E48, 0x16F0,
    0xD2A4, 0x5F15, 0xE12C, 0x4A19, 0xDB62, 0x7D12, 0x1F84, 0x3C77,
    0x9C44, 0xCD5D, 0x2C77, 0x34A9, 0x93C8, 0xB455, 0x6F20, 0x4F1C,
    0x6639, 0x00E6, 0x2076, 0x3B9E, 0x51D8, 0xDF5B, 0x7054, 0x9D83,
    0x3FB1, 0x26F5, 0x5A88, 0x42A9, 0xBB3F, 0xDB28, 0x3D62, 0x7024,
    0x4B6C, 0x2E91, 0xE0B5, 0x159D, 0x220B, 0x7910, 0xE913, 0xF9C0,
    0xED63, 0x78E4, 0x6A9A, 0xC45E, 0xD8B9, 0xA5D6, 0xE4D0, 0xB214,
    0xC593, 0x9835, 0x6B57, 0x3C3E, 0xD59F, 0xB0EC, 0xACD7, 0x01D9,
    0x5175, 0x9BE1, 0x31D1, 0x6B6A, 0xCC92, 0x4791, 0x97E1, 0xAA0B,
    0xE748, 0x0403, 0x8F72, 0xA0F0, 0x5072, 0x1F0C, 0x68C3, 0x529F,
    0x327C, 0x145C, 0x3A8C, 0x0B40, 0x9261, 0x27C7, 0x8C19, 0xC1B5,
    0xBFEF, 0x3C55, 0xA5F7, 0x0C30, 0xE3D1, 0x6045, 0xB97F, 0xD4B9,
    0xF8E9, 0x40AB, 0x5AC8, 0xA3C4, 0xF255, 0xC8D6, 0x122A, 0x67E8,
    0xB251, 0x739F, 0xD6A8, 0x0D8E, 0x752F, 0x66B5, 0x0D99, 0xE6C7,
    0xE342, 0xA35F, 0xA7E6, 0x932F, 0xDB5A, 0xBC62, 0xDA74, 0xF9E8,
    0x7FA6, 0xD296, 0x57B1, 0xAC47, 0x24F2, 0xA9C1, 0x29D6, 0xC8B1,
    0xD531, 0x8B31, 0xD907, 0x1234, 0x4445, 0x2AB0, 0x6F51, 0x957B,
    0xC29B, 0xDC01, 0x4E79, 0x6F4A, 0xFA8F, 0x63A3, 0x9D9B, 0xAA6D,
    0x3C44, 0x750F, 0xBB20, 0x5B7A, 0xD72E, 0x0716, 0xB6F0, 0x2D46,
    0x9313, 0x8471, 0x4982, 0x89A7, 0x8A25, 0x9F36, 0x689A, 0xA2E2,
    0x1731, 0x8B66, 0xA8F5, 0x4F8C, 0x7320, 0x1A5D, 0x68A5, 0x5A9D,
    0x52FB, 0xD740, 0xAD93, 0xEA92, 0x9FB6, 0x6DA3, 0x0729, 0x27F1,
    0x30C7, 0x5B39, 0x87F4, 0x6273, 0x7796, 0xC456, 0x1D63, 0xA5C2,
    0xD6C9, 0xAC35, 0x00FE, 0x95A9, 0xC317, 0x5F9E, 0x6D21, 0x6E72,
    0xCAF3, 0x70E1, 0x5BC7, 0x432F, 0x12E0, 0xF4C2, 0xB0F1, 0x7BB9,
    0x1C32, 0xCE50, 0x2A62, 0x9F41, 0x9A77, 0xBF63, 0x7B34, 0x66C4,
    0x3A92, 0x5DB3, 0x10F9, 0xA492, 0xB9F5, 0xC740, 0x03A3, 0x44F9,
    0x1352, 0x48FE, 0x8D16, 0xF140, 0xA1B2, 0xD283, 0x72D0, 0xA8C0
]





S_box_1 = [
    0x0D6F, 0x1C8A, 0x99AC, 0x5762, 0x1D57, 0x3137, 0xD22B, 0x080C,
    0xA271, 0x79BB, 0x9D91, 0x9B49, 0x312C, 0x8206, 0x9C64, 0xF06F,
    0x60C3, 0x3F92, 0x77D5, 0x7428, 0x5305, 0xF132, 0xA8A4, 0x3581,
    0xB64F, 0xBB11, 0xC712, 0x2BB8, 0x1F3A, 0x9B44, 0x3B27, 0xF451,
    0xA2E6, 0xFB55, 0x9C30, 0xD81A, 0xEF0D, 0xE1E7, 0x79C8, 0x2B1F,
    0x68CC, 0x9D03, 0x1A72, 0xE38E, 0x8E71, 0xA16F, 0x96C4, 0x7325,
    0x8F23, 0x455D, 0xD4FE, 0xA3A5, 0x29E8, 0xBF23, 0xC147, 0x2BC6,
    0x0620, 0x38F6, 0x5024, 0x0C9E, 0x3507, 0x88E5, 0xA06F, 0x6D62,
    0x9A4D, 0x442D, 0x8C9D, 0x52B5, 0x876F, 0x4B16, 0xA08A, 0x9E45,
    0xD3A9, 0x17C8, 0x5F3D, 0x3D98, 0x6DB6, 0x3A25, 0x6C34, 0x0802,
    0x7C91, 0x3E2A, 0x5E72, 0xB618, 0x1072, 0xB72D, 0xA923, 0xBC06,
    0x0138, 0x64A8, 0xE943, 0xE4A3, 0xDA6A, 0xDFD2, 0xE7AD, 0x3B4A,
    0x4C89, 0x115D, 0xF8B2, 0x9C0B, 0xF040, 0x5746, 0xD8BE, 0x5D1A,
    0x5A36, 0x2A71, 0x6278, 0x2303, 0xBD4E, 0x32D5, 0x50A1, 0xC6B5,
    0x3134, 0xDC1A, 0xFE8B, 0x990D, 0x6E12, 0x1079, 0x9B6B, 0x218F,
    0xC75C, 0x233D, 0x7AB9, 0x5672, 0xD489, 0xAEE0, 0x67D8, 0x88B2,
    0xFDF4, 0x8351, 0x6979, 0x77C9, 0x44CA, 0xF28C, 0x23AC, 0x9927,
    0xA7F4, 0x9F5F, 0xC852, 0x8139, 0x9A32, 0x4F93, 0x31DA, 0x50F7,
    0x91B0, 0xAC3A, 0x7D7D, 0x24E4, 0x5D2B, 0xD364, 0x8D50, 0xF83E,
    0x07A7, 0x472F, 0x332C, 0x40A4, 0x8F6E, 0x96C2, 0x8A42, 0x1C88,
    0x2F1A, 0x1E47, 0x7742, 0x9259, 0x3B4D, 0xB95E, 0xA6D5, 0x88E4,
    0xFA52, 0x0E11, 0x82F8, 0x48A3, 0x72A2, 0xF6CB, 0x07D9, 0x56D1,
    0x41CA, 0x2A0C, 0xC9FD, 0xE1A8, 0x4C3A, 0x3E94, 0x5E1B, 0xF21F,
    0xD20B, 0xF6A1, 0x2994, 0x0147, 0x35DC, 0x03DA, 0x3511, 0xE99A,
    0x1A8D, 0xA257, 0x5894, 0xA1D9, 0x92E0, 0x5D1C, 0x79F8, 0x3999,
    0xB72F, 0x4021, 0xFC5B, 0xD0D5, 0x8C76, 0xE9C5, 0xB81E, 0x67E5,
    0x3D5F, 0xFA33, 0x1C14, 0x7484, 0x5ACF, 0x8D51, 0x7590, 0x9F20,
    0x3E44, 0x4B8E, 0x6C8D, 0xCE69, 0x0AB7, 0xB6C2, 0xF324, 0xC2A5,
    0xE963, 0x82F9, 0x2B40, 0x1D2C, 0xC5F6, 0xD730, 0x8DB4, 0x7A9C,
    0x5F88, 0x9F4E, 0x6F24, 0xA9F5, 0x48E9, 0x9256, 0x3383, 0x14D1,
    0xD58F, 0xBFC7, 0xCB99, 0xC0E6, 0x5D79, 0xE5A7, 0x7E93, 0x4D6B,
    0x0F3B, 0x3E2F, 0x9A41, 0xC643, 0x1B6D, 0x7D20, 0x4D3E, 0x8B59
]









# Utility functions
# Optimized left circular rotation using bitmasking.
def rotate_left(val, r_bits, max_bits=32):
    r_bits %= max_bits
    return ((val << r_bits) | (val >> (max_bits - r_bits))) & ((1 << max_bits) - 1)


# Efficient conversion of 16 bytes into four 32-bit words using numpy (optimized for bytearray)
def bytes_to_words(data):
    # Directly use np.frombuffer with bytearray for more efficient memory handling
    return np.frombuffer(memoryview(data), dtype=np.uint32)

# Efficient conversion of four 32-bit words into 16 bytes using numpy
def words_to_bytes(words):
    # Directly use np.asarray with dtype set to np.uint32, and then convert to bytes
    return np.asarray(words, dtype=np.uint32).tobytes()





# Padding and unpadding functions
# Optimized pkcs7 padding function
def pkcs7_pad(data, block_size=16):
    # Directly append the padding bytes in one step using bytearray
    pad_len = block_size - (len(data) % block_size)
    return data + bytearray([pad_len]) * pad_len  # More efficient padding append with bytearray

# Optimized pkcs7 unpadding function
def pkcs7_unpad(data, block_size=16):
    # Remove padding efficiently using bytearray and avoid unnecessary slicing
    pad_len = data[-1]
    return data[:-pad_len]  # Efficient removal of padding







# Key schedule
def key_schedule(key):
    # Split the key into 32-bit words using numpy for efficient conversion
    k = np.frombuffer(key, dtype=np.uint32)  # k is now a numpy array

    # Precompute rotation results and subkeys
    subkeys = np.empty(40, dtype=np.uint32)  # Pre-allocate array for subkeys

    # Generate 40 subkeys (optimized by eliminating redundant modulus operation)
    for i in range(40):
        j = i & 3  # Use bitwise AND instead of modulo for better performance
        subkeys[i] = (k[j] ^ rotate_left(k[(j + 1) & 3], i)) & 0xFFFFFFFF

    # Efficient S-box generation using numpy
    s_boxes = k & 0xFF  # Perform bitwise operation directly on numpy array

    return subkeys.tolist(), s_boxes.tolist()




# Feistel function (F) using the full S-boxes
def feistel_function(right, s_boxes, round_key):
    # Split into two 16-bit halves
    r0 = (right >> 16) & 0xFFFF
    r1 = right & 0xFFFF


    # Apply S-boxes (substitute using the full S-boxes)
    r0 = S_box_0[r0 % 256]  # Ensuring the index is within the range [0, 255]
    r1 = S_box_1[r1 % 256]  # Ensuring the index is within the range [0, 255]



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

    # 16 Feistel rounds (in reverse order)
    for round in range(15, -1, -1):
        # Precompute subkeys for the current round to avoid redundant indexing
        round_key0 = subkeys[4 + round * 2]
        round_key1 = subkeys[5 + round * 2]

        # Apply Feistel function to L0 and L1
        F0 = feistel_function(L0, s_boxes, round_key0)
        F1 = feistel_function(L1, s_boxes, round_key1)

        # XOR with right halves
        L0, L1, R0, R1 = R0 ^ F0, R1 ^ F1, L0, L1

    # Pre-whitening
    L0 ^= subkeys[0]
    L1 ^= subkeys[1]
    R0 ^= subkeys[2]
    R1 ^= subkeys[3]

    # Combine into plaintext and return result
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
