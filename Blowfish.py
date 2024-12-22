#========================================
# Blowfish implementation in Python
# Created by: wyn-cmd
#========================================


def blowfish_decrypt(data, key):
    # Ensure input data is 64 bits (8 bytes)
    if len(data) != 8:
        raise ValueError("Data must be 8 bytes (64 bits).")

    # Ensure key length is valid (32 to 448 bits, i.e., 4 to 56 bytes)
    if not (4 <= len(key) <= 56):
        raise ValueError("Key must be between 4 and 56 bytes.")

    # Generate the P-array dynamically from the key
    P = generate_p_array(key)

    # S-boxes (Simplified; normally initialized based on π and the key)
    S = [[i for i in range(256)] for _ in range(4)]

    # Split the ciphertext into two 32-bit halves
    L = int.from_bytes(data[:4], byteorder='big')
    R = int.from_bytes(data[4:], byteorder='big')

    # Reverse the final P-array adjustments
    R ^= P[17]
    L ^= P[16]

    # Feistel network: 16 rounds in reverse
    for i in range(15, -1, -1):
        L, R = R, L ^ F(R, S) ^ P[i]

    # Swap L and R back to their original order
    L, R = R, L

    # Combine the halves into plaintext
    plaintext = L.to_bytes(4, byteorder='big') + R.to_bytes(4, byteorder='big')
    return plaintext






def blowfish_encrypt(data, key):
    # Ensure input data is 64 bits (8 bytes)
    if len(data) != 8:
        raise ValueError("Data must be 8 bytes (64 bits).")

    # Ensure key length is valid (32 to 448 bits, i.e., 4 to 56 bytes)
    if not (4 <= len(key) <= 56):
        raise ValueError("Key must be between 4 and 56 bytes.")

    # Generate the P-array dynamically from the key
    P = generate_p_array(key)

    # S-boxes (Simplified; normally initialized based on π and the key)
    S = [[i for i in range(256)] for _ in range(4)]

    # Split the data into two 32-bit halves
    L = int.from_bytes(data[:4], byteorder='big')
    R = int.from_bytes(data[4:], byteorder='big')

    # Feistel network: 16 rounds
    for i in range(16):
        L, R = R, L ^ F(R, S) ^ P[i]

    # Final swap and P-array adjustments
    L, R = R, L
    L ^= P[16]
    R ^= P[17]

    # Combine the halves into ciphertext
    ciphertext = L.to_bytes(4, byteorder='big') + R.to_bytes(4, byteorder='big')
    return ciphertext





def generate_p_array(key):
    # Generates the P-array from the given key.
    # Initial P-array values (hex digits of π, simplified)
    P = [
        0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
        0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
        0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
        0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
        0x9216D5D9, 0x8979FB1B
    ]

    # Extend the key cyclically across the P-array
    key_length = len(key)
    j = 0
    for i in range(len(P)):
        # Extract 32 bits from the key and XOR with the current P-array entry
        key_part = (
            (key[j % key_length] << 24) |
            (key[(j + 1) % key_length] << 16) |
            (key[(j + 2) % key_length] << 8) |
            key[(j + 3) % key_length]
        )
        P[i] ^= key_part
        j = (j + 4) % key_length

    return P





def F(x, S):
    # Feistel function: Uses S-boxes for substitution and arithmetic operations.
    a = (x >> 24) & 0xFF  # Extract the first 8 bits
    b = (x >> 16) & 0xFF  # Extract the second 8 bits
    c = (x >> 8) & 0xFF   # Extract the third 8 bits
    d = x & 0xFF          # Extract the last 8 bits

    # Substitute using the S-boxes and apply arithmetic
    return ((S[0][a] + S[1][b]) ^ S[2][c]) + S[3][d]





# Example usage:
plaintext = b"ABCDEFGH"  # 8-byte plaintext (64 bits)
key = b"mysecretkey12"   # Key (32 to 448 bits)


print("Plaintext:", plaintext.decode())
print('Key:', key.decode())

ciphertext = blowfish_encrypt(plaintext, key)
print("Ciphertext:", ciphertext.hex())

decrypted = blowfish_decrypt(ciphertext, key)
print("Decrypted:", decrypted.decode())
