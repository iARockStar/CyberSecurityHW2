import numpy as np


PERMUTATION_BOX = [
    12, 30, 11, 3, 20, 4, 1, 21,
    28, 10, 13, 19, 25, 6, 7, 0,
    2, 22, 15, 17, 29, 27, 18, 23,
    5, 14, 31, 9, 16, 24, 8, 26
]

def generate_subkeys(key, rounds=16):
    key_bin = f"{int(key, 2):056b}"
    subkeys = []
    for i in range(rounds):
        drop_start = i * 4
        key_dropped = key_bin[:drop_start] + key_bin[drop_start + 4:]

        permuted_key = ''.join([key_dropped[j] for j in PERMUTATION_BOX])
        subkey = permuted_key[:32]
        subkeys.append(subkey)
    return subkeys


def block_rearrange(block):
    block_chunks = [block[i:i + 4] for i in range(0, len(block), 4)]
    block_np = np.array([list(map(int, chunk)) for chunk in block_chunks])
    for i in range(1, 8):
        block_np[i] = np.roll(block_np[i], i)

    rearranged_block = ''.join(map(str, block_np.flatten().tolist()))
    return rearranged_block


def round_function(right, subkey):
    rearranged_block = block_rearrange(right)

    xor_result = bin(int(rearranged_block, 2)
                     ^ int(subkey, 2))[2:].zfill(len(rearranged_block))
    return xor_result


def feistel_encrypt(plaintext, key, rounds=16):
    assert len(plaintext) == 64, "Plaintext must be 64 bits"
    assert len(key) == 56, "Key must be 56 bits"

    left = plaintext[:32]
    right = plaintext[32:]

    subkeys = generate_subkeys(key, rounds)

    for i in range(rounds):
        rightlast = right
        round_result = round_function(right, subkeys[i])
        right_new = ''.join(map(str, round_result))
        right = [str(int(x) ^ int(y)) for x, y in zip(left, right_new)]
        left = rightlast

    ciphertext = left + right
    return ciphertext

def feistel_decrypt(ciphertext, key, rounds=16):
    assert len(ciphertext) == 64, "Ciphertext must be 64 bits"
    assert len(key) == 56, "Key must be 56 bits"

    left = ciphertext[:32]
    right = ciphertext[32:]

    subkeys = generate_subkeys(key, rounds)
    subkeys = subkeys[::-1]

    for i in range(rounds):
        leftlast=left
        round_result = round_function(left, subkeys[i])
        left_new = ''.join(map(str, round_result))
        left = [str(int(x) ^ int(y)) for x, y in zip(left_new, right)]
        right = leftlast

    plaintext = left + right
    return plaintext

plaintext = "0111111000000110011001100110011001100110011010100110011001101000"
key = "11110011110011110011110011110011110011110011110011110011"

ciphertext = feistel_encrypt(plaintext, key)
print(f"Ciphertext: {''.join(ciphertext)}")

decrypted_text = feistel_decrypt(ciphertext, key)
print(f"Decrypted Text: {''.join(decrypted_text)}")
