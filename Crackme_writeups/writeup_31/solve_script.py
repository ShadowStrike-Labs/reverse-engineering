
import struct

"""
Inverse of RC4_KEY_GENERATOR (handling_input) for FLRSCRNSVR crackme.

Forward chain:
    1. Char substitution: input[i] = str2[position_of(input[i], str1)]
    2. XOR:               input[m] ^= (m + v32_words[m % 9])
    3. Reverse string

Recovery:
    1. Reverse
    2. XOR again with the same key
    3. Apply inverse substitution (str2 -> str1)
"""

# Target: Quak buffer from .rdata
quak_bytes = bytes([
    0x3C, 0x00, 0x51, 0x00, 0x6A, 0x00, 0x09, 0x00,
    0x02, 0x00, 0x07, 0x00, 0x25, 0x00, 0x03, 0x00,
    0x30, 0x00, 0x08, 0x00, 0x04, 0x00, 0x29, 0x00,
    0x68, 0x00, 0x24, 0x00, 0x01, 0x00, 0x24, 0x00,
    0x18, 0x00, 0x6B, 0x00, 0x77, 0x00, 0x0F, 0x00,
    0x70, 0x00, 0x36, 0x00, 0x02, 0x00, 0x0E, 0x00,
    0x0B, 0x00,
])

quak = list(struct.unpack("<25H", quak_bytes))

# Substitution tables
str1 = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP"
    "QRSTUVWXYZ0123456789}_{=-"
)

str2 = (
    "-={_}9876543210ZYXWVUTSRQPONMLKJIHGF"
    "EDCBAzyxwvutsrqponmlkjihgfedcba"
)

# XOR key: FLARERALF
flare = [
    0x46, 0x4C, 0x41, 0x52, 0x45,
    0x52, 0x41, 0x4C, 0x46,
]

# Step 1: Undo reverse
step1 = quak[::-1]

# Step 2: Undo XOR
step2 = [
    step1[i] ^ (i + flare[i % 9])
    for i in range(25)
]

# Step 3: Undo character substitution
inv_subst = dict(zip(str2, str1))

flag = "".join(
    inv_subst.get(chr(c), chr(c))
    for c in step2
)

print(f"Flag: {flag}")
