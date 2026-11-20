"""
solve_wheristhechallange.py

Recovers the password accepted by WhereIsTheChallange_overlay_7E00_pe.exe.

The innermost validator is a per-byte XOR equality:
    (input[i] ^ 0x50) == expected[i]
with `expected` stored in the overlay EXE's .rdata. Inverting is one XOR:
    input[i] = expected[i] ^ 0x50
"""

# 8 bytes dumped from the overlay EXE's .rdata, in the order the validator
# reads them.
expected = bytes([0x31, 0x32, 0x33, 0x61, 0x62, 0x63, 0x71, 0x71])

flag = bytes(b ^ 0x50 for b in expected)

print(f"Recovered flag: {flag.decode('ascii')}")

# Forward verification: re-encode the recovered flag and compare.
reencoded = bytes(b ^ 0x50 for b in flag)
print(f"Re-encode matches stored bytes: {reencoded == expected}")
