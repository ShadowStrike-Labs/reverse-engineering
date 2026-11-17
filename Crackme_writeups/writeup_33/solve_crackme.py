"""
solve_crackme.py

Analytical solver + verifier for the inner (unpacked) binary.

The validator is a five-stage state machine:
  Stage 0 : length == 16
  Stage 1 : every byte in [0-9A-Za-z]
  Stage 2 : sum == 1318  AND  custom hash == 2014193983
  Stage 3 : for each i, (A[i] ^ (13*i + input[i])) & 0xFF == B[i]
  Stage 4 : six cross-position constraints

Stage 3 pins each flag byte uniquely:
    input[i] = ((A[i] ^ B[i]) - 13*i) & 0xFF
so the solver recovers the flag directly from the two 16-byte tables A and B
dumped from the unpacked binary at byte_40200B (A) and byte_40201B (B), then
verifies the recovered flag against every other stage.
"""

# Dumped from unpacked.exe at .data:0x40200B (16 bytes).
A = bytes([
    0x3A, 0xC1, 0x17, 0x8E, 0x55, 0x29, 0xB4, 0x6D,
    0x90, 0x4F, 0x22, 0xD8, 0x71, 0x0C, 0xAE, 0x5B,
])

# Dumped from unpacked.exe at .data:0x40201B (16 bytes).
B = bytes([
    0x7C, 0xBA, 0x7D, 0x1C, 0x3F, 0x51, 0x77, 0xDF,
    0x0E, 0xE3, 0xD7, 0x1E, 0x8F, 0x2F, 0xA1, 0xAE,
])

# Hash parameters, dumped from Main_Comparison.
HASH_SEED   = 324508639            # same constant used in the outer loader's strange_func
HASH_MULT   = -1640531535          # a signed 32-bit multiplier the author chose
HASH_TARGET = 2014193983
SUM_TARGET  = 1318
MASK32      = 0xFFFFFFFF


def rol32(x: int, n: int) -> int:
    x &= MASK32
    n &= 31
    return ((x << n) | (x >> (32 - n))) & MASK32


def to_signed32(x: int) -> int:
    x &= MASK32
    return x - 0x100000000 if x & 0x80000000 else x


def custom_hash(data: bytes) -> int:
    """Replicates Stage 2's hash loop verbatim.
    Custom_Hash = -1640531535 * ((i + 69*v5) ^ (17*i + v5 + ROL(Custom_Hash, 5)))
    """
    h = HASH_SEED
    for i, v5 in enumerate(data):
        term1 = (i + 69 * v5) & MASK32
        term2 = (17 * i + v5 + rol32(h, 5)) & MASK32
        h = ((HASH_MULT & MASK32) * (term1 ^ term2)) & MASK32
    return to_signed32(h) & MASK32


def recover_flag(A: bytes, B: bytes) -> bytes:
    """Invert Stage 3: input[i] = ((A[i] ^ B[i]) - 13*i) & 0xFF"""
    assert len(A) == 16 and len(B) == 16
    return bytes(((A[i] ^ B[i]) - 13 * i) & 0xFF for i in range(16))


def verify_stage0(flag: bytes) -> bool:
    return len(flag) == 16


def verify_stage1(flag: bytes) -> bool:
    def ok(c: int) -> bool:
        return (0x30 <= c <= 0x39) or (0x41 <= c <= 0x5A) or (0x61 <= c <= 0x7A)
    return all(ok(c) for c in flag)


def verify_stage2(flag: bytes) -> tuple[bool, bool, int, int]:
    s = sum(flag)
    h = custom_hash(flag)
    return s == SUM_TARGET, h == HASH_TARGET, s, h


def verify_stage3(flag: bytes) -> bool:
    return all(((A[i] ^ (13 * i + flag[i])) & 0xFF) == B[i] for i in range(16))


def verify_stage4(flag: bytes) -> list[tuple[str, bool]]:
    checks = [
        ("flag[7]  - flag[0]  == 17",   flag[7]  - flag[0]  == 17),
        ("flag[12] + flag[3]  == 205",  flag[12] + flag[3]  == 205),
        ("flag[8]  == flag[4]",         flag[8]  == flag[4]),
        ("flag[11] == flag[9]",         flag[11] == flag[9]),
        ("flag[13] ^ flag[2]  == 0x2A", (flag[13] ^ flag[2]) == 0x2A),
        ("flag[15] + flag[0]  == 120",  flag[15] + flag[0]  == 120),
    ]
    return checks


def main() -> None:
    flag = recover_flag(A, B)
    print(f"Recovered flag:  {flag.decode('ascii')}")
    print(f"Length:          {len(flag)}")
    print()

    print("Per-position recovery:")
    print("  i | A[i] | B[i] | A^B  | 13*i | ((A^B)-13i)&FF | char")
    print("----+------+------+------+------+----------------+------")
    for i in range(16):
        xor = A[i] ^ B[i]
        thirteen_i = 13 * i
        byte = (xor - thirteen_i) & 0xFF
        print(f"  {i:2d}| 0x{A[i]:02X} | 0x{B[i]:02X} | 0x{xor:02X} | {thirteen_i:4d} |     0x{byte:02X}       | {chr(byte)!r}")
    print()

    print(f"Stage 0 (length == 16):          {verify_stage0(flag)}")
    print(f"Stage 1 (alphanumeric):          {verify_stage1(flag)}")

    sum_ok, hash_ok, s, h = verify_stage2(flag)
    print(f"Stage 2 (sum == 1318):           {sum_ok} (got {s})")
    print(f"Stage 2 (hash == 2014193983):    {hash_ok} (got {h})")

    print(f"Stage 3 (per-position XOR):      {verify_stage3(flag)}")

    print("Stage 4 (cross-position):")
    for name, ok in verify_stage4(flag):
        print(f"  {name:35s}  {ok}")


if __name__ == "__main__":
    main()
