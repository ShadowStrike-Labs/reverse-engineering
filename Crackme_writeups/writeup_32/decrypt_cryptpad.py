"""
decrypt_cryptpad.py

Decrypts a flag.enc produced by cryptpad.exe.

The output file layout is:
    [0 .. plaintext_len)         ciphertext (RC4-encrypted plaintext)
    [plaintext_len .. file-13)   random padding
    [file-13 .. file-9)          plaintext length (LE DWORD)
    [file-9  .. file-1)          8-byte RC4 key
    [file-1]                     0x08 (key-size sentinel)

The forward encryption chain is:
    pre_xor(P, K8) -> RC4(KSA/PRGA with 8-byte key extended to 256) -> post_xor(_, K8)

Because the pre- and post-XOR layers use the same 8-byte key cycled by the same
position function, they cancel exactly at every byte. The pipeline is thus
mathematically equivalent to plain RC4 with the 8-byte key -- but the script
below runs the full three-stage pipeline faithfully to match the binary.
"""

import struct
import sys
from pathlib import Path


FLAG_PATH = Path(__file__).with_name("flag.enc")
KEY_SIZE_SENTINEL = 0x08


def parse_trailer(enc: bytes) -> tuple[int, bytes]:
    """Return (plaintext_len, key) from the last 13 bytes of enc."""
    if enc[-1] != KEY_SIZE_SENTINEL:
        raise ValueError(
            f"unexpected key-size sentinel: 0x{enc[-1]:02X} (expected 0x08)"
        )
    plaintext_len = struct.unpack("<I", enc[-13:-9])[0]
    key = enc[-9:-1]
    return plaintext_len, key


def rc4_crypt(buf: bytearray, key: bytes) -> None:
    """In-place RC4 KSA + PRGA. Matches cryptpad.exe's implementation:
    the 8-byte key is extended to 256 bytes (repeated 32 times) and fed to
    the KSA."""
    extended = key * 32  # 8 * 32 == 256

    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + extended[i]) & 0xFF
        S[i], S[j] = S[j], S[i]

    i = j = 0
    for n in range(len(buf)):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        buf[n] ^= S[(S[i] + S[j]) & 0xFF]


def xor_cycle(buf: bytearray, key: bytes) -> None:
    """In-place XOR each byte with the 8-byte key cycled by index."""
    for i in range(len(buf)):
        buf[i] ^= key[i % 8]


def decrypt(enc: bytes) -> bytes:
    plaintext_len, key = parse_trailer(enc)
    buf = bytearray(enc[:plaintext_len])

    xor_cycle(buf, key)   # Stage 1: pre-XOR
    rc4_crypt(buf, key)   # Stage 2+3: KSA + PRGA
    xor_cycle(buf, key)   # Stage 4: post-XOR (cancels stage 1)

    return bytes(buf)


def simple_rc4(ciphertext: bytes, key: bytes) -> bytes:
    """RC4 alone -- the mathematically-equivalent simplification of the
    full pipeline (because the two outer XORs cancel)."""
    buf = bytearray(ciphertext)
    rc4_crypt(buf, key)
    return bytes(buf)


def main() -> None:
    enc = FLAG_PATH.read_bytes()
    print(f"File size:      {len(enc)} bytes")
    print(f"Multiple 64?    {len(enc) % 64 == 0}")

    print("")
    print("--- Trailer ---")
    print(f"Last byte (key size): 0x{enc[-1]:02X} (expected 0x{KEY_SIZE_SENTINEL:02X})")
    plaintext_len, key = parse_trailer(enc)
    print(f"Key (8 bytes):   {key.hex()}")
    print(f"Plaintext length: {plaintext_len}")

    print("")
    print("--- Decryption ---")
    faithful = decrypt(enc)
    simple = simple_rc4(enc[:plaintext_len], key)
    print(f"Simple RC4 matches faithful: {faithful == simple}")

    print("")
    print("Decrypted text (ASCII):")
    print("=" * 50)
    sys.stdout.write(faithful.decode("ascii", errors="replace"))
    sys.stdout.write("\n")
    print("=" * 50)


if __name__ == "__main__":
    main()
