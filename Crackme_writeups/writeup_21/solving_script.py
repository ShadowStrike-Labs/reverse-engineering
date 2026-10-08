import zlib
import sys


def find(second):
    for X in range(1000, 10000):
        for Y in range(1000, 10000):
            r = (X * Y >> 10) if second else (X * Y & 0x7FFF)
            if (X ^ Y ^ r) == 0:
                return X, Y
    return None


B, C = find(False)   # BBBB, CCCC   ->  B ^ C ^ ((B*C) & 0x7FFF) == 0
D, E = find(True)    # DDDD, EEEE   ->  D ^ E ^ ((D*E) >> 10)   == 0

# name = exactly what you type in the Name field; pass it on the command line:
#   python solving_script.py MyName
name = sys.argv[1].encode() if len(sys.argv) > 1 else b"crackme"

A = zlib.adler32(name) & 0xFFFFFFFF
serial = "%08X-%04X-%04X-%04X-%04X" % (A, B, C, D, E)

print("name  :", name.decode())
print("serial:", serial)
