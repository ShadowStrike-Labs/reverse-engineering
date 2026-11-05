
# vm_dispatcher_dump.py v2 - cursor-based, auto-terminating

import idc

base = idc.here()  # Cursor position = first dd entry of the table

seen = {}
i = 0

print(f"Table base: {base:#x}\n")
print(f"[opcode] target             label")
print(f"-------- ------------------ ---------------------")

while True:
    ea = base + i * 4

    # Read 4 bytes as signed int32
    disp = idc.get_wide_dword(ea)

    if disp & 0x80000000:
        disp -= 0x100000000

    target = base + disp

    # Termination: target must be a valid code address
    if not idc.is_code(idc.get_full_flags(target)):
        print(f"\n(terminated at entry {i}: {target:#x} is not code)")
        break

    tag = ""

    if target in seen:
        tag = f"  (dup of op {seen[target]:#04x})"
    else:
        seen[target] = i

    name = idc.get_name(target) or f"loc_{target:X}"
    print(f"[{i:#05x}]  {target:#018x}  {name}{tag}")

    i += 1

print(f"\nTotal valid entries: {i}")
print(f"Unique handlers:     {len(seen)}")