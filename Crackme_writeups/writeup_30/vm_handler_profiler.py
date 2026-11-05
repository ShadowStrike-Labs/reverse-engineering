# vm_handler_profiler.py
#
# Captures the handler address (R8) at each dispatch (jmp r8) breakpoint,
# statically analyzes each handler's body, and produces:
#   1. A sequential trace of every hit
#   2. A frequency table: how many times each unique handler was visited
#   3. A classification per handler (trivial / conditional / memory / call)
#   4. Full disassembly of the "interesting" handlers (non-trivial ones)
#
# Setup:
#   1. Set a software BP on the dispatch instruction (`jmp r8` at base_location).
#      For this binary: .text:00007FF6D001119D
#   2. Press F9 to start the process. Enter the password. BP hits.
#   3. Alt+F7 -> pick this script.
#   4. Watch the console; a full report is also written to disk.

import ida_dbg
import idc
import os
from collections import Counter

# ---------------- Config ----------------

MAX_HITS       = 2000
TIMEOUT_SEC    = 10
MAX_BODY_INSNS = 48      # cap on how many instructions we walk per handler

OUTPUT_DIR  = r"C:\Users\RTX40\Desktop\RE\Language_Specific_Crackmes\Rust\2\The_Obfuscators_Riddle"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "handler_profile.txt")

# Which register holds the dispatch target when the BP fires.
# At `jmp r8` the target is in R8. Change if your BP is somewhere else.
TARGET_REG = "R8"

# Auto-rename TRIV handlers (short, no-conditional "advance AL" obfuscation)
# from loc_XXXXXXXX to obf_location_NNN so the real logic handlers stand out.
# Numbering is by address, so re-runs give identical names.
# Only touches names that start with "loc_" or the prefix below -- user-set
# names are preserved.
RENAME_TRIVIAL = True
RENAME_PREFIX  = "obf_location_"

# Rename non-TRIV handlers (the real logic nodes) to rl_location_NNN
# in the order they are FIRST visited by the trace. This produces a
# readable sequential map of the real program, with the TRIV decoys
# already hidden behind obf_location_* names.
RENAME_REAL   = True
REAL_PREFIX   = "rl_location_"

# ---------------- Classification helpers ----------------

CONDITIONAL_MNEMS = {
    # Conditional jumps
    "jz", "jnz", "je", "jne", "js", "jns",
    "ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle",
    "jc", "jnc", "jo", "jno", "jp", "jnp", "jpe", "jpo",
    "jecxz", "jrcxz",
    # Conditional moves
    "cmovz", "cmovnz", "cmove", "cmovne",
    "cmovs", "cmovns", "cmova", "cmovae",
    "cmovb", "cmovbe", "cmovg", "cmovge",
    "cmovl", "cmovle", "cmovc", "cmovnc",
    "cmovo", "cmovno", "cmovp", "cmovnp",
    # Conditional sets
    "setz", "setnz", "sete", "setne", "sets", "setns",
    "seta", "setae", "setb", "setbe", "setg", "setge",
    "setl", "setle", "setc", "setnc",
}

MEMORY_HINTS = ("[rbp", "[rsp", "[rbx", "[rsi", "[rdi",
                "[rax", "[rcx", "[rdx", "[r8",  "[r9",
                "[r10", "[r11", "[r12", "[r13", "[r14", "[r15",
                "ds:")

TERM_MNEMS = {"jmp", "ret", "retn", "retf", "iret", "iretq", "ud2", "hlt"}


def analyze_handler(ea):
    """Walk instructions starting at `ea` until a terminating jump/ret.
       Return a dict describing the handler body."""
    insns = []
    conditionals = 0
    mem_touches  = 0
    calls        = 0
    cur = ea
    for _ in range(MAX_BODY_INSNS):
        if cur == idc.BADADDR or not idc.is_code(idc.get_full_flags(cur)):
            break
        mnem   = idc.print_insn_mnem(cur).lower()
        disasm = idc.generate_disasm_line(cur, 0)
        insns.append((cur, mnem, disasm))

        if mnem in CONDITIONAL_MNEMS:
            conditionals += 1
        if mnem == "call":
            calls += 1
        if mnem != "lea" and any(h in disasm.lower() for h in MEMORY_HINTS):
            mem_touches += 1

        if mnem in TERM_MNEMS:
            break
        cur = idc.next_head(cur)

    return {
        "insns":        insns,
        "n_insns":      len(insns),
        "conditionals": conditionals,
        "mem_touches":  mem_touches,
        "calls":        calls,
    }


def classify(a):
    """Short tag describing the handler shape."""
    if a["conditionals"] > 0:
        return "COND"
    if a["calls"] > 0:
        return "CALL"
    if a["mem_touches"] > 0:
        return "MEM"
    if a["n_insns"] <= 4:
        return "TRIV"
    return "OTHER"


# ---------------- Main trace loop ----------------

trace    = []  # [(hit_num, handler_addr, rcx), ...]
analyses = {}  # handler_addr -> analyze_handler() result

print(f"=== VM handler profiler, max {MAX_HITS} hits ===")
print(f"Report: {OUTPUT_FILE}\n")

for i in range(1, MAX_HITS + 1):
    if not ida_dbg.is_debugger_on():
        print("  Debugger not active, stopping")
        break

    try:
        target = idc.get_reg_value(TARGET_REG)
        rcx    = idc.get_reg_value("RCX")
    except Exception as e:
        print(f"  Can't read registers ({e}), stopping")
        break

    trace.append((i, target, rcx))

    if target not in analyses:
        analyses[target] = analyze_handler(target)

    a    = analyses[target]
    tag  = classify(a)
    name = idc.get_name(target) or f"loc_{target:X}"
    print(f"[{i:4d}]  {TARGET_REG}={target:#018x}  RCX={rcx:#06x}  "
          f"{name:<30}  {tag:<4}  n={a['n_insns']:>2}  "
          f"cond={a['conditionals']}  mem={a['mem_touches']}  call={a['calls']}")

    if not ida_dbg.continue_process():
        print("  ! continue_process() failed")
        break
    ev = ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, TIMEOUT_SEC)
    if ev <= 0:
        print(f"  ! wait event ended ({ev}), stopping")
        break


# ---------------- Frequency table ----------------

freq = Counter(h for _, h, _ in trace)


# ---------------- Rename TRIV handlers (optional) ----------------

renamed = []  # list of (addr, new_name, old_name)
if RENAME_TRIVIAL:
    triv_addrs = sorted(a for a, info in analyses.items() if classify(info) == "TRIV")
    for idx, addr in enumerate(triv_addrs, 1):
        old = idc.get_name(addr) or f"loc_{addr:X}"
        # Only touch default auto-names or prior-run renames; preserve manual labels
        if old.startswith("loc_") or old.startswith(RENAME_PREFIX):
            new = f"{RENAME_PREFIX}{idx:03d}"
            if idc.set_name(addr, new, idc.SN_NOWARN):
                renamed.append((addr, new, old))
    print(f"\n=== Renamed {len(renamed)} TRIV handlers to {RENAME_PREFIX}NNN ===")


# ---------------- Rename REAL (non-TRIV) handlers in visit order ----------------

real_renamed    = []     # [(addr, new_name, old_name), ...] in visit order
first_seen_idx  = {}     # addr -> order (1-based) of first non-TRIV visit

if RENAME_REAL:
    counter = 0
    for _hit_num, addr, _rcx in trace:
        if addr in first_seen_idx:
            continue
        if classify(analyses[addr]) == "TRIV":
            continue
        counter += 1
        first_seen_idx[addr] = counter

    for addr, order in first_seen_idx.items():
        old = idc.get_name(addr) or f"loc_{addr:X}"
        # Replace default names and prior-run rl_* names; preserve manual labels
        # and obf_* names (shouldn't collide, but be safe)
        if old.startswith("loc_") or old.startswith(REAL_PREFIX):
            new = f"{REAL_PREFIX}{order:03d}"
            if idc.set_name(addr, new, idc.SN_NOWARN):
                real_renamed.append((addr, new, old))
    print(f"=== Renamed {len(real_renamed)} REAL handlers to {REAL_PREFIX}NNN ===")


# ---------------- Build report ----------------

lines = []
lines.append("=" * 72)
lines.append(f"VM Handler Profile")
lines.append("=" * 72)
lines.append(f"Total hits captured: {len(trace)}")
lines.append(f"Unique handlers:     {len(freq)}")

tag_counts = Counter(classify(analyses[a]) for a in freq)
lines.append(f"Unique handler tags: " +
             ", ".join(f"{t}={c}" for t, c in tag_counts.most_common()))
lines.append("")

# ---- Section 1: sequential trace ----
lines.append("-" * 72)
lines.append("Section 1 - Sequential trace (every F9 hit, in order)")
lines.append("-" * 72)
for i, addr, rcx in trace:
    name = idc.get_name(addr) or f"loc_{addr:X}"
    a    = analyses[addr]
    tag  = classify(a)
    lines.append(f"[{i:4d}]  {addr:#018x}  {name:<30}  "
                 f"RCX={rcx:#06x}  tag={tag:<4}  n={a['n_insns']:>2}  "
                 f"cond={a['conditionals']}  mem={a['mem_touches']}  "
                 f"call={a['calls']}")

# ---- Section 2: frequency table ----
lines.append("")
lines.append("-" * 72)
lines.append("Section 2 - Frequency table (most-visited first)")
lines.append("-" * 72)
lines.append(f"{'hits':>6}  {'address':<18}  {'name':<30}  tag   n_ins  cond  mem  call")
for addr, cnt in freq.most_common():
    name = idc.get_name(addr) or f"loc_{addr:X}"
    a    = analyses[addr]
    tag  = classify(a)
    lines.append(f"{cnt:>6}  {addr:#018x}  {name:<30}  "
                 f"{tag:<4}  {a['n_insns']:>5}  {a['conditionals']:>4}  "
                 f"{a['mem_touches']:>3}  {a['calls']:>4}")

# ---- Section 3: full body of INTERESTING handlers ----
lines.append("")
lines.append("-" * 72)
lines.append("Section 3 - Interesting handler bodies (non-TRIV, visit-sorted)")
lines.append("-" * 72)
for addr, cnt in freq.most_common():
    a   = analyses[addr]
    tag = classify(a)
    if tag == "TRIV":
        continue
    name = idc.get_name(addr) or f"loc_{addr:X}"
    lines.append("")
    lines.append(f"[{tag}] {name}  @ {addr:#x}  visits={cnt}  "
                 f"insns={a['n_insns']}  cond={a['conditionals']}  "
                 f"mem={a['mem_touches']}  call={a['calls']}")
    for ea, _mnem, disasm in a["insns"]:
        lines.append(f"    {ea:#x}  {disasm}")

# ---- Section 4: rename map (TRIV handlers only) ----
if renamed:
    lines.append("")
    lines.append("-" * 72)
    lines.append(f"Section 4 - Rename map (TRIV handlers -> {RENAME_PREFIX}NNN)")
    lines.append("-" * 72)
    lines.append(f"{'address':<18}  {'old name':<28} -> new name")
    for addr, new, old in renamed:
        lines.append(f"{addr:#018x}  {old:<28} -> {new}")

# ---- Section 5: real execution flow (obfuscation filtered out) ----
lines.append("")
lines.append("-" * 72)
lines.append("Section 5 - Real execution flow (TRIV handlers filtered out)")
lines.append("-" * 72)
lines.append(f"{'step':>5}  {'hit#':>5}  {'address':<18}  {'name':<28}  "
             f"tag  n_ins  cond  mem  call")
step = 0
for hit_num, addr, _rcx in trace:
    if classify(analyses[addr]) == "TRIV":
        continue
    step += 1
    name = idc.get_name(addr) or f"loc_{addr:X}"
    a    = analyses[addr]
    tag  = classify(a)
    lines.append(f"{step:>5}  {hit_num:>5}  {addr:#018x}  {name:<28}  "
                 f"{tag:<4}  {a['n_insns']:>4}  {a['conditionals']:>4}  "
                 f"{a['mem_touches']:>3}  {a['calls']:>4}")
lines.append(f"\n({step} non-TRIV steps out of {len(trace)} total hits)")

# ---- Section 6: real-handler rename map ----
if real_renamed:
    lines.append("")
    lines.append("-" * 72)
    lines.append(f"Section 6 - Real-handler rename map (first-visit order -> {REAL_PREFIX}NNN)")
    lines.append("-" * 72)
    lines.append(f"{'address':<18}  {'old name':<28} -> new name")
    for addr, new, old in real_renamed:
        lines.append(f"{addr:#018x}  {old:<28} -> {new}")

# ---- Save ----
try:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n=== Report written to {OUTPUT_FILE} ===")
    print(f"    {len(lines)} lines, {len(trace)} hits, {len(freq)} unique handlers")
except Exception as e:
    print(f"\n! Failed to write report: {e}")

# ---- Short console summary ----
print(f"\n=== Top 20 hottest handlers ===")
for addr, cnt in freq.most_common(20):
    name = idc.get_name(addr) or f"loc_{addr:X}"
    a    = analyses[addr]
    tag  = classify(a)
    print(f"  {cnt:>5}x  {addr:#018x}  {name:<30}  tag={tag:<4}  n={a['n_insns']}")

print(f"\n=== Non-trivial handler count: "
      f"{sum(1 for a in freq if classify(analyses[a]) != 'TRIV')} / {len(freq)} ===")
