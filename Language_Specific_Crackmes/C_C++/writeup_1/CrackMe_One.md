# CrackMe One

> A username/serial validator whose "complex math" is a single custom FNV-style 64-bit hash of the username, rendered as 16 hex digits. Solved by inverting the final comparison jump (patch).

## Metadata

| Field        | Value |
|--------------|-------|
| Source       | Local archive — `Language_Specific_Crackmes/C_C++/8` |
| Author       | unknown |
| Language     | C/C++ |
| Architecture | x86-64 |
| Platform     | Windows (console) |
| Difficulty   | ~3.5 / 6 (self-assessed) |
| Quality      | 4 / 6 (self-assessed) |
| Date solved  | 2026-09-06 |
| Time spent   | ~0.5h |
| Tools        | IDA Pro (Hex-Rays), x64dbg, DIE |
| Solve type   | patch |

## 1. Goal

The program asks for two inputs on the console:

```
  Username: <4..32 chars>
  Serial  : <16 hex chars>
```

On a correct pair it prints a green `[+] <success>` line; on a wrong pair a red `[X] <failure>` line. All user-facing strings are obfuscated in the binary (see Recon), so none of them show up in a naive strings dump. The task is to reach the success path.

## 2. Triage / Recon

- **File type / compiler:** PE32+ (x86-64), MSVC. Console subsystem. Not packed.
- **Packed / protected:** No packer. Entropy normal, sections standard (`.text/.rdata/.data`). Protection is in-code: anti-debug + string obfuscation, not a packer.
- **Strings:** A plain strings pass is nearly useless — every prompt and verdict is stored XOR-encrypted. The messages are built at runtime by XOR-ing byte tables with the constant `0x5A` (loaded via SSE from `xmmword_*` blobs). To read them statically, XOR the referenced tables with `0x5A`.
- **Imports:** `SetConsoleTitleA`, `GetStdHandle`, `SetConsoleTextAttribute`, `fgets`, `printf`, `IsDebuggerPresent`, `ExitProcess`. The console-color APIs are just cosmetics for the verdict lines; `IsDebuggerPresent` plus a custom checker are the anti-analysis surface.
- **First run behavior:** Prints a banner, reads username, reads serial, prints a verdict, waits for Enter. Under a debugger it bails early with a distinct message instead of validating.

## 3. Static Analysis

Control flow of `main`, in order:

1. `SetConsoleTitleA("CrackMe One")`.
2. `debugger_check()` — called **before** any input. If it reports a debugger, `main` decodes the "[!]" anti-debug string (XOR `0x5A`) and exits `1`.
3. Read `Username` via `fgets(.., 256, stdin)`, strip trailing `\r\n`, NUL-terminate.
4. Read `Serial` the same way.
5. `debugger_check()` again, after input — same early bail.
6. Presence check on both buffers (`Length_Checker`); empty/invalid → "[!]" verdict.
7. **Username length gate:** `if ((unsigned)(len - 4) > 28)` → reject. Valid range is `[4, 32]`.
8. **Username charset gate:** per-character bitmask lookup (`0x43FFFFFF01FF9`, base offset `45`) plus the explicit `a`–`z` range. Effective allowed set is `[A-Za-z0-9_-]`.
9. **Serial length gate:** `Length_Checker(serial) == 16`.
10. **Serial charset gate:** bitmask (`0x7E0000007E03FF`, base offset `48`) → hex digits `[0-9A-Fa-f]` only.
11. **Serial parse:** `strtoull(serial, &end, 16)` → 64-bit value `v26`; the end-pointer is checked so all 16 chars must be consumed.
12. `IsDebuggerPresent()` — third anti-debug gate, same bail.
13. **Key derivation** (the "complex operations"): a custom 64-bit hash over the username, combined with a character-class fingerprint and the length, then compared to `v26`.

Annotated key-derivation snippet (cleaned from Hex-Rays):

```c
// --- stage 1: custom FNV-64-style mix over the username ---
uint64_t h1 = 0x0123456789ABCDEF;          // seed A
uint64_t h2 = 0xFEDCBA9876543210;          // seed B
for (int i = 0; i < len; i++) {
    uint8_t b = username[i];
    uint64_t t = 0x100000001B3ULL *         // 0x100000001B3 == FNV-64 prime
                 (h1 ^ ((uint64_t)b << (8 * (i % 7))));
    uint64_t u = t + (b ^ ror64(h2, 3));
    h2 = (uint64_t)(-(int64_t)u) - 0x61C8864E7A14357AULL; // golden-ratio-family const
    h1 = t ^ u;
}
uint64_t mixedA = finalize(h1 ^ h2);        // sub_...61A40 (64-bit avalanche)

// --- stage 2: character-class fingerprint ---
int letters = 0, digits = 0, others = 0;    // [A-Za-z] / [0-9] / rest
for (int i = 0; i < len; i++) classify(username[i], &letters, &digits, &others);

// --- stage 3: fold length + classes into the hash, finalize, compare ---
uint64_t folded = mixedA ^ ((uint64_t)others
               ^ (((uint64_t)digits
               ^ (((uint64_t)letters << 16))) << 16)) << 16;
uint64_t expected = finalize(0x12345678ULL * len + folded);

if (expected == serial_value /* v26 */)     // ORIGINAL: equal => accept
    success();
else
    fail();
```

**Algorithm in plain words:** the serial is not stored — it is *computed* from the username. Hash the bytes with a custom FNV-64 mix, fold in how many letters/digits/other characters the name has and its length, run a final avalanche, and expect the result as 16 hex digits. Deterministic input → deterministic serial.

## 4. Dynamic Analysis

- **Breakpoints:** one, on the final comparison in stage 3 (the `cmp` feeding the accept/reject branch).
- **Observed values:** at the breakpoint, `v26` holds the parsed serial and the other operand holds `expected`. Feeding any 4–32 char alphanumeric username and any 16 hex serial lands cleanly on this compare, confirming stages 1–3 run to completion before the decision.
- **Anti-debug encountered:** three gates — `debugger_check()` (×2, pre- and post-input) and `IsDebuggerPresent()`. All three route to the same early "[!]" exit, so they are trivial to neutralize (patch the checker's return, or set the PEB `BeingDebugged` flag to 0 / use ScyllaHide). There is also a **tamper/anti-patch guard**, `sub_...610A0`, evaluated *after* the verdict: if it returns non-zero the process calls `ExitProcess(0xBAD)`. This is the one that punishes a careless patch — it must be satisfied (or neutralized) for a patched binary to exit cleanly.

## 5. The Core Insight

All the geometry of the code is misdirection. Strip the anti-debug noise and the XOR-string theater and you are left with one fact: **the serial is a pure function of the username, and validation is a single 64-bit equality.** The entire check funnels through one `cmp`, so flipping the single conditional branch that reads its result is enough to make any well-formed serial pass.

## 6. Solution

**Solve type: patch.** The check funnels into one conditional jump after the final comparison; inverting it makes the validator accept any well-formed serial.

- Instruction: the `jnz` (opcode `0x75`) taken when `expected != serial`.
- Change: `0x75` → `0x74` (`jnz` → `jz`), so the accept path is taken for any serial that clears the length/charset gates.
- What it bypasses: only the final equality. The length gate `[4,32]`, charset gate `[A-Za-z0-9_-]`, and the 16-hex-digit serial format still apply, so a valid-shaped serial (16 hex chars) is still required as input.
- Caveat handled: the post-verdict guard `sub_...610A0` → `ExitProcess(0xBAD)` can detect the modified image, so it has to be neutralized (force its return to 0 / patch out the `ExitProcess` path) — otherwise the patched binary exits with `0xBAD` instead of printing the success line.

**Verification:** with the branch inverted and the tamper guard neutralized, the binary prints the green `[+]` success line and exits `0`.

## 7. Key Takeaways

- **New technique learned — unsigned range idiom:** `(unsigned)(X - A) > B` is TRUE exactly when `X` is *outside* `[A, A+B]`; i.e. the passing range is `A ≤ X ≤ A+B`. Here `(len-4) > 28` ⇒ username length `[4,32]`, and `(len-16)` logic ⇒ serial length `== 16`. Added to `RE_Personal_Notes`.
- **Constant recognition pays off:** `0x100000001B3` is the FNV-64 prime — spotting it immediately reframed the "complex operations" as a known hash family rather than something to trace blindly. `0x61C8864E7A14357A` (golden-ratio family) and `0x12345678` are decorative magic constants. Added to the magic-constant table.
- **String obfuscation:** single-byte XOR (`0x5A`) over SSE-loaded tables. Naive `strings` returns nothing useful; XOR the referenced blobs with `0x5A` to read every prompt/verdict.
- **Mistakes / time sinks:** the SSE `xmmword` string-decode blocks are visually noisy and repeat for every message — easy to mistake for real logic. They are just `printf` decoration. The real program is: two gates + one hash + one compare.
- **Reusable trick for next time:** on a serial validator, find the single decision `cmp` first — everything before it is input validation, everything the hash feeds is the key check. And check for a post-verdict integrity guard **before** patching (`ExitProcess(0xBAD)` here) so the patch does not get punished.

## 8. Artifacts

- **Patch:** `jnz`→`jz` (`0x75`→`0x74`) at the stage-3 decision jump; neutralize `sub_...610A0` tamper guard to avoid `ExitProcess(0xBAD)`.
- **Input constraints:** username `[A-Za-z0-9_-]`, length `[4,32]`; serial `[0-9A-Fa-f]`, length `16` → parsed as a 64-bit hex value.
- **String decode:** `plaintext[i] = table[i] ^ 0x5A`.
