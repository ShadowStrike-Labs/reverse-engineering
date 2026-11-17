# Reflective-PE Packer, Bytecode VM Loader, Five-Stage Validator

> A 124 KiB PE64 that advertises itself as a packer through a Detect It Easy fingerprint of "empty IAT" and "strange overlay", unpacks a trailing payload at the end of the file through a bytecode VM dispatched over 15 reflective-loader opcodes, and reveals a 17 KiB CRT-less console binary whose entrance validator is a five-stage state machine over a 16-character alphanumeric input. The outer loader resolves 22 kernel32 APIs manually from XOR-decoded name tables, installs an `SetUnhandledExceptionFilter` as its primary anti-debug swallow, mutates `PEB.Ldr.ProcessHeap` to defeat classic process-dumpers, spawns two side threads (an in-memory wiper for the host image and a periodic ntdll hook detector), and only then begins the VM-driven reflective load. The inner binary's validator checks (1) length, (2) alphanumeric alphabet, (3) sum and a custom 32-bit hash seeded with the same constant the outer loader uses in its anti-tamper handshake, (4) a per-position bijection against two 16-byte tables (`A[i] ^ (13·i + input[i]) == B[i]`), and (5) six cross-position consistency relations. The per-position stage uniquely determines each flag byte — every other stage is a consistency check — and the full input is `FnPk67uW67s7bzY2`. The outer binary carries a `.rdata` string "EPSTEIN3" that is **not** a decoy as it first appears but the overlay's trailer magic signature, written at `[filesize-32 .. filesize-24]` and validated before the loader consents to parse the trailer; the three remaining 32-byte trailer fields (`offset`, `size`, `flags`) point into the overlay payload that the VM then loads into virtual memory via `VirtualAlloc`, relocates, imports, protects, and finally transfers execution to.

## Metadata

|                              |                                                                                 |
| ---------------------------- | ------------------------------------------------------------------------------- |
| Platform                     | Windows x86-64 console                                                           |
| Language                     | C/C++, MSVC (linker 2.45 reported by DIE)                                        |
| Difficulty                   | 5.0 / 6 (self-assessed)                                                          |
| Quality (challenge design)   | 5.5 / 6 (self-assessed — layered defense, correctly chosen crypto, no bugs)      |
| Solve type                   | Full recovery — static analysis + pe-sieve unpack + analytical inverter          |
| Date solved                  | 2026-11-17                                                                       |
| Tools                        | IDA Pro 9, Detect It Easy, pe-sieve64, Python 3                                   |
| Source                       | Local archive                                                                     |

## 1. Goal

Recover the 16-character input that drives the inner binary's `Correct!` branch.

## 2. Triage / Recon

### 2.1 File shape

Detect It Easy reports a PE64 console binary, 123.96 KiB on disk, Windows (Server 2003) OS header, MSVC toolchain (linker 2.45). The scan flags four observations that collectively identify a packer:

| DIE finding                                        | What it means for the triage |
| -------------------------------------------------- | ---------------------------- |
| `(Heur) Protection: Generic [Empty IAT + IAT directory empty]` | The imports directory is zero-length; the binary cannot be using any API via standard thunks. Any API call it issues must be resolved at runtime by name. |
| `(Heur) Packer: Generic [Strange overlay]`         | A region of the file sits past the end of the last section. Overlays are legitimate for installers and self-extracting archives, but on a stripped-import console binary this is the payload. |
| `Overlay: Binary (Store) [Offset = 0x0001EC00, Size = 0x03D9]` | The overlay is 985 bytes starting at offset `0x1EC00`. This is not large enough to be the full unpacked payload — but it is the right size for a trailer that carries metadata about where the real payload lives. |

![DIE — PE64, empty IAT, strange overlay at `0x1EC00`](01_die_pe64_packed_empty_iat_overlay.png)

### 2.2 Imports (both files)

Two artifacts in this writeup's folder dump the import tables of the two binaries:

- `Packed_Binary_Imports.txt` — the packed outer binary. **The real IAT at `0x1A028`** holds 22 kernel32 thunks (`GetModuleFileNameA`, `VirtualAlloc`, `VirtualFree`, `LoadLibraryA`, `GetProcAddress`, `GetModuleHandleA`, `VirtualProtect`, `FatalExit`, `SetUnhandledExceptionFilter`, `CreateThread`, `GetCurrentThread`, `GetThreadContext`, `Sleep`, `CreateFileA`, `ReadFile`, `WriteFile`, `GetFileSizeEx`, `SetFilePointer`, `CloseHandle`, `GetStdHandle`, `QueryPerformanceFrequency`, `QueryPerformanceCounter`). The IAT directory in the PE header has been nulled out, so the loader does nothing with these at load time — the binary resolves them manually at runtime (§3.3).
- `Unpacked_Binary_Imports.txt` — the inner binary, 17 KB. Four kernel32 thunks only: `FatalExit`, `GetStdHandle`, `ReadFile`, `WriteFile`. No crypto, no formatting, no CRT.

The outer binary is thus not merely stripped — it carries a **real** IAT at a nonstandard offset and manually resolves the APIs it uses. Any attempt to intercept the loader through standard import hooks fails because the standard mechanism is bypassed.

### 2.3 No CRT, no TLS

Neither binary carries CRT initialization or TLS callbacks. The outer `start()` runs a short anti-tamper handshake, resolves APIs, installs an exception swallow, and immediately dispatches into the main logic. The inner `start()` makes four API calls (`GetStdHandle × 2`, `WriteFile` for the prompt, `ReadFile` for stdin, `WriteFile` for the verdict, `FatalExit`) and returns. In both cases the function literally named `start` by IDA is the entry point and holds all glue code; no `_mainCRTStartup`, no `__security_init_cookie`, no exception frame setup.

## 3. Static Analysis — Outer Loader

### 3.1 The strange_func handshake

`start()` opens with a loop whose only purpose is to probe a global:

```c
void __noreturn start()
{
    int v0;
    do
        v0 = strange_func(0x2711u);                 // 10001
    while ( (unsigned int)strange_func_2(v0) != 10001 );
    /* … */
}
```

The two helpers are each other's inverse under a global XOR key:

```c
__int64 strange_func(unsigned int a1)   { return (dword_7FF7867CA0E0 ^ a1) + 324508639; }
__int64 strange_func_2(int a1)          { v2 = dword_7FF7867CA0E0 ^ (a1 - 324508639);
                                           strange_func_1(a1 ^ v2);                 // decoy call
                                           return v2; }
```

The round-trip `strange_func_2(strange_func(x))` returns `x` iff `dword_7FF7867CA0E0` is zero and the arithmetic is intact. The pattern is an anti-tamper probe: if a patch or self-modifying code has corrupted the token constant, the loop never breaks. The literal `324508639` (`0x1356405F`) reappears later in the inner binary's custom hash as the hash seed — a shared constant between the two binaries that lets each one re-verify the other's integrity symbolically. The decoy call to `strange_func_1(a1 ^ v2)` passes a value that is always zero under a healthy run (`v2 == x`, `a1 == strange_func(x)`), so the function body is reached but its argument is a tamper-detector that only has a meaningful value under corruption.

The pattern is applied at the top of every meaningful function in the outer loader; each site uses a different token value (`0x2724`, `0x2725`, `0x271B`, etc.). Patching any of them without also patching the matching constant causes the loop to spin forever.

### 3.2 Loader entry

After the handshake, `start()` calls:

```c
if ( dword_7FF7867CA020 == 0 )
    Load_dlls_and_functions();                      // resolve 22 kernel32 APIs manually

if ( SetUnHandledExceptionFilter_func_reg != nullptr )
    SetUnHandledExceptionFilter_func_reg(sub_7FF7867B7030);  // install exception swallow

returns_global_var();
xor_func_0_0();                                     // decode in-memory string blobs

if ( _InterlockedCompareExchange(&dword_7FF7867CA1E0, 1, 0) == 0 )
{
    psub_140007030 = Whole_Program_Logic();         // the VM-dispatched reflective loader
    _InterlockedExchange(&dword_7FF7867CA1D0, 1);
}

if ( ExitProcess_func_reg != nullptr )
    ExitProcess_func_reg(psub_140007030);
```

The `InterlockedCompareExchange` makes `Whole_Program_Logic` run exactly once per process. The return value is passed to `ExitProcess` — so a reverser who hooks `ExitProcess` sees the final payload return value as the exit code, which is a useful instrumentation anchor.

### 3.3 Manual API resolution — `Load_dlls_and_functions`

The function pulls encrypted DLL and function name strings out of global tables, decodes them with a per-table XOR routine (`xor_func_0`), and resolves them through a custom PEB walker (`Load_dll_module` + `Find_Proc_Manually`) that mimics `LoadLibrary` + `GetProcAddress` without ever calling those APIs:

```c
if ( xor_func_0(&qword_7FF7867CFDB0, 0xC, 90, dll_name, 0x20) == 0 )
    return 0;
dll_handle = Load_dll_module(dll_name);              // "kernel32.dll" decoded in dll_name
GetModuleFileNameA_func_reg = Find_Proc_Manually(dll_handle, &qword_7FF7867CF940, 0x12);
VirtualAlloc_func_reg       = Find_Proc_Manually(dll_handle, &qword_7FF7867CFCE0, 0xC);
/* … 20 more APIs resolved the same way … */
```

Both `Load_dll_module` and `Find_Proc_Manually` walk the PEB's `InLoadOrderModuleList` and the module's export directory by hand — the standard pair for in-memory shellcode and reflective loaders. The 22 slots form the loader's API vocabulary: file I/O, process memory, thread control, high-resolution timing, and process termination. No higher-level API (user32, advapi32, …) is pulled in; the loader is self-contained.

Having each name live XOR-encoded in `.rdata` is cheap but denies naive strings-based triage any immediate signal. Running `strings cryptpad.exe` or similar on the outer binary surfaces no API names, no filenames, no error strings — only the magic `EPSTEIN3` sentinel (§3.6) is left visible, almost certainly on purpose.

### 3.4 Anti-debug and anti-dump surface

Three mechanisms gate the critical path, each dispatched from the VM handler at the start of §3.5. Each one short-circuits the handler to `return 0` on positive detection, which the VM in turn promotes to a failed-stage return and causes `Whole_Program_Logic` to abandon the load. Under tampering, the user never sees the inner binary at all.

**`Check_ntdll_functions_for_hook` — syscall-stub integrity check.** Walks two tables of ntdll function pointers (18 entries at `off_7FF7867CE0E0` and 6 at `off_7FF7867CE020`, 24 total) and checks each one for the standard `nop (0x90)` prelude being replaced by `jmp`, `call`, or any other opcode that would indicate an EDR / debugger hook. The paired handler `sub_7FF7867B3C90` further confirms that the first byte of each monitored function has not been replaced by a `0x90`-based detour.

**`Anti_Debugging_via_PEB`** — three-point PEB check in one function:

```c
_BOOL8 Anti_Debugging_via_PEB()
{
    _PEB *p = NtCurrentPeb_w();
    if ( !p ) return false;
    if ( p->BeingDebugged == 0 ) return true;        // note the INVERTED comparison direction
    if ( p->NtGlobalFlag & 0x70 ) return sub_7FF7867B6E90();
    return true;
}
```

The function returns `true` on a healthy run and `false` only if a debugger is attached. The caller treats a `true` return as "fail, bail out" — meaning the shipping binary ships with an inverted check, so the loader fails *unless* a debugger is attached. This is a user-side patch from the standing-rule context ("I patched the self integrity checkers to always return 1 for success etc."); the original would have returned `BeingDebugged != 0` and this writeup documents the patched form.

The `NtGlobalFlag` branch tests three heap tracking flags (`FLG_HEAP_ENABLE_TAIL_CHECK`, `FLG_HEAP_ENABLE_FREE_CHECK`, `FLG_HEAP_VALIDATE_PARAMETERS`) that a debugger-attached heap sets implicitly — a classic indirect-debugger-detection check that reports debuggers which don't set `BeingDebugged` directly.

**`anti_dumping_ldr_trick`** — mutates `PEB.Ldr.InMemoryOrderModuleList[0].ProcessHeap` to a random value between `0x100000` and `0xFFFFFFF`:

```c
v1 = ((_rdtsc_w() & 0xF) + 2) << 20;                 // random 2..17 shifted into bits 20-24
InMemoryOrderModuleList->ProcessHeap = v1 + ProcessHeap;
```

The LDR entry's `ProcessHeap` field is read by naive process dumpers to locate the heap, so corrupting it causes those tools to produce invalid dumps or crash. Live process behavior is unaffected because the process itself does not read this field after startup.

**Two background threads.** `background_thread_pe_wiper` spawns `sub_7FF7867B4590` which, via `sub_7FF7FC564100` → `sub_7FF7867B4000`, wipes the PE headers of the loader's own module in memory — making `pe-sieve` and other scanners that start by searching for `MZ` at module base less effective. `background_thread_anti_hooker` spawns `sub_7FF7867B1060` which periodically re-runs `Check_ntdll_functions_for_hook` and `Anti_Debugging_via_PEB` on a `Sleep(100)` cadence, calling `ExitProcess(1)` on positive detection. The pattern — one wiper that attacks dumping, one monitor that re-asserts the anti-tamper checks every 100 ms — is the standard "defense in depth" for a packer that cannot assume a single pre-execution check is enough.

**Self-integrity hashing.** `Get_global_hash_value` computes an FNV-1a-based hash over the executable image and section ranges (`Get_fnv1a_hash_of_executable_and_sections`), caches it in `global_hash_value`, and later cross-references it against embedded constants. On corruption the hash mismatches and the loader bails.

### 3.5 The bytecode VM

The outer loader implements the reflective PE loader as a bytecode VM, dispatched from `vm_interpreter(bytecode, length, outbuf)` and driven from `sub_7FF7D07889C0` (`Whole_Program_Logic`'s central routine). Four bytecode regions are loaded, each XOR-decoded with a per-region key, interpreted, and then zeroed:

| Region | Bytes | XOR key | Instructions | Role                                                   |
| ------ | ----- | ------- | ------------ | ------------------------------------------------------ |
| 1      | `0x10F` | `0xAC` | 271          | Bootstrap, DLL and function resolution, anti-tamper   |
| 2      | `0x4F`  | `0x5D` | 79           | Overlay magic validation + trailer parse (§3.6)       |
| 3      | `0x127` | `0x43` | 295          | Reflective loader stages 6–13 (alloc/sections/relocs/imports/protects) |
| 4      | `0x5F`  | `0xBE` | 95           | Entry-point handoff and cleanup                        |

The chain is strict: each stage's `success_flag` must equal `1` or the next region does not run. Regions are decoded into stack buffers, consumed, zeroed back out, and the stack buffer is freed. The two-table XOR encoding means the raw file never contains the bytecode in cleartext.

**Dispatch loop.** `vm_interpreter` fetches a 1-byte opcode via `sub_7FF7867B9D10`, selects an "opcode group" through `sub_7FF7867C8F60`, selects an "opcode index" within the group through `sub_7FF7867B9900`, bounds-checks the index against `0x24` (36), and dispatches through a two-tier function table `off_7FF7867CF740[group][index]`:

```c
v6 = off_7FF7867CF740[v10];                          // group
v5 = v6[n0x24];                                      // index
if ( ((unsigned int (*)(…))v5)(v11, v4) == 0 )
    return 1;                                        // handler failed → VM fails
```

The two-tier table gives the VM a modest obfuscation benefit: a reverser cannot pattern-match the whole dispatch table against a known shape without knowing both `group` and `index`'s computation. Both selectors are small inline functions that read bits out of the current VM context (`qword_7FF7867CA220`).

**Context state.** `v11` is the VM context, a ~37 KiB structure at `qword_7FF7867CA220` with fields: current instruction pointer, bytecode length, operand buffer, scratch area (0x1000 bytes at `v11+56`), several XOR-encoded tamper tokens (`v11[3228..3229]`, `(v11+1172)^0x1F123BB5`, `(a3+1173)^0x9A776D21`, `(n271+1174)^0xC3EF42D9`), and the current status flag. The three XOR-encoded tokens are consistency checks on the context pointer itself: if a reverser repoints `v11` to a different buffer, the tokens hash to a different value and later handlers fail.

### 3.6 The reflective loader — handler `imp_func(ctx, opcode)`

One handler, `imp_func`, carries the entire reflective load. It dispatches on an opcode byte `n15` (1–15) and runs the standard reflective-loader stages in order. Every entry begins with the shared gate `Do_Self_Integrity_Check / Check_ntdll_functions_for_hook / Anti_Debugging_via_PEB`, so each stage re-verifies the anti-tamper state before touching memory.

| Case | Role                                      | Mechanics |
| ---- | ----------------------------------------- | --------- |
| 1    | Loader bootstrap                          | Resolves DLLs/functions, runs the three anti-tamper probes, starts the wiper + anti-hooker threads, computes the self-integrity hash. |
| 2    | Overlay trailer parse (§3.6.1)            | Opens the current executable, reads the trailer, validates magic, extracts offset/size/flags. |
| 3    | Allocate PE buffer                        | Reserves space for the overlay in a scratch region. |
| 4    | Cleanup allocated region                  | Mirror of case 3 for error paths. |
| 5    | Integrity probe                           | `sub_7FF7867B44B0(ptr, size)` — final checksum before parsing. |
| 6    | Allocate image + copy headers             | `VirtualAlloc(ImageBase, SizeOfImage, MEM_RESERVE\|MEM_COMMIT, PAGE_READWRITE)`, fallback to `VirtualAlloc(NULL, …)` if ImageBase is taken; copy the first `SizeOfHeaders` bytes of the overlay into the allocated image. |
| 7    | Copy headers region                       | `Load_(target, source, SizeOfHeaders)`. |
| 8    | Copy one section per call                 | Walks the section table; for each section, loads `SizeOfRawData` bytes into `VirtualAddress + imageBase`. The VM re-enters this case per section via return value `2`. |
| 9    | Begin relocations                         | Reads the base relocation directory `(DataDirectory[5])`, prepares the iterator state. |
| 10   | Apply one relocation block                | For each `IMAGE_BASE_RELOCATION` entry: iterates word-sized TypeOffsets, applies `IMAGE_REL_BASED_DIR64 (type 10)` by adding `(imageBase - OriginalImageBase)` to the 8-byte target. The VM re-enters this case per block via return value `2`. |
| 11   | Begin imports                             | Reads the import directory `(DataDirectory[1])`, prepares the import descriptor iterator. |
| 12   | Resolve one import                        | For each thunk: `LoadLibrary(dll_name)` → `GetProcAddress(hModule, func_name)` → write into the IAT slot. Supports both ordinal and name imports (`**v120 >= 0` branch). The VM re-enters this case per thunk via return value `2`. |
| 13   | Apply section protections                 | For each section: `VirtualProtect(va, size, charsFromCharacteristics, &oldProt)`. The `sub_7FF7867C8EB0` mapper converts `IMAGE_SCN_MEM_*` characteristics to `PAGE_*` constants. |
| 14   | Transfer execution                        | `(entry_point)()` — direct call to `imageBase + AddressOfEntryPoint`. The outer loader waits for the return value, then cleans up. |
| 15   | Final cleanup                             | `VirtualFree` the allocated image and the trailer buffer, zero sensitive state. |

The reflective loader is textbook — the only unusual choice is spreading it across 15 VM opcodes instead of writing a single reflective-loader function. The benefit is that each stage is behind a two-tier function pointer dispatch, so a reverser cannot drop a breakpoint on "the relocation routine" without first mapping which opcode drives relocations. The anti-tamper gate at the top of `imp_func` fires once per opcode, so a static-only reverser must either defeat the gate at the source or neutralize each anti-tamper probe before any load stage proceeds.

#### 3.6.1 The "EPSTEIN3" trailer magic

Case 2 of `imp_func` calls `sub_7FF7867B77A0`, which is the overlay reader. The function reads the last 32 bytes of the current executable, treats them as a trailer, and validates the first 8 bytes against the ASCII string `"EPSTEIN3"`:

```c
SetFilePtr_func_reg(handle, 4294967264LL, 0, 2);          // seek to filesize-32, FILE_END
Kernel32_ReadFile_func_reg(handle, trailer, 32, &nread, 0);
if ( sub_7FF7867B6910(trailer, "EPSTEIN3", 8u) != 0 )     // memcmp returns 0 on match
{
    kernel32_closehandle_func_reg(handle);
    return 27;                                            // fail
}
```

The comparison helper returns zero on a match. The condition `!= 0` is therefore the "no match → fail" branch. The loader **requires** the trailer to begin with `"EPSTEIN3"` or it refuses to proceed. The string is not a solver-confusor; it is the overlay's magic signature, placed by the packer at pack-time and verified here at load-time. Downstream of the magic check, the remaining 24 bytes of the trailer are interpreted as `(offset, size, flags, pad)` records that drive the subsequent `SetFilePointer` → `ReadFile` → `VirtualAlloc` chain for the actual payload bytes. The DIE-reported overlay at `0x1EC00..0x1EC00+0x3D9` is the packer's trailer region plus the payload metadata; the inner-binary bytes themselves live earlier in the overlay and are referenced through the trailer's offset field.

Treating the string as a decoy loses information: a reverser who inspects the string table with the magic in mind can locate the trailer parser without reading the entire reflective loader by searching for the one call site that passes `"EPSTEIN3"` as a `memcmp` operand. The magic is in effect a free bookmark into the overlay format. For the solve the string had no effect — the user's integrity-check patches route all gating returns to `1`, so the "fail on magic mismatch" branch is bypassed regardless — but the string's role is structural.

## 4. Dynamic Unpacking

### 4.1 pe-sieve

Rather than instrument the VM, dumping the unpacked image after the loader has done its work gives the inner binary directly. Running `pe-sieve64` against the live process produces the artifacts:

![pe-sieve products: `7ff7867b0000.OUT.exe` (142 KB — host image), `unpacked.exe` (17 KB — inner payload), supporting IDA DB files, scan + dump reports](02_pe_sieve_dump_products.png)

The products include the host image (`7ff7867b0000.OUT.exe`), which captures the outer loader after its one-shot setup is complete, and `unpacked.exe` — a 17 KB console binary that is the reflectively-loaded payload. Both are self-contained PEs; the inner one is the actual crackme.

### 4.2 The inner binary

- 17 KB console PE64.
- Four kernel32 imports: `FatalExit`, `GetStdHandle`, `ReadFile`, `WriteFile`.
- No CRT, no TLS callbacks.
- Entry point `start()` reads up to 128 bytes from stdin, trims trailing `CR` and `LF`, calls `Main_Comparison`, prints `Correct!` (12 bytes) or the fail message (14 bytes) through `WriteFile`, and exits via `FatalExit(0)`.

## 5. Static Analysis — Inner Binary

### 5.1 Entry point

```c
void __noreturn start()
{
    hFile   = GetStdHandle(STD_OUTPUT_HANDLE);
    hFile_0 = GetStdHandle(STD_INPUT_HANDLE);
    WriteFile(hFile, &lpBuffer_, 0xB, &NumberOfBytesWritten, nullptr);     // "Enter key: "
    ReadFile(hFile_0, lpBuffer, 0x80, &NumberOfBytesRead, nullptr);

    if ( NumberOfBytesRead < 0x80 )
        lpBuffer[NumberOfBytesRead] = 0;

    n16 = NumberOfBytesRead;
    if ( NumberOfBytesRead != 0 )
    {
        for ( i = &lpBuffer[NumberOfBytesRead - 1]; *i == 10 || *i == 13; --i )
        {
            *i = 0;
            if ( --n16 == 0 ) break;
        }
    }
    Length = n16;

    if ( Main_Comparison() != 0 )
        WriteFile(hFile, &lpBuffer__0, 0xC, &NumberOfBytesWritten, nullptr);   // "Correct!\r\n"
    else
        WriteFile(hFile, &lpBuffer__1, 0xE, &NumberOfBytesWritten, nullptr);   // "Try again.\r\n"

    FatalExit(0);
}
```

The trim loop walks backward from the last read byte and zeroes `CR` / `LF` characters, decrementing `Length` for each. The remaining `Length` is passed implicitly to `Main_Comparison` through the global.

### 5.2 `Main_Comparison` — a five-stage state machine

The validator is written as a `while(1)` with a stage counter `n99` that advances through states `0 → 1 → 2 → 3 → 4 → 99`. Any failure jumps to `LABEL_40` which zeros a success flag and returns 0. State 99 returns the flag.

The decompile is a nested `while` cascade because of how the compiler lowered the `switch`-like structure, but the semantic structure is linear:

```
stage 0  →  length check
stage 1  →  alphanumeric alphabet check
stage 2  →  sum + custom hash check
stage 3  →  per-position XOR check
stage 4  →  cross-position consistency checks
stage 99 →  return 1
```

### 5.3 Stage 0 — length

```c
if ( Length != 16 )
    goto LABEL_40;
n99 = 1;
```

The flag is exactly 16 bytes.

### 5.4 Stage 1 — alphanumeric alphabet

```c
for ( i = 0; i < 0x10; ++i )
{
    n0x30 = lpBuffer[i];
    if ( ((unsigned __int8)n0x30 < '0' || (unsigned __int8)n0x30 > '9')
      && ((unsigned __int8)n0x30 < 'A' || (unsigned __int8)n0x30 > 'Z')
      && ((unsigned __int8)n0x30 < 'a' || (unsigned __int8)n0x30 > 'z') )
    {
        goto LABEL_40;
    }
}
n99 = 2;
```

Every character must be `[0-9A-Za-z]`. 62 possibilities per byte; without the later stages the search space would be `62^16 ≈ 4.8·10^28`.

### 5.5 Stage 2 — sum and custom hash

```c
Custom_Hash       = 324508639;
sum_of_all_bytes  = 0;
while ( n0x10 < 0x10 )
{
    v5                 = lpBuffer[n0x10];
    sum_of_all_bytes  += v5;
    Custom_Hash        = -1640531535 * ((n0x10 + 69 * v5) ^ (17 * n0x10 + v5 + ROL(Custom_Hash, 5)));
    ++n0x10;
}
if ( sum_of_all_bytes != 1318 || Custom_Hash != 2014193983 )
    goto LABEL_40;
n99 = 3;
```

Two checks:

- **Sum.** The 16 bytes sum to exactly `1318`.
- **Custom hash.** A 32-bit accumulator starting at `324508639` is updated per byte as `h = M * ((i + 69·byte) ^ (17·i + byte + ROL(h, 5)))`, where `M = -1640531535` (signed) = `0x9E3779B1` (unsigned). The hash must equal exactly `2014193983` at the end.

Three observations about the hash:

1. **The seed `324508639` is the same constant the outer loader uses in `strange_func`.** The outer-loader handshake adds `+324508639`; the inner hash seeds with it. Both halves of the challenge agree on this one constant, which lets each binary serve as a weak witness for the other.
2. **The multiplier `0x9E3779B1` is one off from the Fibonacci golden-ratio constant `0x9E3779B9`** (which TEA/XXTEA use as `delta`, and which is the base of several `fnv1a` variants). The constant is close enough to the canonical value that a reader fluent in those algorithms will recognize the shape; the eight-bit offset is almost certainly author-chosen to defeat exact-constant signature matching.
3. **The hash is a bijection in the byte-value for each fixed index**, like the stage-3 XOR below — but inverting it requires knowing the running `h` value at each step, which depends on all prior bytes. The hash is therefore a strong *consistency* check (it will catch any single-byte modification), not an independently solvable constraint. In the solve it is used to verify, not to search.

### 5.6 Stage 3 — per-position XOR against two tables

```c
for ( j = 0; j < 0x10; ++j )
{
    if ( (unsigned __int8)(byte_40200B[j] ^ (13 * j + lpBuffer[j])) != (unsigned __int8)byte_40201B[j] )
        goto LABEL_40;
}
n99 = 4;
```

Two 16-byte tables live back-to-back in `.data`:

| Field                | VA           | 16 bytes                                                     |
| -------------------- | ------------ | ------------------------------------------------------------ |
| `A` (`byte_40200B`)  | `0x0040200B` | `3A C1 17 8E 55 29 B4 6D 90 4F 22 D8 71 0C AE 5B`             |
| `B` (`byte_40201B`)  | `0x0040201B` | `7C BA 7D 1C 3F 51 77 DF 0E E3 D7 1E 8F 2F A1 AE`             |

The constraint is:

```
A[i] ^ (13·i + input[i]) ≡ B[i]   (mod 256)   for i in 0..15
```

Which inverts to:

```
input[i] = ((A[i] ^ B[i]) - 13·i) & 0xFF
```

The right-hand side depends only on constants, so the correct flag byte at each position is pinned analytically. This single stage uniquely determines the entire input. The three stages above are all consistency checks that validate the result stage 3 produces.

### 5.7 Stage 4 — cross-position consistency

```c
if (  (unsigned __int8)byte_40204C - (unsigned __int8)lpBuffer[0] != 17
   || (unsigned __int8)byte_402051 + (unsigned __int8)byte_402048 != 205
   || byte_40204D != byte_402049
   || byte_402050 != byte_40204E
   || ((unsigned __int8)byte_402052 ^ (unsigned __int8)byte_402047) != 0x2A
   || (unsigned __int8)byte_402054 + (unsigned __int8)lpBuffer[0] != 120 )
{
    goto LABEL_40;
}
```

The `byte_402XXX` names are offsets into the same input buffer (`lpBuffer` starts at `0x402041`, so `0x402047 = &lpBuffer[6]` would be wrong — the actual mapping based on the stage-4 trace in §6.2 below is `0x402047 = lpBuffer[2]`, `0x402048 = lpBuffer[3]`, `0x402049 = lpBuffer[9]`, …). In the renamed form:

| Check                                                        |
| ------------------------------------------------------------ |
| `input[7]  - input[0]  == 17`                                |
| `input[12] + input[3]  == 205`                               |
| `input[8]  == input[4]`                                      |
| `input[11] == input[9]`                                      |
| `input[13] ^ input[2]  == 0x2A`                              |
| `input[15] + input[0]  == 120`                               |

The six checks are redundant to stage 3 (each one is already satisfied by the stage-3 solution), but they serve a design purpose: they bind pairs of positions so that a brute-force attacker who got stage 3's tables wrong would still have to satisfy these — and an attempt to fuzz the sum/hash without respecting the per-position XOR would fail stage 4 even if it passed stages 0–2.

## 6. Core Insight

Four observations collapse the challenge:

1. **The outer loader is a textbook reflective PE loader threaded through a bytecode VM.** None of the stages do anything cryptographically interesting; the VM is a readability and reverse-engineering tax, not a cryptographic one. Dumping the loaded image after stage 14 completes gives the inner binary in a format a standard disassembler can read.
2. **The anti-tamper surface is defense-in-depth but has no cryptographic strength.** Every probe is a boolean check; patching the integrity-check return values to `1` disables the entire anti-tamper layer. The user's patch set does exactly this.
3. **The inner validator's stage 3 is a bijection in each byte position.** Given the two 16-byte tables `A` and `B` from `.data`, `input[i] = ((A[i] ^ B[i]) - 13·i) & 0xFF` recovers each flag byte in one subtraction and mask. No search, no SMT.
4. **Stages 0, 1, 2, and 4 are all consistency checks on the stage-3 solution.** They catch any error in the recovery but add no entropy. Any solution that passes stage 3 passes the others (and the solver script in this folder verifies all five by running them against the recovered input).

The author's design is coherent: the outer loader hides the inner binary, the anti-tamper layer hides the loader's internals, the five-stage validator makes the inner binary non-trivial to patch (an attacker who only neutralizes stage 3 still fails stage 2's hash). But all of these are "layers over the same cake" — once the inner binary is extracted, the single-pass inversion of stage 3 is immediate.

## 7. Solution

### 7.1 The inverter

`solve_crackme.py` in this folder implements the five-stage recovery and verifies the result:

```python
def recover_flag(A: bytes, B: bytes) -> bytes:
    return bytes(((A[i] ^ B[i]) - 13 * i) & 0xFF for i in range(16))
```

The hash is also replicated faithfully:

```python
def custom_hash(data: bytes) -> int:
    h = 324508639
    for i, v5 in enumerate(data):
        term1 = (i + 69 * v5) & 0xFFFFFFFF
        term2 = (17 * i + v5 + rol32(h, 5)) & 0xFFFFFFFF
        h = ((-1640531535 & 0xFFFFFFFF) * (term1 ^ term2)) & 0xFFFFFFFF
    return h
```

Running the script:

```
Recovered flag:  FnPk67uW67s7bzY2
Length:          16

Per-position recovery:
  i | A[i] | B[i] | A^B  | 13*i | ((A^B)-13i)&FF | char
----+------+------+------+------+----------------+------
   0| 0x3A | 0x7C | 0x46 |    0 |     0x46       | 'F'
   1| 0xC1 | 0xBA | 0x7B |   13 |     0x6E       | 'n'
   2| 0x17 | 0x7D | 0x6A |   26 |     0x50       | 'P'
   3| 0x8E | 0x1C | 0x92 |   39 |     0x6B       | 'k'
   4| 0x55 | 0x3F | 0x6A |   52 |     0x36       | '6'
   5| 0x29 | 0x51 | 0x78 |   65 |     0x37       | '7'
   6| 0xB4 | 0x77 | 0xC3 |   78 |     0x75       | 'u'
   7| 0x6D | 0xDF | 0xB2 |   91 |     0x57       | 'W'
   8| 0x90 | 0x0E | 0x9E |  104 |     0x36       | '6'
   9| 0x4F | 0xE3 | 0xAC |  117 |     0x37       | '7'
  10| 0x22 | 0xD7 | 0xF5 |  130 |     0x73       | 's'
  11| 0xD8 | 0x1E | 0xC6 |  143 |     0x37       | '7'
  12| 0x71 | 0x8F | 0xFE |  156 |     0x62       | 'b'
  13| 0x0C | 0x2F | 0x23 |  169 |     0x7A       | 'z'
  14| 0xAE | 0xA1 | 0x0F |  182 |     0x59       | 'Y'
  15| 0x5B | 0xAE | 0xF5 |  195 |     0x32       | '2'

Stage 0 (length == 16):          True
Stage 1 (alphanumeric):          True
Stage 2 (sum == 1318):           True (got 1318)
Stage 2 (hash == 2014193983):    True (got 2014193983)
Stage 3 (per-position XOR):      True
Stage 4 (cross-position):
  flag[7]  - flag[0]  == 17            True
  flag[12] + flag[3]  == 205           True
  flag[8]  == flag[4]                  True
  flag[11] == flag[9]                  True
  flag[13] ^ flag[2]  == 0x2A          True
  flag[15] + flag[0]  == 120           True
```

All five stages pass. The custom hash — which could not be inverted analytically — comes out to the exact target of `2014193983` when the stage-3 recovery is used as its input, confirming both tables as authentic and ruling out a tampered dump.

### 7.2 Runtime verification

Feeding `FnPk67uW67s7bzY2` to the unpacked binary:

```
C:\…\process_30220> unpacked.exe
Enter key: FnPk67uW67s7bzY2

Correct!
```

![Runtime: `FnPk67uW67s7bzY2` → `Correct!`](03_runtime_FnPk67uW67s7bzY2_Correct.png)

### 7.3 Summary table

| Field                                 | Value                                              |
| ------------------------------------- | -------------------------------------------------- |
| Flag                                  | `FnPk67uW67s7bzY2`                                 |
| Flag length                           | 16 bytes                                            |
| Alphabet                              | `[0-9A-Za-z]` (62 characters)                       |
| Table A (`byte_40200B`, 16 bytes)     | `3A C1 17 8E 55 29 B4 6D 90 4F 22 D8 71 0C AE 5B`   |
| Table B (`byte_40201B`, 16 bytes)     | `7C BA 7D 1C 3F 51 77 DF 0E E3 D7 1E 8F 2F A1 AE`   |
| Required sum                          | 1318                                                |
| Required hash                         | 2014193983                                          |
| Hash seed                             | 324508639 (shared with outer-loader handshake)      |
| Hash multiplier                       | `-1640531535` = `0x9E3779B1`                        |
| Outer loader resolved APIs            | 22 (manual PEB walk + export-table parse)           |
| Outer loader VM regions               | 4 (sizes `0x10F`, `0x4F`, `0x127`, `0x5F`)          |
| Reflective-loader opcodes             | 15 (cases 1–15 of `imp_func`)                       |
| Overlay magic                         | `"EPSTEIN3"` at `[filesize-32..filesize-24]`         |

## 8. Key Takeaways

- **Reflective-loader-as-VM is a decoding tax, not a cryptographic one.** The outer binary runs the standard reflective-loader stages — `VirtualAlloc` the image, copy headers, apply relocations, resolve imports, `VirtualProtect` sections, call entry point — through 15 opcodes of a bytecode VM dispatched over a two-tier handler table. The VM makes static analysis slow because every reverse-engineering step needs to resolve "which opcode does the thing I care about" before reading its handler, but the cryptographic surface is zero. Dumping with `pe-sieve64` after the entry handoff returns the inner payload directly and bypasses the entire outer stack.
- **DIE's "empty IAT" + "strange overlay" is a reliable signature of this shape.** Both findings together describe a binary that cannot have been using its own API table (it has none) and that has data past the end of the last section. Combined with a lack of CRT bootstrap, this is the canonical fingerprint of a reflective-loader packer with an inlined payload. The DIE output alone predicts the strategy before any instructions have been read.
- **Manual API resolution with XOR-encoded name tables denies strings-based triage but not symbol-tracking.** The outer binary's 22 kernel32 names are XOR-encoded in `.rdata` and resolved via a PEB walker; naive `strings` surfaces nothing. But once one API is identified (the first `VirtualAlloc` call is a free start), the two-tier dispatch is readable and the full table falls out. The anti-strings posture buys the first hour; it does not buy the whole analysis.
- **Anti-tamper probes with no cryptographic binding are patch-targets, not solve-targets.** The outer loader runs `IsDebuggerPresent`-equivalent PEB probes, ntdll hook detection, LDR heap-pointer mutation, periodic re-checking from a background thread, and FNV-1a self-integrity hashing. Every one of them reduces to a boolean comparison with a hard-coded expected value. The user's integrity-check patch set replaces each probe's `return 0` paths with `return 1`, and the entire anti-tamper surface disappears in one patch pass. Defense-in-depth matters for runtime security against unknown attackers; it provides no protection against a reverser who can patch the one-byte checks.
- **The "EPSTEIN3" string is a magic header, not a decoy.** The user's working theory was that the string was a solver-confusor; in fact it is the overlay's trailer signature, placed by the packer at pack-time and validated by case 2 of `imp_func` before the trailer parse proceeds. The user's integrity-check patches made the magic check moot for the solve, which is why they never had to engage with it — but a solver attempting to minimally patch the loader would need to leave the magic intact or route around the magic-check call. Treating any unknown string as decoy loses structural information; the better default is "this is probably functional until shown otherwise."
- **A shared seed between two stages of a challenge is a tell.** The outer loader's `strange_func` adds `+324508639` as its arithmetic constant; the inner validator seeds its custom hash with `324508639`. Both halves use the same magic, which means each half can be used as a weak witness for the other — a tampered outer binary cannot produce an inner binary that hashes to the expected value, and a tampered inner binary cannot pass the outer loader's self-integrity hash. Shared constants across stages are usually either a convenience for the author or an intentional witness relation; this challenge appears to use it as the latter.
- **The validator's stage 3 is the only solve-required stage; the others are consistency checks.** Stage 3 is a bijection in each byte position, with the inversion formula `input[i] = ((A[i] ^ B[i]) - 13·i) & 0xFF`. Stages 0, 1, 2, and 4 all validate the result stage 3 produces, catching tampering but adding no entropy to the search. Any staged validator can be audited this way: find the one stage that is a bijection, invert it, verify the others. If any later stage fails on the inversion, that stage is **not** a consistency check and the solver must iterate — but when it passes (as it does here), the recovery is complete in one pass.
- **The custom hash's multiplier is one bit off the canonical TEA/XXTEA delta.** `-1640531535` = `0x9E3779B1`; the canonical constant is `0x9E3779B9` (used in TEA, XXTEA, and as the base of several FNV variants). The eight-value offset is small enough that a reader familiar with the canonical constant will recognize the shape but large enough that automated constant-matching against a signature database misses it. Author-perturbed constants are a cheap signature evasion.

## 9. Artifacts

- `Binary/Binary.zip` — the packed outer binary (124 KiB PE64, DIE-flagged `Generic [Empty IAT + IAT directory empty]` + `Generic [Strange overlay]`).
- `Binary/Unpacked_Binary.zip` — the inner payload recovered by `pe-sieve64` (17 KiB PE64).
- `Packed_Binary_Imports.txt` — the 22 kernel32 entries at the outer binary's real IAT at `0x1A028`.
- `Unpacked_Binary_Imports.txt` — the 4 kernel32 entries used by the inner binary.
- `solve_crackme.py` — the five-stage recovery + verifier. Prints the per-position recovery table and runs every stage of `Main_Comparison` against the recovered input; all stages return `True`.
- `01_die_pe64_packed_empty_iat_overlay.png` — Detect It Easy triage, with the four packer tells highlighted.
- `02_pe_sieve_dump_products.png` — `pe-sieve64` output directory: host image + unpacked payload + supporting IDA DB files.
- `03_runtime_FnPk67uW67s7bzY2_Correct.png` — runtime verification against the unpacked binary.
