# Reverse Engineering Writeups

A growing collection of my reverse-engineering writeups: crackmes, CTF reversing challenges, and malware analysis.

I started reverse engineering in June 2026. For a while I solved crackmes and CTF challenges privately, only for myself. I later decided there was no reason to keep that work closed, so this repository publishes those writeups in a consistent, readable format. The focus is now shifting from crackmes to real-world malware analysis — the crackme series was the training phase.

## Structure

- `Crackme_writeups/` — crackme writeups, numbered **by ascending difficulty** (`writeup_01` is the easiest, `writeup_27` the hardest). Each folder holds the writeup markdown, the binary (zipped where it is large), and the referenced screenshots.
- `Malware_Analysis/` — the current and ongoing focus. Writeups analysing real-world samples, grouped by family: `Ransomware/`, `InfoStealers/`, `RATs/`, `Loaders/`, `Banking_Trojans/`, `Rootkits/`, `Cryptominers/`, `Misc/`.
- `CTF_Reversing/` — reversing challenges from CTF competitions.

## Format

Every writeup follows one fixed template: metadata, triage/recon, static analysis, dynamic analysis, the core insight, the solution, key takeaways, and artifacts. Where it is safe to do so, the original binary is kept next to its writeup.

## Crackmes

Twenty-seven writeups in ascending difficulty. Writeups **04, 12, 15, 16, 17, 20, 21** are sub-challenges of the same binary (WeekDaysBased — a .NET shell over a native `helper.dll` whose `xor0_fun` export dispatches on `wDayOfWeek` to seven per-weekday handlers); each is self-contained and includes a short note of the shared architecture inline.

- [01 — MultiTool, Plaintext Credential Check (.NET Managed)](Crackme_writeups/writeup_01/MultiTool_Plaintext_Credential_Check.md) — unobfuscated WinForms login; credentials read directly from the decompiled `button1_Click` handler. _Difficulty 1.0 / 6._
- [02 — chip-8, Plaintext Serial in the Managed DLL](Crackme_writeups/writeup_02/chip8_Plaintext_Serial.md) — .NET Core apphost `.exe` + managed `.dll`; serial compared to a plaintext literal in `Program.Main`. _Difficulty 1.0 / 6._
- [03 — gui-crackme, Plaintext Activation Key (.NET Managed)](Crackme_writeups/writeup_03/gui_crackme_Plaintext_Activation_Key.md) — .NET Framework WinForms; activation key compared to a plaintext literal in the button handler. _Difficulty 1.0 / 6._
- [04 — WeekDaysBased: Monday, plaintext serial](Crackme_writeups/writeup_04/Monday_Plaintext_Serial.md) — fixed 19-character serial (A-10 Warthog), username ignored. _Difficulty 1.0 / 6._
- [05 — veryeasycrackme (Go), little-endian 8-byte password](Crackme_writeups/writeup_05/veryeasycrackme_Go_LittleEndian_Password.md) — first Go target; find `main.main` past the runtime bootstrap, then the check is one 8-byte compare whose constant `'321abmis'` reverses to `simba123`. _Difficulty 1.0 / 6._
- [06 — Fun CrackMe, Caesar +4 keygen (.NET Managed)](Crackme_writeups/writeup_06/Fun_CrackMe_Caesar_Shift.md) — unobfuscated console app; tangled per-character arithmetic that folds to a `+4` shift, so password = username shifted +4. _Difficulty 1.5 / 6._
- [07 — goCrackMe (Go), username-derived password](Crackme_writeups/writeup_07/goCrackMe_Username_Base64_Password.md) — no stored secret; password = Windows username + `base64("C:\Users\<USERNAME>")`, reconstructed from the environment. _Difficulty 1.5 / 6._
- [08 — G0l4ng_1s_C00l (Go), login panel with little-endian credentials](Crackme_writeups/writeup_08/G0l4ng_1s_C00l_Login_LittleEndian_Credentials.md) — username/password checked as byte-reversed DWORD/WORD/byte chunks (`admin` / `kaka123`), then a restricted `ls`-only shell whose listed filename decodes (decimal ASCII) to `flag{S1mple_g0l4ng_b1n4ry}`. _Difficulty 1.5 / 6._
- [09 — HeavensGate, 32-bit shell running 64-bit code](Crackme_writeups/writeup_09/HeavensGate_ModeSwitch_KEY.md) — debug-build PE32 that far-returns to selector `0x33` to switch into 64-bit mode; the validator only reads correctly as x86-64, and the key `h34vEn` falls out of four byte checks plus a two-equation system. _Difficulty 2.0 / 6._
- [10 — CrackMePlease, junk obfuscation over a byte compare](Crackme_writeups/writeup_10/CrackMePlease_Obfuscated_Constant_License.md) — MSVC C++ padded with dead calls, decoy strings (`"Maybe check here?"`) and a never-true condition; the real validator builds `"3f3"`+thirteen `'9'` in place, so the key is `3f39999999999999`. _Difficulty 2.0 / 6._
- [11 — crackme, XOR-0x5A string obfuscation](Crackme_writeups/writeup_11/crackme_XOR0x5A_String_Obfuscation.md) — clean MSVC C++ console target; every string in the program (banner, prompt, success, failure, and the expected license) is XOR-0x5A-encoded in SIMD immediates and decoded at runtime into `std::string`. Key `I_CRACKED_IT_2025_LOL!` recovered both statically and dynamically. _Difficulty 2.0 / 6._
- [12 — WeekDaysBased: Tuesday, external 32-byte file constraint](Crackme_writeups/writeup_12/Tuesday_External_File_Constraint.md) — external `xor0.rox` file must be crafted by the solver; small arithmetic system ending in `(sum × K) ⊕ last4 == 0xFACE0FB0`. _Difficulty 2.5 / 6._
- [13 — Reversed-Username Credential Validator](Crackme_writeups/writeup_13/Reversed_Username_Credential_Validator.md) — no stored password; the accepted password is derived from the reversed username and must be exactly twice its length. _Difficulty 3.0 / 6._
- [14 — VEH-Guarded SipHash License Validator](Crackme_writeups/writeup_14/VEH_Guarded_SipHash_License_Validator.md) — anti-debug hidden in a Vectored Exception Handler (`ud2`), rdtsc timing, ThreadHideFromDebugger; keyed SipHash with a one-way gate, solved by patching the comparison constant. _Difficulty 3.0 / 6._
- [15 — WeekDaysBased: Wednesday, machine-specific T10- suffix](Crackme_writeups/writeup_15/Wednesday_Machine_Specific_Suffix.md) — serial of form `T10-XXXX`, suffix derived from username and per-machine `cpuid`; recovered dynamically. _Difficulty 3.0 / 6._
- [16 — WeekDaysBased: Thursday, uppercase-hex serial](Crackme_writeups/writeup_16/Thursday_Uppercase_Hex_Serial.md) — serial parsed as 8-digit hex; parser accepts A–F only (not a–f); target recovered dynamically for a chosen input. _Difficulty 3.0 / 6._
- [17 — WeekDaysBased: Sunday, crypto decoy over a plain memcmp](Crackme_writeups/writeup_17/Sunday_Crypto_Decoy_Memcmp.md) — RC6 key schedule and chained hashing all feed a single 16-byte `memcmp`; the target is read from memory. _Difficulty 3.0 / 6._
- [18 — CrackMe One](Crackme_writeups/writeup_18/CrackMe_One.md) — username/serial validator built on a custom FNV-64-style hash; solved by inverting the final comparison. _Difficulty 3.5 / 6._
- [19 — Bytecode-VM Key Validator](Crackme_writeups/writeup_19/Bytecode_VM_Key_Validator.md) — a custom switch-dispatch bytecode VM that XORs the key with 0x11 and compares to a fixed string; key recovered by inverting the XOR. _Difficulty 3.5 / 6._
- [20 — WeekDaysBased: Friday, MD5(username) == serial (keygen)](Crackme_writeups/writeup_20/Friday_MD5_Serial.md) — XOR-obfuscated comparison that reduces by algebra to a straight digest-equals-serial check; forward MD5 gives a full keygen. _Difficulty 3.5 / 6._
- [21 — WeekDaysBased: Saturday, Adler-32 + numeric constraints (keygen)](Crackme_writeups/writeup_21/Saturday_Adler32_Numeric_Constraints.md) — GUID-shaped serial `AAAAAAAA-BBBB-CCCC-DDDD-EEEE`, all forward-computable. _Difficulty 3.5 / 6._
- [22 — Saenro CTF, tiny PE64, patch the hardcoded constant](Crackme_writeups/writeup_22/Saenro_CTF_Patch_Constant.md) — 666-byte hand-crafted PE (no normal sections); success is an XOR chain equaling zero, solved by patching the hardcoded qword (little/big-endian gotcha). _Difficulty 3.5 / 6._
- [23 — virtualmachine, VM-obfuscated key check](Crackme_writeups/writeup_23/VirtualMachine_VM_Obfuscation_KEY.md) — custom bytecode interpreter (~39 opcode handlers, most of them dead) hiding a single register-equality test; constant `0x10F2C` → key `69420`. _Difficulty 3.5 / 6._
- [24 — license-cli (Go, analysis only)](Crackme_writeups/writeup_24/license_cli_UPX_SHA256_XOR_AntiTamper.md) — unpacked with `upx -d`; one-way SHA-256 digest gate and an underdetermined repeating-XOR flag stage, plus an anti-tamper battery neutralised by patching one aggregator. Scheme fully mapped; not solved (would require guessing). _Difficulty not rated (slots at ~3.5)._
- [25 — Layered Anti-Debug Key Validator](Crackme_writeups/writeup_25/Layered_AntiDebug_Key_Validator.md) — layered encrypted data files and heavy anti-debug; the key is recovered from memory at the comparison. _Difficulty 4.5 / 6._
- [26 — RE02, 32-bit Layered Constraint Validator](Crackme_writeups/writeup_26/Reversed_RE02_Layered_Constraint_Validator.md) — 32-bit, anti-decompilation (opaque-predicate overlap) and a data-poisoning anti-debug; 54 chained arithmetic layers over a 49-byte input, scheme fully recovered. _Difficulty 4.5 / 6._
- [27 — pcrackme, reflective DLL + direct syscalls (full defense stack)](Crackme_writeups/writeup_27/pcrackme_ReflectiveDLL_DirectSyscalls_FullDefenseStack.md) — a hardened Windows x64 crackme: opaque pointer-table call sites, a direct-syscall trampoline through `gs:[0]`/`gs:[0x150]`, reflective DLL injection into the process itself (with a `0x404040` sync sentinel), MBA (Mixed Boolean Arithmetic) on the saved return address as a soft tamper check, and a late `ThreadHideFromDebugger`; solved by neutralising the two decision gates at runtime (ZF flips + RIP skip) — defense stack mapped end-to-end, password not pursued. _Difficulty 5.2 / 6._

## Malware Analysis

The current and ongoing focus. Writeups appear under one subfolder per malware family.

- [Ransomware/](Malware_Analysis/Ransomware/) — file-encrypting / extortion families.
- [InfoStealers/](Malware_Analysis/InfoStealers/) — credential, cookie, and crypto-wallet exfiltration.
- [RATs/](Malware_Analysis/RATs/) — remote-access trojans and interactive backdoors.
- [Loaders/](Malware_Analysis/Loaders/) — droppers and stagers delivering follow-on payloads.
- [Banking_Trojans/](Malware_Analysis/Banking_Trojans/) — web-injects, man-in-the-browser, and banking fraud families.
- [Rootkits/](Malware_Analysis/Rootkits/) — user-mode and kernel-mode persistence/stealth tooling.
- [Cryptominers/](Malware_Analysis/Cryptominers/) — unauthorised coin-mining payloads.
- [Misc/](Malware_Analysis/Misc/) — samples that do not cleanly fit the categories above.
