# Reverse Engineering Writeups

A growing collection of my reverse-engineering writeups: crackmes, CTF reversing challenges, and malware analysis.

I started reverse engineering on 2026-06-05. For a while I solved crackmes and CTF challenges privately, only for myself. I later decided there was no reason to keep that work closed, so this repository publishes those writeups in a consistent, readable format. It will grow as I solve more.

## Structure

- `Language_Specific_Crackmes/` — crackmes grouped by target language: `C_C++`, `DOT_NET` (Managed / AOT), `Go`, `Rust`, `WASM`, plus `Mixed` (targets that span managed + native, e.g. a .NET shell over a native DLL)
- `CTF_Reversing/` — reversing challenges from CTF competitions
- `Malwares/` — malware analysis writeups

## Format

Every writeup follows one fixed template: metadata, triage/recon, static analysis, dynamic analysis, the core insight, the solution, key takeaways, and artifacts. Where it is safe to do so, the original binary is kept next to its writeup.

## Index

### Crackmes — C/C++
- [CrackMe One](Language_Specific_Crackmes/C_C++/writeup_1/CrackMe_One.md) — username/serial validator built on a custom FNV-64-style hash; solved by inverting the final comparison.
- [Layered Anti-Debug Key Validator](Language_Specific_Crackmes/C_C++/writeup_2/Layered_AntiDebug_Key_Validator.md) — layered encrypted data files and heavy anti-debug; the key is recovered from memory at the comparison.
- [Reversed-Username Credential Validator](Language_Specific_Crackmes/C_C++/writeup_3/Reversed_Username_Credential_Validator.md) — no stored password; the accepted password is derived from the reversed username and must be exactly twice its length.
- [RE02 — 32-bit Layered Constraint Validator](Language_Specific_Crackmes/C_C++/writeup_4/Reversed_RE02_Layered_Constraint_Validator.md) — 32-bit, anti-decompilation (opaque-predicate overlap) and a data-poisoning anti-debug; 54 chained arithmetic layers over a 49-byte input, scheme fully recovered.
- [Bytecode-VM Key Validator](Language_Specific_Crackmes/C_C++/writeup_5/Bytecode_VM_Key_Validator.md) — a custom switch-dispatch bytecode VM that XORs the key with 0x11 and compares to a fixed string; key recovered by inverting the XOR.
- [VEH-Guarded SipHash License Validator](Language_Specific_Crackmes/C_C++/writeup_6/VEH_Guarded_SipHash_License_Validator.md) — anti-debug hidden in a Vectored Exception Handler (ud2), rdtsc timing, ThreadHideFromDebugger; keyed SipHash with a one-way gate, solved by patching the comparison constant.
- [Saenro CTF — Tiny PE64, patch the hardcoded constant](Language_Specific_Crackmes/C_C++/writeup_7/Saenro_CTF_Patch_Constant.md) — 666-byte hand-crafted PE (no normal sections); success is an XOR chain equaling zero, solved by patching the hardcoded qword (little/big-endian gotcha).

### Crackmes — .NET (Managed)
- [MultiTool — Plaintext Credential Check](Language_Specific_Crackmes/DOT_NET/DOT_NET_Managed/writeup_1/MultiTool_Plaintext_Credential_Check.md) — unobfuscated WinForms login; credentials read directly from the decompiled `button1_Click` handler.
- [chip-8 — Plaintext Serial in the Managed DLL](Language_Specific_Crackmes/DOT_NET/DOT_NET_Managed/writeup_2/chip8_Plaintext_Serial.md) — .NET Core apphost `.exe` + managed `.dll`; serial compared to a plaintext literal in `Program.Main`.
- [gui-crackme — Plaintext Activation Key](Language_Specific_Crackmes/DOT_NET/DOT_NET_Managed/writeup_3/gui_crackme_Plaintext_Activation_Key.md) — .NET Framework WinForms; activation key compared to a plaintext literal in the button handler.
- [Fun CrackMe — Caesar +4 of the username (keygen)](Language_Specific_Crackmes/DOT_NET/DOT_NET_Managed/writeup_4/Fun_CrackMe_Caesar_Shift.md) — unobfuscated console app; tangled per-character arithmetic that folds to a `+4` shift, so password = username shifted +4.

### Mixed — WeekDaysBased Crackme (one binary, day-dispatched sub-challenges)
A single binary — a .NET shell (`WeekDaysBased_Crackme.exe`) over a native `helper.dll` whose `xor0_fun` export runs a **different challenge for each weekday**. Every entry below is the *same* binary, a different internal sub-challenge. Start with the [category overview](Language_Specific_Crackmes/Mixed/README.md).
- [Monday — plaintext serial (A-10 Warthog)](Language_Specific_Crackmes/Mixed/WeekDaysBasedCrackme_Monday_sub_writeup_1/Monday_Plaintext_Serial.md)
- [Tuesday — external 32-byte file constraint (`xor0.rox`)](Language_Specific_Crackmes/Mixed/WeekDaysBasedCrackme_Tuesday_sub_writeup_2/Tuesday_External_File_Constraint.md)
- [Wednesday — machine-specific `T10-` suffix (cpuid)](Language_Specific_Crackmes/Mixed/WeekDaysBasedCrackme_Wednesday_sub_writeup_3/Wednesday_Machine_Specific_Suffix.md)
- [Thursday — uppercase-hex serial](Language_Specific_Crackmes/Mixed/WeekDaysBasedCrackme_Thursday_sub_writeup_4/Thursday_Uppercase_Hex_Serial.md)
- [Friday — MD5(username) serial, XOR-obfuscated (keygen)](Language_Specific_Crackmes/Mixed/WeekDaysBasedCrackme_Friday_sub_writeup_5/Friday_MD5_Serial.md)
- [Saturday — Adler-32 + numeric constraints (keygen)](Language_Specific_Crackmes/Mixed/WeekDaysBasedCrackme_Saturday_sub_writeup_6/Saturday_Adler32_Numeric_Constraints.md)
- [Sunday — crypto (RC6) decoy over a plain memcmp](Language_Specific_Crackmes/Mixed/WeekDaysBasedCrackme_Sunday_sub_writeup_7/Sunday_Crypto_Decoy_Memcmp.md)
