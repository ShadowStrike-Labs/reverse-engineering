# Reverse Engineering Writeups

A growing collection of my reverse-engineering writeups: crackmes, CTF reversing challenges, and malware analysis.

I started reverse engineering on 2026-06-05. For a while I solved crackmes and CTF challenges privately, only for myself. I later decided there was no reason to keep that work closed, so this repository publishes those writeups in a consistent, readable format. It will grow as I solve more.

## Structure

- `Language_Specific_Crackmes/` — crackmes grouped by target language: `C_C++`, `DOT_NET` (Managed / AOT), `Go`, `Rust`, `WASM`
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
