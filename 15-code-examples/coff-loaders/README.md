# COFF Loaders & BOF Development - Code Examples

## What is COFF?

**Common Object File Format (COFF)** is the object file format produced by Windows compilers
(MSVC `cl.exe`, MinGW `gcc`) *before* the linker combines them into a PE executable. When you
compile a `.c` file with `/c` (compile-only), the resulting `.obj` (MSVC) or `.o` (MinGW) is
a COFF object. It contains machine code, data, symbol tables, and relocation entries -- but no
imports table, no PE headers, and no entry point metadata. It is raw, unlinked code.

A COFF file is structured as:

```
+---------------------+
| COFF File Header    |  20 bytes - machine type, section count, symbol table pointer
+---------------------+
| Section Header 1    |  40 bytes each - .text, .data, .rdata, .bss, etc.
| Section Header 2    |
| ...                 |
+---------------------+
| Section Raw Data    |  Actual machine code and data bytes
+---------------------+
| Relocation Tables   |  Per-section fixup entries (what addresses need patching)
+---------------------+
| Symbol Table        |  All defined and external symbols (functions, variables)
+---------------------+
| String Table        |  Names longer than 8 characters
+---------------------+
```

## Why COFF Matters for Red Teams

Cobalt Strike's **Beacon Object Files (BOFs)** are COFF object files executed directly inside
the Beacon process. Instead of spawning a new process or injecting a DLL, a BOF is loaded,
relocated, and executed in the same thread as the Beacon -- then its memory is freed. This
concept has been adopted well beyond Cobalt Strike into open-source C2 frameworks, standalone
loaders, and post-exploitation toolkits.

Building a COFF loader means you can:

- Execute arbitrary compiled C code in-process without touching disk
- Avoid the signatures associated with `execute-assembly`, reflective DLL injection, or `CreateProcess`
- Keep your tooling modular: each capability is a tiny `.o` file, loaded on demand
- Reduce detection surface: no PE headers, no new process, no .NET runtime

## BOF Advantages Over Alternatives

| Technique | Process | Memory Artifacts | Size | Detection Risk |
|---|---|---|---|---|
| **BOF (COFF)** | Same process, same thread | Minimal -- freed after use | 1-20 KB typical | Low |
| **execute-assembly** | Fork & run (sacrificial process) | Full .NET assembly in memory | 50 KB - 5 MB | Medium-High |
| **Fork & Run (DLL)** | New process via `CreateProcess` | Full DLL, new process | 10 KB - 2 MB | High |
| **Reflective DLL** | Same process, new thread | Full DLL mapped in memory | 10 KB - 2 MB | Medium |
| **Shellcode** | Same process or injected | Raw code, no headers | 0.1 - 50 KB | Low-Medium |

BOFs win on stealth because they leave the smallest footprint: no new process for EDR to
inspect, no PE headers for memory scanners to find, and the memory is released immediately
after execution completes.

## Limitations of BOFs

- **No C runtime**: You cannot call `printf`, `malloc`, `fopen`, or any CRT function. All
  Windows API calls must go through Dynamic Function Resolution (DFR).
- **No exception safety**: A crash in a BOF crashes the entire Beacon. There is no process
  boundary to contain failures.
- **No global state**: BOFs are loaded, executed, and freed. There is no persistent state
  between invocations unless you write to Beacon's memory.
- **Single-threaded**: BOFs execute synchronously. Long-running BOFs block the Beacon.

## Files in This Section

| File | Description |
|---|---|
| [coff-format-deep-dive.md](coff-format-deep-dive.md) | Complete COFF binary format reference with C structure definitions, relocation type tables, and section flag breakdowns |
| [basic-coff-loader.md](basic-coff-loader.md) | Minimal but functional COFF loader in C (~250 lines) that parses headers, allocates sections, processes relocations, resolves symbols, and executes an entry point |
| [bof-development.md](bof-development.md) | Writing custom BOFs: beacon.h API, Dynamic Function Resolution macros, three complete example BOFs (process list, whoami, registry query), and compilation instructions |
| [coff-loader-advanced.md](coff-loader-advanced.md) | Production-quality loader with full Beacon API implementation, argument packing/parsing, structured exception handling, memory cleanup, and output capture |

## Build Environment

All examples compile with either:

```
# MSVC (Windows)
cl.exe /c /GS- source.c                    # Compile BOF
cl.exe source.c /link /out:loader.exe       # Compile loader

# MinGW (Linux cross-compile or Windows)
x86_64-w64-mingw32-gcc -c -o bof.o bof.c   # Compile BOF
x86_64-w64-mingw32-gcc -o loader.exe loader.c -lkernel32 -luser32  # Compile loader
```

## References

- Microsoft PE/COFF Specification: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- Cobalt Strike BOF documentation: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm
- TrustedSec COFFLoader: https://github.com/trustedsec/COFFLoader
- Kevin Haubris (TrustedSec) BOF development blog series
