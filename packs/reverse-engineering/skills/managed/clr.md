---
id: managed/clr
title: Managed .NET assemblies and application bundles
when: A PE declares a CLR header, or a native PE looks like a .NET launcher.
needs: [triage/quarantine]
tools: [pe_info, pe_directories]
requires_host: [strings, floss]
---

Use when `pe_info` shows `declares_clr_runtime_header`, or a native PE carries a large overlay and a runtime-loader import set. Not for reading native code (`code/static-inspection`), and not for a conclusion from decompiled C#.

1. **Read the CLR header.** `pe_directories` gives `clr`: `flags`, `runtime_version`, `entry_point`, `metadata.version_string` and the metadata streams. `runtime_version` is the header's own format version, not the .NET release the assembly targets; `metadata.version_string` (such as `v4.0.30319`) names the runtime the metadata was built against, a claim of the build and not the release that would load it. `ILONLY` set with no native entry point fits an IL-only assembly. A native entry point (`is_native_rva` true) or a `managed_native_header` means native code sits beside the IL: read that part as native, and say the IL may not be the code that runs. An `mscoree.dll` import (`_CorExeMain`, `_CorDllMain`) is the loader stub, not native code.
2. **A managed file's import table is the loader stub, not its capabilities.** Do not map `pe_info` imports to behaviour here; the calls are IL references, which this pack does not read.
3. **This pack has no metadata-table reader.** The assembly name and version, type and method names, IL, resources and P/Invoke declarations are not available from it: write "not read". The entry point is a token (`token_table`, `token_row`), not a name. A .NET decompiler or metadata reader would have to be supplied by the operator; none is declared.
4. **Decompiled C# is a reconstruction.** Names can be obfuscated or generated; the IL and the metadata are the evidence. Anything you read from a reconstruction is a lead until you can cite IL.
5. **Strings.** User strings live in the `#US` heap as UTF-16; `strings -a -e l -t x SAMPLE` shows them with offsets (FLOSS support for managed code depends on its version: check `floss -h` and record what ran).
6. **Strong naming** (`STRONGNAMESIGNED`, a non-empty `strong_name_signature_field`) is a declaration. It is not a check that the signature verifies, and it is not publisher trust. Authenticode is not verified either (`pe/signature-and-resources`).
7. **Bundles.** A native apphost with assemblies appended in the overlay (`overlay_offset`, `overlay_bytes`) is a candidate for a single-file bundle; this pack has no bundle reader, so record the overlay range and stop there. Do not run the apphost to extract it.

Sensitive output: user strings and resources can hold credentials; write `strings` output to `$OUT` in a job with `secret_output: true` and cite offsets and lengths.

Shows: CLR flags, runtime version, metadata root and stream sizes, overlay range. Does not show: assembly identity, what any method does, strong-name validity, that the IL is what runs. Record: `pe_directories` status and problems, `clr` fields, what was not read.
