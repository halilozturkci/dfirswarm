---
id: pe/structure
title: A PE file, and what its structure says before any code is read
when: The sample is a Windows executable, DLL, driver or .NET assembly.
needs: [triage/quarantine]
tools: [pe_info, entropy_map, timestamp_decode]
requires_host: [r2]
---

`pe_info` reads the headers without running anything. The fields that answer
questions:

**The compile timestamp** in the COFF header. It is a Unix time, it is
attacker-controllable, and it is still useful: a timestamp in the future, or
before the imports it uses existed, or identical across a family, is itself the
finding. Compare it against the Rich header, which most linkers write and most
tamperers forget.

**The sections.** Name, virtual size, raw size, and the characteristics. Two
shapes matter:
- raw size far smaller than virtual size, with high entropy: a packer, and the
  real code appears only once it has unpacked itself in memory;
- a section that is both writable and executable, which almost nothing
  legitimate needs.

**The imports.** What a binary asks the operating system for is the cheapest
capability list you will get. `WININET`, `WINHTTP` or `WS2_32` means network.
`CreateRemoteThread`, `WriteProcessMemory`, `VirtualAllocEx` together mean
injection. `CryptEncrypt` with file enumeration means ransomware. A binary with
almost **no** imports and one call to `LoadLibrary` is resolving them at runtime
to hide exactly this, and that emptiness is the signal.

**The exports** name a DLL's entry points; a service DLL exports
`ServiceMain`, and an unusual export on something claiming to be a system
library is worth a sentence. `pe_info` names the export directory but does not
list its symbols; use `r2 -2 -q -c 'iE' sample.dll` for the complete table.

**The certificate**, where there is one. `pe_info.signed` means only that the PE
has a non-empty certificate-table directory; it does **not** verify the
signature or identify the signer. Do not report it as valid. Verification needs
a trust-aware Authenticode verifier, which this image does not yet carry. A
verified signature from a real company on a malicious binary means a stolen
certificate, which is a much bigger finding than the sample.

**Resources** hold the icon, the version information — company, product,
original file name — and quite often a second executable. `pe_info` does not
parse resources; use `r2 -2 -q -c 'izz' sample.exe` to inventory their strings, and
say explicitly when resource extraction was not done. An original file name
that disagrees with the name on disk is how you match a renamed binary to its
prefetch entry. See `execution/overview` in the Windows pack.
