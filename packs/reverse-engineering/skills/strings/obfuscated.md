---
id: strings/obfuscated
title: Strings, including the ones the sample hides
when: You need addresses, paths, commands or keys out of a binary.
needs: [pe/structure]
tools: [pe_info, ioc_scan, fuzzy_hash]
requires_host: [floss, strings, ssdeep, tlsh]
---

`strings` is the first tool everybody reaches for and the one that produces the
most wrong answers, for two reasons.

**Half of what matters is not ASCII.** Windows binaries hold paths, URLs and
command lines as UTF-16LE, and a default `strings` run does not see them at all.
Use `strings -el` as well as `strings -a`, or `ioc_scan`, which does both.

**The interesting strings are usually not there.** Anything worth hiding is
stacked, XOR-ed with a one-byte key, base64-ed, or built a character at a time
at runtime. `floss` recovers those by emulating the deobfuscation routines
without running the sample, and it is the single biggest improvement available
over plain `strings` on this platform.

What to do with what comes out:

- **A string is not a behaviour.** "The binary contains `http://x/y`" is a fact
  about the file. "The binary connects to `http://x/y`" is a claim about
  behaviour, and it needs the cross-reference: which function references the
  string, and does anything call that function. `r2` answers that.
- **Check for the references, and say when there are none.** A string in the
  data section that nothing references is often a leftover from a library or
  from a previous build, and reporting it as an indicator produces a false lead
  that somebody else then has to chase.
- **Sort by section.** A URL in `.rdata` is data the program was built with. The
  same URL in a resource, or in a region that entropy says was packed, arrived a
  different way and means something different.

Encoded blobs are worth carving out and decoding in their own right: base64 that
decodes to a PE header, a PowerShell command in UTF-16LE base64, a certificate.
See `filesystem/carving` in the base pack for cutting them out.

For family clustering, run `fuzzy_hash` over the original bytes before making
any unpacked or patched copy. SHA-256 proves identity; ssdeep and TLSH are only
similarity leads. Record the digest and the tool version, and do not turn an
arbitrary similarity score into a family attribution without shared code or
structure to explain it.
