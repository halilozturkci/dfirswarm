---
id: elf/structure
title: An ELF file, and the Linux equivalents
when: The sample is a Linux or BSD executable, shared object or core file.
needs: [triage/quarantine]
tools: [pe_info, entropy_map]
requires_host: [r2, upx]
---

`pe_info` reads ELF as well as PE and reports the same shape of answer.

**The header** gives the class (32 or 64 bit), the endianness, the machine, and
the type: executable, shared object, core. A "shared object" that is actually a
position-independent executable is normal on a modern distribution and is not
suspicious on its own.

**The sections and the segments are two different views** and a sample can lie
in one and not the other. Section headers are optional at runtime, so a stripped
or hostile binary may have none at all while the program headers still describe
everything the loader needs. When the two disagree, trust the program headers,
because that is what the kernel reads.

**The dynamic section** carries what the PE import table carries: `DT_NEEDED`
libraries and the symbols resolved from them. `libcurl`, `libssl` and raw
sockets are the network story here.

Three Linux-specific shapes:

- **A static binary** where the rest of the estate is dynamic. It carries
  everything with it, runs on any distribution, and is what a dropped tool
  usually looks like.
- **`DT_RPATH` or `DT_RUNPATH` pointing somewhere writable**, which is a
  library-hijack waiting to happen, and `LD_PRELOAD` in a unit file, which is
  the same idea applied from outside.
- **A packed ELF**, most often UPX. The section names survive even when the
  header is mangled, and entropy makes it obvious. Use `upx -t` first; if it
  identifies the file, unpack only a copy under `work/`, preserve both hashes,
  and analyse both forms. Never overwrite the only extracted copy.

The build id in `.note.gnu.build-id` identifies a binary across rebuilds and
strippings, and is the right thing to quote when the file name and the hash both
change but you believe it is the same program.
