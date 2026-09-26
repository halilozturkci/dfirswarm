---
id: capabilities/mapping
title: From a file to what it can do
when: You must say what a sample is for, not just what it contains.
needs: [pe/structure]
tools: [pe_info]
requires_host: [capa, r2]
---

`capa` reads the code — not the strings — and reports named capabilities with
the evidence for each: which function, which instructions, which imports. It is
the closest thing to an automated "what is this for", and its output maps to
ATT&CK techniques.

    capa -j sample.bin        the whole report, as JSON (the image build includes the rules)
    capa -v sample.bin        with the address behind each match

**Quote the evidence, not the label.** `capa` saying "create a process" is a
conclusion drawn from an import and a call site. The report should carry the
call site, because that is what a reviewer can check. A capability list pasted
without addresses is the tool's opinion.

**Absence is weak.** A packed sample gives `capa` almost nothing, because there
is no code to read until it unpacks. A short list on a high-entropy binary means
"packed", not "harmless", and saying so is part of the answer.

Pair it with two other readings before you commit:

- **The import table** (`pe/structure`), which is capability by declaration
  rather than by code.
- **The strings** (`strings/obfuscated`), which say what the capability is
  pointed at: a domain, a path, a registry key, a mutex name.

A mutex name is worth calling out on its own. It is often unique to a family, it
is rarely obfuscated, and it is the cheapest way to tie two samples together.

Finally, the honest framing for the report: this is static analysis. It says
what the code is able to do and what it was built to do. It does not say what it
did on this machine — that comes from the host artefacts, and it is the Windows
or Linux pack's job.
