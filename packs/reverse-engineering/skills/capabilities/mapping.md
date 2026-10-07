---
id: capabilities/mapping
title: Static capabilities and the evidence behind them
when: You must assess what a sample could do without claiming it ran.
needs: [triage/quarantine]
tools: [pe_info]
requires_host: [capa, r2]
---

Use when you must say what a sample could do. Not for what it did, who wrote it or why: a rule match is a hypothesis about code.

1. capa matches rules against features it extracts from supported inputs. Which kinds of feature a rule used is in the rule and in the match explanation of the version you run: do not describe a match as code-only evidence. A match supports a capability hypothesis. ATT&CK labels organise it; they do not show the technique occurred.
2. Run `capa -j SAMPLE` and keep the whole result. Record the program version, backend, input format and architecture, the rule-set identity, any added rules and the warnings (`capa -h` lists the modes). Do not assume another installation carries the rules a given release does. Read what `pe_info` says it did not read (managed code, delay imports) first: an unsupported input is a result, not a clean file.
3. For each material match keep the rule namespace and the full feature explanation with its locations, then read the code (`r2`). A match may not reduce to one import or call site.
4. Few or no matches mean the chosen rules and analysis recovered little: unsupported runtime or architecture, incomplete analysis, library-heavy code, packing, obfuscation or limited coverage. Write "no matches under this tool, rule set and scope"; neither "harmless" nor "packed" follows.
5. Imports, strings and capa output can come from one feature or library: they are not independent evidence. A mutex name is a candidate indicator: establish how it is built and used, check for generic or shared values, and say how discriminating it is before clustering samples.
6. Say what the inspected code supports and what stays unresolved. To say what happened on a system, link the sample to execution, memory or network artefacts in the pack that holds them.

Shows: rule-supported capability hypotheses with feature locations. Does not show: execution, reachability, intent or purpose. Record: version, rule set, input mode, warnings, a reference to the complete output, the code you read.
