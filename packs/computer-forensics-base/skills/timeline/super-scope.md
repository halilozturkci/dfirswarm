---
id: timeline/super-scope
title: Parsers, zone and export for a Plaso timeline
when: Choosing parsers, a zone, or another export.
needs: []
tools: [timeline_super]
requires_host: [log2timeline, psort]
---

Use only if you run or re-export `timeline_super` (`timeline/super` says when). Not for reading its result (there).

**Name the parsers.** A default run over a large image takes hours and returns tens of millions of events, mostly file metadata. Read the installed Plaso's help and parser inventory (`log2timeline` and `psort` print them) before choosing a filter: names and presets vary by version, so take none from memory. Start with the parsers the question needs, document the gaps this leaves, and widen when another source family could change the answer. File metadata events are useful where their meaning bears on the question; the size of a volume alone does not predict how long a run takes.

**Give it the timezone** when the machine's is known (`timezone`), and say which you used: several formats store local time and Plaso needs the machine's zone to convert them. Derive it for each source (`timeline/clocks`), not from one host setting. Without it Plaso used its own default, which the tool does not read back; the storage file records it. State the zone of any filter and whether its bounds are inclusive.

**Then narrow before you read.** The storage file stays. To make another export without collecting the evidence again, call `timeline_super` with `mode: export`, the `.plaso` as `storage_file` and a `psort_filter`; calling it in the default mode again collects everything again. Filter syntax is the installed `psort`'s, for example `date > '2026-02-14 00:00:00' AND date < '2026-02-16 00:00:00'`: check it against that version's help (`psort` prints it).

**Record.** The parser list and why, the zone and where it came from, the filter text with its bounds, the program versions, the storage file's sha256, and the parsers that produced no event.

**Does not show.** That a parser you did not enable would have found nothing, or that a filter's window is the incident's.
