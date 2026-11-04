---
id: logs/exported-evidence
title: What an exported log file is
when: A cloud log export is the evidence and you must describe the file before reading its records.
needs: []
tools: []
mentions: [check_inputs]
requires_host: []
---

Use when a supplied export is the evidence. Not for what its records mean (the provider's skill). Offline: never fetch an export.

**Keep apart:** byte integrity (a hash shows the file is as recorded), authenticity (the provider made it) and completeness (every event is in it). None implies another.

**Per file:** event, ingestion and export time; format and locale; archive members; page, query and limit; collector errors; exclusions; duplicates.

**Counts:** acquired, parsed, rejected, filtered, each with file and record. `check_inputs` compares files with a baseline; the recipe `cloud-export-inventory` counts an export set.

**Does not show:** that the provider logged an event, or that the export is whole.
