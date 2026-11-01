---
id: scope/triage-tools-names
title: What the triage tools withhold from a path
when: You say what the survey and the scan withhold from a path, or quote a withheld count.
needs: []
tools: []
requires_host: []
---

Use only if you must say what the survey and the note scan withhold from a path, or quote a count of withheld paths. Not for the counts of candidates and notes (`scope/triage-tools`).

**Names.** Both tools withhold from every path each component that holds an
identifier-shaped token, and the survey a withheld note name's extension; the
order of rows and ids says nothing about a withheld name. Every other file's name
is printed, ids too: it is evidence. The shape is a deny-list: other shapes
print. Printed whole: 7 characters or fewer, 8 or 9 digits, up to 15 letters of
one case, 7 hex pairs, pairs joined by 2 characters, MAC and IPv6 addresses, other
groupings, CJK, emoji; a random 8-character token 3%, 12 characters 0.6%. Not
printed: hex, UUIDs, 12 digits, 8 or more hex pairs with one separator, 16 letters
of one case. About 6% of ordinary names are withheld: list the directory. A second
check replaces what slips through and marks the answer `partial`.

**Does not show.** A withheld name does not show that the name was an identifier; a printed name does not show that it holds none, and an identifier of another shape is printed.

Record: the count of withheld paths, and that the directory was listed for each name you needed.
Sensitive output: none here; the values behind a note are in the scan's sealed job file, never in a path.
