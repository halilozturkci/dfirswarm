### Fixed: one LF-only JSONL reader for every verifier

Node's `readline` also ends a line at U+2028 and U+2029 (on Node 24), and
`JSON.stringify` writes both raw, so a valid trace record that held one was read
as broken pieces: custody reported an intact trace "edited", the report's chain
check reported it broken, and `traceLineBytes` could not find the line (a false
tampering claim in the custody record). Custody, the report, the evidence store
(the trace readers and the member-list lookup, whose rows hold names from the
evidence), the hub, the access reader, the event log and the staged-path reader
now read through `extensions/jsonl-lines.ts`: it streams bytes, splits at 0x0A
only, keeps a CR that comes before the LF (a line edited to end in CRLF is now
seen), yields a last record that has no LF and says so, and gives each record's
byte offset and length. `traceLineBytes` returns the record's exact bytes. It
read a 1 GB trace in 1.5 s against `readline`'s 1.9 s. Three unused
`createInterface` imports were removed.
