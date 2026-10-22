---
id: verify/raw-and-derived
title: Raw artefacts, companions and derived reports
when: A delivery mixes collected artefacts with parsed output.
needs: []
tools: [collection_path_map, collection_manifest_verify]
requires_host: []
---

Use when you must say whether a delivered file is collected bytes or something produced from them. Not for choosing a parser (`normalise/parsers`).

1. Sort every object you rely on as **collected** (bytes copied from the source), **parsed output** (a table or report a program made from collected bytes: KAPE module output, Zimmerman CSV or JSON, a platform export) or **replayed or repaired** (a copy with transaction logs applied). Their authority differs. `collection_path_map` gives a collected file's observed source path; an output with no observed source path is not shown to be a copy of anything.
2. For parsed output name the generating program and version, its parameters and maps, the input it read and when it finished. Check that the input is in the delivery: a report row does not show its source file was delivered, and a missing row is not a missing artefact on the source. Two parsers that disagree are two observations to reconcile against the raw bytes, not one answer.
3. For a collected file keep the companions a consistent reading needs: a hive's transaction logs, a database's journal or WAL, an event log's rotated siblings. A companion not delivered limits the reading; say that, and read the file as it is.
4. Replay or repair on a derived copy only, and cite it as one, with the tool, version, options and the hashes of input and output. The original stays as delivered.
5. A record that a file was copied (`collection_manifest_verify`: matched) shows agreement with the collector's record. It does not make a parsed report of that file correct.
6. When a platform pack is loaded, use its skills for the artefact itself; check the run's tool inventory before naming a tool that belongs to another pack.

Shows: which of the delivered objects are collected bytes and which are someone's reading of them. Does not show: that a parsed report is complete or right, or that a collected file is the one the question concerns.
Record: per object its class (collected, parsed output, replayed), the producing program and version or the observed source path, the companions delivered and missing, and any derived copy with its hashes.
Sensitive output: a hive, a database or a browser store can hold credentials; run parsers as jobs with `secret_output: true`, cite locators, and never copy the digest of a file that is itself a secret.
