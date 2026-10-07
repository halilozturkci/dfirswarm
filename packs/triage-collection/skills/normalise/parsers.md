---
id: normalise/parsers
title: Handing delivered files to the platform parsers
when: A delivered file goes to a parser.
needs: []
tools: [collection_index]
requires_host: []
---

Use when you choose a parser for a delivered file. Not for deciding what the delivery can establish (`gaps/what-is-missing`).

1. Route each object to a parser that accepts the form it was delivered in. Raw copies of hives, event logs and databases can usually be read by the same content parsers as files taken out of an image. A command that needs an image, a volume, an inode or a stream-extraction source cannot be run on a copy that has none: say so instead of forcing it.
2. Before parsing check what travelled with the file: completeness, truncation, one acquisition moment, and the companions a consistent reading needs (a registry hive's transaction logs, a database's WAL or journal, an ESE database's recovery files). Preserve every supplied companion and cite it.
3. Replay or repair only on a derived copy. Keep the original and a record of the transformation (tool, version, options, input and output hashes), and cite the derived copy as one.
4. If the Windows pack is loaded, its `filesystem/ads` takes a stream out of an image by inode and does not tell you how a collector stored one. Check the run's tool inventory before naming a tool that belongs to another pack.
5. A successful parse shows the bytes parsed. It does not show that the acquisition was complete, or that the file is the one the question concerns.
6. Cite by delivered path and hash (`collection_index`), with the source path only as `normalise/layout` allows.

Shows: which parser fits a delivered form, and what must accompany it. Does not show: that a parse is complete, or that a companion that was not delivered would have changed the answer.
Record: parser and version, the object and its companions with hashes, any derived copy and how it was made, and what the parse did not cover.
Sensitive output: a hive, a database or a browser store can hold credentials; run the parser as a job with `secret_output: true`, cite locators, and never copy a hash of a secret.
