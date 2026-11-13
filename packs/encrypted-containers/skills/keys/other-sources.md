---
id: keys/other-sources
title: Password stores, memory, escrow and shell history
when: Key material may sit in a store, keychain, memory image, escrow record or shell history.
needs: []
card: Read a password store's rows without printing values: sqlite_query {"db_path": "<store>", "write_values": true, "table": "<table>"} in a job; the answer carries locators. A credential found is an indicator: never test it on a live service. Record "not decrypted", never "absent". Does not show: that it is reusable on the encrypted object.
tools: [sqlite_query]
requires_host: []
---

Use only if the key may sit in a password store, a memory image, an escrow record or shell history. Not for the order of search or the authority (`keys/where-they-hide`).

Browser password stores, password managers and keychains are protected by the
account's own material, and this pack provides no reader that decrypts them. When
the question asks for what a store holds, examine it with what the run has, within
the case's authority: say where it is, read its rows without printing the values
(`sqlite_query` in a job with `secret_output: true`: the base pack's
`data/sqlite-secrets`) and name what would open it. A Chromium `v10` or `v11` value
needs the profile key, which `Local State` holds wrapped by DPAPI; a Firefox login
needs `key4.db` and the primary password. Before attacking DPAPI, look where the
user keeps secrets (notes, documents, a manager's export, shell history): the key
or the answer is often written down. A negative from your own decryption code
counts only after that code reproduced a known answer; until then record "not
decrypted", never "absent". A credential found there is an indicator, not a
credential to try: never test it against a live service, and do not read its
presence as reuse on the encrypted object.

A memory image, page file or hibernation file may hold material for a volume that
was mounted at capture. Say when and how it was captured and what it covers: a
mounted volume at one time does not put a key in a later capture. If the
memory-forensics pack is loaded, its `acquire/images` skill covers capture;
otherwise state the limit.

Escrow (a directory service, a cloud identity, a fleet manager) is requested as a
scoped export through its authorised custodian. Match the device, volume and
protector identifiers the record gives against the volume's metadata; record the
retrieval time, the source and any rotation history. Do not use found credentials
to sign in to any of these.

Shell history and configuration may hold a password given on a command line.
Retention, shell settings, session length and redaction decide what survives, so
"no match" is a search result (which file, which period), not proof that none was
used.

**Does not show.** That a credential found in a store is reusable on the encrypted object; that a volume mounted at one time puts a key in a later capture; that "no match" in shell history means no password was used.

Record: for a store, where it is, what was read from it and with what, and what stayed undecrypted and why; for a capture, when and how it was taken and what it covers; for escrow, the custodian, the retrieval time, the source and any rotation history.
Sensitive output: a credential found in any of these is an indicator, never a credential to try; cite its locator, never its value (`keys/where-they-hide`).
