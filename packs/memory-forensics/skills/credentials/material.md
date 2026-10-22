---
id: credentials/material
title: Credential material in memory, and reporting it
when: Memory may expose credentials, keys or tokens; say whether any were exposed or taken.
needs: []
tools: [mem_fs, mem_carve, ioc_scan]
requires_host: [memprocfs, vol, aeskeyfind]
---

Use when memory may expose credentials, or you say whether any were taken. Not for AES schedules.

Whether memory holds credential-related material, in what form, and whether
anything could reach it depends on the capture, the operating system and
build, the process and its protection settings. Read what the image shows; do not
assume the rest.

**Sensitive output.** Run as `job_run` with `secret_output: true` every job that can
print or write a credential, a password verifier, a private key, a token, a cookie,
a key schedule, a command line, an environment block, shell history or the bytes
around a match. Its outputs, its stdout and its stderr are then sealed whole as
sensitive, and so is anything made from them; an entry that cites one is recorded
sensitive and a redacted package withholds it. That covers `mem_fs` in its text and
export modes and `mem_carve` with `extract_to` (both refuse otherwise),
`ioc_scan` (its answer carries snippets of the bytes around a hit), `aeskeyfind`,
and the Volatility plugins and the YARA scans that print or dump memory
(`triage/volatility`; `vol` and `memprocfs` are the engines).

What you write about it anywhere (a post, a thread, the ledger, the report, a file
in `work/`) is where it sits (artefact and offset, or process and virtual range),
its kind, its length, what it would grant, and a reference to the sealed output
(`job:<id>/<path>`). Never the value; never a character of a password, a PIN or any
short secret (of a random secret of 16 characters or more, at most the first 4 and
the last 4); never a hash, digest, fingerprint or masked "shape" of a secret, since
an unsalted hash of a weak secret is reversed in seconds. A secret found in
evidence is an indicator, never a credential: do not try it against a service, a
host or an artefact the question does not name. Where the question asks for the
value itself, hand it over through the channel the operator named, not through the
report. Put the material on the list of what to rotate.

**Four questions, each with its own evidence.** Do not let one answer stand in for
another.

- *Was material present?* A recovered artefact validated as what it is (a region,
  a ticket cache, a hive fragment), with its location.
- *Could something reach it?* A process handle with the access rights it was
  granted shows a capability, not a read. A protection setting (a registry value
  such as WDigest's) shows configuration, not that plaintext existed.
- *Was it accessed or collected?* A dump written to disk, a call that a process
  had no reason to make, a validated tool signature (a string or a YARA hit is a
  lead; see `strings/discipline`), access telemetry.
- *Did it leave?* Transfer evidence: proxy, flow or endpoint records
  (`network/state`).

Say which stage remains unestablished. What a handle or a dumped region does and
does not show is in `processes/injection`.

Only for AES key schedules: `credentials/key-schedules`.

**Does not show.** That a credential was used, by whom, or against what; that a
located string is a live secret; that the absence of a hit means no secret was
present.
