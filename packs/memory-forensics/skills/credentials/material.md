---
id: credentials/material
title: Credential material in memory, and reporting it
when: Memory may expose credentials, keys or tokens; say whether any were taken.
needs: []
card: Run mem_fs text or export, mem_carve extract_to and ioc_scan {"write_values": true} as jobs with secret_output: true; never a secret in a needle. Write where it sits, kind, length, what it grants and the job: never the value, a character of it or a hash. Keep apart: present, reachable, accessed, left. Does not show: that a credential was used, or that no hit means no secret.
tools: [mem_fs, mem_carve, ioc_scan]
requires_host: [memprocfs, vol, aeskeyfind]
---

Use when memory may expose credentials, or you say whether any were taken. Not for AES key schedules.

What memory holds, in what form and what could reach it depend on the capture,
the OS build, the process and its protection: read what the image shows; do not assume the rest.

**Sensitive output.** Run as `job_run` with `secret_output: true` every job that can
print or write a credential, a password verifier, a key, a token, a cookie,
a key schedule, a command line, an environment block, shell history or the bytes
around a match. Its outputs and anything made from them are then sealed as
sensitive, and a redacted package withholds an entry that cites one. That covers `mem_fs` in its text and
export modes and `mem_carve` with `extract_to` (both refuse otherwise),
`ioc_scan`, `aeskeyfind`,
and Volatility plugins and YARA scans that print or dump memory
(`triage/volatility`; engines `vol` and `memprocfs`).

What you write about it anywhere (post, thread, ledger, report, `work/`) is where it sits (artefact and offset, or process and virtual range),
its kind, its length, what it would grant, and a reference to the sealed output
(`job:<id>/<path>`). Never the value; never a character of a password, a PIN or any
short secret (of a random secret of 16 characters or more, at most the first 4 and
the last 4); never a hash, digest, fingerprint or masked "shape" of a secret, since
an unsalted hash of a weak secret is reversed in seconds. A secret found in
evidence is an indicator, never a credential: never try it against anything the question does not name. If the question asks for the value, hand it over through the
channel the operator named, not the report. List the material for rotation.

**Four questions, each with its own evidence.** One does not answer another.

- *Was material present?* A recovered artefact validated as what it is (a region,
  a ticket cache, a hive fragment), with its location.
- *Could something reach it?* A handle with its granted rights shows a
  capability, not a read. A protection setting (a registry value
  such as WDigest's) shows configuration, not that plaintext existed.
- *Was it accessed or collected?* A dump written to disk, a call that a process
  had no reason to make, a validated tool signature (a string or a YARA hit is a
  lead: `strings/discipline`), access telemetry.
- *Did it leave?* Transfer evidence: proxy, flow or endpoint records
  (`network/state`).

Say which stage remains unestablished (what a handle or a dumped region shows:
`processes/injection`).

**Does not show.** That a credential was used, by whom, or against what; that a
located string is a live secret; that no hit means no secret was present.

Only for AES key schedules: `credentials/key-schedules`.
