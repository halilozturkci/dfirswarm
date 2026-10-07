---
id: credentials/material
title: Credential material in memory, and how to handle and report it
when: An examination may expose credentials, keys, tokens or cookies in memory, or you must say whether credentials were exposed or taken.
needs: []
tools: [mem_fs, ioc_scan]
requires_host: [memprocfs, vol, aeskeyfind]
---

Memory may hold credential-related material. Whether it does, in what form, and
whether anything could reach it depends on the capture, the operating system and
build, the process and its protection settings. Read what the image shows; do not
assume the rest.

**Sensitive output.** Run as `job_run` with `secret_output: true` every job that can
print or write a credential, a password verifier, a private key, a token, a cookie,
a key schedule, a command line, an environment block, shell history or the bytes
around a match. Its outputs, its stdout and its stderr are then sealed whole as
sensitive, and so is anything made from them; an entry that cites one is recorded
sensitive and a redacted package withholds it. That covers `mem_fs` in its text and
export modes (the answer is a locator; the content is files under `$OUT/mem_fs`),
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

**Key schedules.** `aeskeyfind` tests every position of an image against the
AES-128 and AES-256 expanded-key layout and tolerates a few decayed bits. Run it as
a `secret_output` job (`aeskeyfind -q -v IMAGE`; `-v` adds the offset in
hexadecimal, and its help names the rest). Its stdout carries the keys: take the
offsets and the count, not the keys; never put one on a command line or in a file
under `work/`. A hit shows that bytes laid out like a schedule are at that offset.
It does not show which application or artefact used it, that it is in use (a
library may keep a schedule it no longer needs), or that it opens anything.
Establish it only by opening something the evidence holds, with the authority the
case gives, through a reader that takes the key from a sealed file. A negative
covers the two standard layouts, the bytes read and the threshold used; it does
not say no key was in memory, and AES-192, other ciphers and other layouts are not
examined. The tool library (`--tools-from tool-library`) has two more layouts,
`aes_schedule_scan` (the bytes of each word reversed) and `aes_inverse_scan` (as a
decryption routine stores it). They write a key to a private file under their
`out_dir`, and their answer still carries a digest of it: run them as
`secret_output` jobs and copy neither the key nor that digest into a post, the
ledger or the report. `aeskeyfind` is in the memory and full images; a host run has
it only if the operator installed it, and without it this check was not run, and
the report says so.

**Does not show.** That a credential was used, by whom, or against what; that a
located string is a live secret; that the absence of a hit means no secret was
present.
