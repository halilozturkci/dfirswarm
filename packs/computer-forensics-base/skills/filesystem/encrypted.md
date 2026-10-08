---
id: filesystem/encrypted
title: Distinguish encryption from other causes of unreadability
when: A supported reader cannot open a source, or validated metadata identifies encryption.
needs: [evidence/imaging]
tools: []
requires_host: [fsstat, fls, bdeinfo, dislocker, cryptsetup, luksdeinfo, fvdeinfo, fsapfsinfo]
mentions: [crypto_id]
---

An unreadable volume (`fsstat` refuses it, or the listing is one file you cannot
open) is an observation, not a diagnosis. Keep these apart and test them as
separate hypotheses, recording the exact failure of each: a wrong
offset or sector size, missing or truncated segments, a mapping layer (LVM,
RAID, Storage Spaces), a format or feature the installed reader does not
handle, damage or overwriting, and encryption. Rule the cheap ones out first
with `evidence/imaging`. Unreadability alone establishes none of them. A volume
`fls` lists is readable at the volume level; encryption of single files is below.

**Identify encryption from metadata, not from absence.** A signature is a lead
to the parser that reads that scheme's header:

    BitLocker   "-FVE-FS-" near the start of the volume (offset 3 on a volume encrypted in place); bdeinfo confirms it
    LUKS        "LUKS\xba\xbe" at offset 0 of the device or of a detached header file
    FileVault   a CoreStorage or APFS container with an encrypted volume (two different mechanisms, below)

A volume with no recognised header and random-looking content is an
unidentified high-entropy region. VeraCrypt or TrueCrypt is one explanation;
a wiped or compressed region, an overwritten header, a format no reader here
knows and a wrong offset are others. Report its offset, size and what was ruled
out, and name no product. If the encrypted-containers pack is loaded (check the
run's tool inventory), its `crypto_id` and `identify/headers` read headers
further.

**Metadata first, before any key is in play.** `bdeinfo` prints a BitLocker
volume's encryption method and the key protectors it finds: recovery password,
TPM, startup key, clear key. A clear-key protector keeps the protector's key
unprotected beside the metadata, so a reader that supports the volume's state
can open it without a secret from the case; check that the reader does, and
record any block that did not decrypt. A recovery-password protector names an
unlock mechanism, not where its value is kept. Sources that might hold one (a
printout, an exported key file, a file on another volume of the case, a
directory service) are searched only where the case authorises it and the
source is supplied; a source the evidence does not hold is an acquisition
request (`lead_close needs_operator` with `ask: acquisition`), not a finding.

LUKS: `cryptsetup luksDump` or `luksdeinfo` give the version, header source,
key slots and tokens; note whether the header is detached. A slot count does not
show how many passphrases exist, whose they are, or that nothing can open the
volume. FileVault: `fvdeinfo` reads the encryption metadata of the legacy
CoreStorage form (encryption method, key material references) and is not assumed
to read APFS. An APFS container is read with `fsapfsinfo`, whose declaration here
says snapshots, Fusion drives and T2-based encryption are not supported: a
failure on those is the reader's limit, not damage and not absence. APFS
structure is the macOS pack's `filesystem/apfs`, when it is loaded; the route
into an encrypted APFS volume is the encrypted-containers pack's.

**Unlocking is the encrypted-containers pack's method.** With a key the case
supplies, `dislocker` (BitLocker) and `cryptsetup` (LUKS) open a volume as a file
or a mapping; how, with which key source and under which job is that pack's
`volumes/bitlocker` and `volumes/luks-filevault`, when it is loaded (check the
run's tool inventory). What holds in every pack:

- The key is a secret. A key found in the evidence is used only where a question
  asks for the artefact to be opened, and offline.
- It never goes on a command line: argv is recorded in the trace, which travels
  with the package. Pass a file the case holds (a BitLocker `.BEK` key file, a
  LUKS `--key-file`), in a job run with `secret_output: true`. A program that
  takes a recovery password only as an argument value cannot
  be given a file: the traced command line then holds the key, so say so in the
  report, and the trace is redacted before it is shared.
- A mounted view is not a sealed output. Stream the decrypted volume, or the
  files you need, into `$OUT` before the job ends, and record the protector, the
  source and the transformation. The job's outputs are decrypted content, hence
  `secret_output: true`.
- Record where the key was found, its kind and its length, never its value or
  any hash or fragment of it.

**Encrypted at the file.** The volume reads and individual files do not: office
documents, archives, containers. That is an ordinary extract and a different
question. Identify the format and the kind of protection from its structure
before choosing a reader; where a key might be is a question for the case
sources the examination may search.

**Not encrypted, just unreadable.** A volume manager, a damaged partition table,
a sparse or truncated image, or an offset that is wrong: all more common than
encryption and cheaper to fix. See `evidence/imaging`.

**Does not show.** A BitLocker or LUKS header shows the format is present, not
that the data is intact, was in use, or is recoverable. A protector list shows
which mechanisms were enrolled when the metadata was last written, not who holds
them or that they still work.

**Sensitive output.** `bdeinfo`, `cryptsetup luksDump`, `luksdeinfo` and
`fvdeinfo` print header fields that include salts, digests and protector
identifiers. Run them as jobs, record protector kinds, counts, offsets and
lengths, and paste none of the digests, salts or key material into a post.

Write what you found as a bounded finding, not as an obstacle: "the second
volume's metadata identifies BitLocker with a recovery-password protector and no
clear key; no key material was supplied or found in the sources searched (named),
so its contents were not read with this reader". That is a limit of this
examination, not a statement that no route exists.
