---
id: filesystem/encrypted-metadata
title: Encryption metadata, protectors and keys
when: A header identifies BitLocker, LUKS or FileVault: protectors, or a key you are given.
needs: []
tools: []
requires_host: [bdeinfo, dislocker, cryptsetup, luksdeinfo, fvdeinfo, fsapfsinfo]
---

Use only if `filesystem/encrypted` found a header for a known scheme. Not for deciding whether a volume is encrypted (there).

**Metadata first, before any key is in play.** `bdeinfo` prints a BitLocker volume's encryption method and its key protectors: recovery password, TPM, startup key, clear key. A clear-key protector keeps its key unprotected beside the metadata, so a reader that supports the volume's state can open it without a secret from the case; check that it does and record any block that did not decrypt. A recovery-password protector names a mechanism, not where its value is kept. Sources that might hold one (a printout, an exported key file, another volume, a directory service) are searched only where the case authorises and supplies them; a source the evidence does not hold is an acquisition request (`evidence/scope`), not a finding.

LUKS: `cryptsetup luksDump` or `luksdeinfo` give the version, header source, key slots and tokens; note whether the header is detached. A slot count does not show how many passphrases exist, whose they are, or that none opens the volume. FileVault: `fvdeinfo` reads the encryption metadata of the legacy CoreStorage form (method, key material references) and is not assumed to read APFS. An APFS container is read with `fsapfsinfo`, whose declaration here says snapshots, Fusion drives and T2-based encryption are not supported: a failure there is the reader's limit, not damage or absence. APFS structure is the macOS pack's `filesystem/apfs`, and the route into an encrypted APFS volume the encrypted-containers pack's, when loaded.

**Unlocking is the encrypted-containers pack's method.** With a key the case supplies, `dislocker` (BitLocker) and `cryptsetup` (LUKS) open a volume as a file or a mapping; how is that pack's `volumes/bitlocker` and `volumes/luks-filevault`, when loaded. In every pack:

- A key found in the evidence is a secret, used only where a question asks for the artefact to be opened, and offline.
- It never goes on a command line: argv is recorded in the trace, which travels with the package. Pass a file the case holds (a BitLocker `.BEK`, a LUKS `--key-file`) in a job run with `secret_output: true`. A program that takes a recovery password only as an argument cannot be given a file: the traced command line then holds the key, so say so in the report and the trace is redacted before it is shared.
- A mounted view is not a sealed output. Stream the decrypted volume, or the files you need, into `$OUT` before the job ends (its outputs are decrypted content, hence `secret_output: true`) and record the protector, the source and the transformation.
- Record where the key was found, its kind and length, never its value, a hash or a fragment.

**Does not show.** A protector list is the state when the metadata was last written, not who holds a protector or that it works.

**Sensitive output.** `bdeinfo`, `cryptsetup luksDump`, `luksdeinfo` and `fvdeinfo` print salts, digests and protector identifiers. Run them as jobs, record protector kinds, counts, offsets and lengths, and paste none into a post.
