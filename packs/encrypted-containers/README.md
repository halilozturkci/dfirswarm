# Encrypted Containers Pack

Working out what protects a piece of evidence, what its metadata shows without a
key, and where key material the case supplies may already be, before anybody
spends an hour on a way in.

Depends on the Computer Forensics Base Pack, whose `filesystem/encrypted` skill
covers the three reasons a volume will not open. This pack is what to do once you
know it is the encrypted one.

## What it carries

**Eighteen skills**: ten decision leaves and seven second-level leaves they point to
("only if X"); every leaf is at most 800 tokens. `identify/headers`
(`identify/by-format`), `volumes/bitlocker` (`volumes/bitlocker-opening`),
`volumes/luks-filevault` (`volumes/luks`, `volumes/filevault-apfs`), `archives/protected`
(`archives/formats`), `keys/where-they-hide` (`keys/recovery-key-scan`,
`keys/other-sources`), `recovery/authorised`, and four that stand alone: `volumes/layered-reading`,
`volumes/veracrypt-truecrypt`, `messages/openpgp` and `files/aescrypt`. The eighteenth is the pack's router, `encrypted/router` (at
most 400 tokens): it names the other seventeen by the question each answers, holds no
rule, and is the one line a run shows for the pack when its skills index is over budget.

**Nine tools.**
`materialise_decrypted` is the one tool that writes decrypted evidence: inside a `secret_output` job, from a
key in a sealed 0600 file (never an argument), through pybde, pyluksde or pyAesCrypt, to a raw image or file under
`$OUT` with a provenance file; a key that does not work leaves nothing, and what is not whole stays an unverified `.partial`.
`archive_metadata` says what protects a 7-Zip or RAR archive, from the start header or the block
headers and then through 7z: whether the headers (the names) and the members are encrypted,
whether the set of volumes is whole; it lists a ZIP through 7z, and never extracts.
`crypto_selftest` builds tiny synthetic LUKS, BitLocker, Core Storage, APFS, ZIP-AES
and VHD samples, runs the installed readers and modules on them and says which pairs
parsed, which did not and which are unavailable, with exact versions and john's helper
inventory: the receipt an image's acceptance step reads.
`crypto_metadata` takes a volume image and a byte offset and runs the reader for the
scheme the signature shows (`cryptsetup luksDump`, `bdeinfo`, `fvdeinfo`,
`fsapfsinfo`): the key slots, segments, digests and tokens of LUKS, the key
protectors of BitLocker, the counts the Core Storage and APFS readers print. It
prints no key, salt, digest, UUID, label or identifier, only whether each is
present, and a reader that is not installed is `unavailable`, never an empty list.
`crypto_id` names the scheme from the first bytes of a volume or file and reads
what a header holds without a key: the LUKS1 key-slot fields, the LUKS2 binary
header (version, label, UUID). It prints no raw bytes of the file, and header text
only when it is what the format says (the header's numbers and the sample's entropy are printed). It does not read LUKS2 keyslots, BitLocker
protectors or the encryption state of an APFS volume, and it names the reader
that does. `archive_probe` lists a ZIP's members with per-member encryption, and
says what it can and cannot establish about 7-Zip, RAR, PDF and OLE documents; a
result from a byte search is marked a heuristic, never "not encrypted".
`recovery_key_scan` sweeps a tree for text in the BitLocker 48-digit format,
private-key headers and the file names key files are saved under. It returns
where each is (file, offset, length, a structure check), never the value, a
fragment of it or a hash of it, and lists every file it could not read in full or
did not reach before its own time limit. `tcrypt_header` reads a VeraCrypt or
TrueCrypt header with cryptsetup's tcrypt mode, for a password (and, optionally,
keyfiles) the case supplies on a sealed file; it reports whether a header
decrypted and, if so, its non-secret fields (cipher chain and mode, PBKDF, key
size, sizes and offsets), never the volume key or a salt. `password_recover` is
this pack's one password-recovery route: inside a `secret_output` job, it
extracts a hash with the matching `*2john` helper (or takes one from another
sealed job) and runs john against a case-supplied candidate list; the hash,
john's pot, session and log sit only under `$OUT`, and the answer carries
counts and versions, never a value. Names, paths and header strings the tools
print have parts shaped like identifiers or secrets withheld, by shape.

**One goal template**: `what-is-locked.md`.

## Secrets

A tool that can reach secret material answers with presence, kind, location,
length and offsets, never the value itself; `password_recover` and
`tcrypt_header`, whose job is a password attempt rather than a locator, answer
with counts, versions and whether a header decrypted, and the same rule: never
a value, a hash, a salt or a length of either. A value is written only when
the caller asks for it, only in a job run with `secret_output: true`, and only
to a file under `$OUT`. `recovery_key_scan` is the reference implementation of
the locator pattern; `docs/packs.md` ("Secrets and sensitive output") has it in
full. No skill or report writes a password, a PIN, a recovery value, a
fragment of one, or a hash of one.

**A program that leaves a process behind.** The tools that run a program share one process block, and its `settle()` ends, before anything is read or counted,
every process a program left running after it ended (in the tool's group, in a session of its own, or holding no descriptor at all); the answer carries `program_group`
(`subreaper`, `left_behind`, `unproven`, `notes`; a refusal or an error carries none). `password_recover`, `crypto_metadata`, `crypto_selftest` and `materialise_decrypted`
report a file a program wrote (the hash and pot files, the reader's output, the decrypted image), so they answer `partial` when `settle()` ended a leftover and, on a host that
is not Linux or where the kernel refuses `PR_SET_CHILD_SUBREAPER`, when the absence of one cannot be ruled out (`materialise_decrypted` then keeps the image as an unverified
`.partial` file, and claims no digest of it after a process was ended). `tcrypt_header`, `archive_metadata` and `archive_probe` report what a program printed on a pipe: they are
not held to the second rule, but a process `settle()` ended makes them `partial`. A process that holds the pipe after the program ended is let go after at most one second
(`tcrypt_header` and the version probes: or 1 MiB of further output, whichever comes first, and the cut makes the answer `partial`; the 7z tools: one second, and the listing is then
`listed_with_warnings`). A flood that starts while the program is still running is not capped by this. A writer that is no descendant of the program (started through a service manager) is not found. `crypto_id` and `recovery_key_scan`
start no program.

## Three things the skills insist on

**Read the metadata first.** A BitLocker volume's protector list, a LUKS header,
an archive's member table: what each shows is readable with no secret, and each
skill says what it does not show.

**Look in the evidence the case supplies.** Key material is sometimes already in
the case: a saved file, a backup, an escrow export, a memory capture. Locating it
is a bounded search with its coverage stated, and a hit is a lead until it opens
the object.

**Do not start a recovery you have not been asked for.** It may be outside the
authority the engagement gives you, and where the material is a third party's it
may be unlawful. Establish what the container is, report it, and ask.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/encrypted-containers
    scripts/swarm.sh start --pack computer-forensics-base,encrypted-containers ...
