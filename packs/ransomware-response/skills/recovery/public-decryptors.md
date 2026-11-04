---
id: recovery/public-decryptors
title: Public decryptors: catalogue lookup, test on copies
when: A family or variant may have a public decryptor to obtain and test.
needs: []
tools: [decryptor_catalog, recovery_validate]
requires_host: []
---

Use when a family or variant hypothesis may have a public decryptor. Not for the family (`identify/family`), the recovery position (`recovery/what-is-possible`) or partial damage (`recovery/routes-and-decryptors`).

**Look up.** `decryptor_catalog` reads an offline snapshot of five public decryptors, dated; it fetches, uploads and runs nothing and is not a current list. Give it family names or {family, variant} (the variant ids of the family match) and what you hold in `have` and `lack`. `no_entry_in_snapshot` is not "no decryptor exists". A snapshot or entry past `fresh_until` makes the answer `partial`.

**Read a row.** `variant_status` says whether the sources state the tool for that variant; a matching family name does not show compatibility. `prerequisites_status` (`all_met`, `not_met`, `unknown`) covers the key, file pair or machine it needs. With `limitations` and `acquisition` it is the publisher's account, not a test. The tool's terms are its publisher's: read them there.

**Obtain.** Reach catalogues through the case's authorised process. Use only a tool the operator supplied whose provenance was checked and whose documented support matches the variant. Ask for dated material from the original law-enforcement or vendor publisher and from public catalogues such as No More Ransom. Browsing a catalogue is not uploading a note or an encrypted sample to an identification service: do not upload evidence or victim identifiers without explicit case authority. Identification needs no payment and no contact with the adversary. `obtained_and_verified` is yours: the tool copies what you give it and never sets it true. Never run a decryptor that came from the evidence.

**Test on copies.** Test on disposable copies of representative files, large files and the relevant formats included, never over an original. Compare what comes back with trusted originals where they exist, and check structure and application behaviour: a success message is not enough. Run `recovery_validate` separately on the output (its verdicts are in `recovery/routes-and-decryptors`); its `provenance` is recorded as you give it, not verified. Keep the output of a failed run beside the others.

If current references cannot be reached, write "public decryptor availability not verified as of this date", not "no decryptor exists".

**Shows.** What the snapshot states of a tool, and what a test on copies returned.

**Does not show.** A matching family name does not show a decryptor's compatibility; a success message does not show that a decryptor restored the files; failing to reach current references does not show that no decryptor exists.

Record: for a candidate decryptor record the publisher, exact version, hash, where and when it was obtained, the integrity and authenticity checks, the instructions, the variants it supports, the key it needs and its known limits; the snapshot's date; which files were tested and what came back against trusted originals.
Sensitive output: upload nothing to a catalogue; a key stays in the sealed output.
