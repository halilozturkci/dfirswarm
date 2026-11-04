### Added: ransomware-response has a leaf for public decryptors, `recovery/public-decryptors`

The pack's skills now include one leaf that covers a public decryptor from the lookup to the test on copies: the dated, offline
snapshot of `decryptor_catalog` (never a current list, and `no_entry_in_snapshot` is not "no decryptor exists"), how to read a
row (`variant_status`, `prerequisites_status`, `limitations`, `acquisition`), reaching catalogues through the case's authorised
process, the rule that browsing a catalogue is not uploading evidence, the record to keep for a candidate (publisher, version,
hash, source, checks, variants, key needed, limits), tests on disposable copies against trusted originals with `recovery_validate`,
and keeping the output of a failed run. The paragraphs about decryptors in `recovery/routes-and-decryptors` and
`identify/samples-and-decryptors` moved into it, sentence for sentence, and both now point to it; `recovery/routes-and-decryptors`
keeps the checks of an output by `recovery_validate`. The router names the leaf once and its glosses are shorter so that it stays
within its budget; the index and the README count 25 skills. The skill tests check each field the leaf names against the two tools
and hold the moved sentences. No tool changed.
