
### Added: ransomware-response has a seventh tool, `ransomware_family_match`, with a dated reference snapshot (RAN-13)

It gives candidate families and variants for the extensions and ransom-note names an examination observed. The note names
and the note files come from the sealed values file of `ransom_note_scan` (read by reference, so the manifest declares secret
output `required`); the extensions and further note names are the caller's. Each candidate lists the reference features that
matched, their strength (strong for two or more publishers, moderate for one, weak for a shape or a generic name such as
`readme.txt`), the numbered sources, the `yara` rule id and version and the byte offsets of a text rule, and a support level
(`corroborated`, `single_feature`, `weak_lead`). The outcome is one word: `unidentified`, `candidate`, `leading_candidate` or
`ambiguous`; contradictions between features (an extension of one variant with a note of another, a note that embeds other
characters than the extension seen) and variants supported alike are listed. `observed_on` is compared with the dates of the
cited sources and says `before`, `within` or `after` them, as a note about the snapshot and not a contradiction. The reference
set (`reference/entries.json`, `reference/rules.yar`) is project-authored under AGPL-3.0-or-later and holds seven families
(Akira, LockBit, BlackCat, Black Basta, Rhysida, Phobos, Play), each entry with `reviewed_on`, `fresh_until`, an evidence
strength, `valid_for` and the public pages it summarises, with their dates and the date they were read. Its sha256 are checked
against `reference/reference-manifest.json` at every run and a mismatch, a missing file or an unlisted file is refused; an
entry past its freshness date is reported as stale and makes the answer partial. The set is a snapshot: no match does not mean
that an unknown family is absent, and the tool has no field for an affiliate or an actor and never names one. It prints no
observed extension, note name, path, indicator or note text; with `yara` absent it still matches extensions and names and says
the text rules did not run. The pack README no longer says that no reference data ships with it; `identify/samples-and-decryptors`
and `encryptor/samples-and-notes` name the tool and the snapshot. The shared process block is carried by a ransomware-response
tool for the first time, and the census, paging-rerun and carrier lists name the tool.
