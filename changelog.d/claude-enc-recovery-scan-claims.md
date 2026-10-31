### Fixed: encrypted-containers recovery_key_scan locates what its manifest says

The manifest listed PGP among the private-key header types the tool locates, but
the rule needed `PRIVATE KEY-----` right after the type, and an OpenPGP armored
private key (RFC 4880 section 6.2) begins `-----BEGIN PGP PRIVATE KEY BLOCK-----`:
it was never found, and the scan answered `complete` without it. The header is
now located as a private key with `key_type` `PGP PRIVATE KEY BLOCK`, its file and
offset, never its text (`PARSER` recovery_key_scan/4: a record newly kept). The
manifest and `skills/keys/recovery-key-scan.md` now list exactly what is located
(a type of up to two words, `other` for an unknown one, and RFC 4880's armor) and
say that a type of three or more words and a recovery password written with a
group missing (seven groups) are not located.
