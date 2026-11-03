### Changed: the shared withholding block carries the credential rules, and the cloud tools use it

- The block that withholds identifier-shaped strings in the network, computer-forensics-base, encrypted-containers, memory-forensics,
  virtualization-backup-forensics, ransomware-response and reverse-engineering packs (50 tools, the reverse-engineering and
  computer-forensics-base tool-library twins included) now also withholds a credential by the name it is given under, in every
  name, path, URL and message it prints. Withheld now that was printed before: a value given to a password, secret, token or cookie
  name (`password=...`, `Pwd=...`, a `Cookie:` header), a Name/Value pair in text whose Name is a credential (a number, an array or a
  long Value as well, and the NewValue after an OldValue), a `-Password` style switch, the argument of `ConvertTo-SecureString`,
  `curl -u user:pass`, `mysql -uUSER -pSECRET`, a bcrypt hash and the known token families (Azure, Google, Stripe and others). Nothing
  that was withheld before is printed now: the new rules run after the old ones and leave their markers alone. Not withheld (known
  gaps): an array Value nested in another or over 4,096 characters, a crypt hash that is not bcrypt, and a secret with neither a
  credential name nor a token shape. A carrier may set `WITHHOLD_LIMIT` (default 65,536 characters) and `WITHHOLD_TICK` above the block.
- cloud-forensics: cloudtrail_parse, signin_analyse and ual_parse carry the shared block byte for byte and keep their 1 MiB gate.
  Every slot has one treatment: identifiers (event, request, correlation and object ids, access key ids, ARNs, account ids, hashes)
  are printed as they are; every other string, name, path, pointer, key and message goes through the credential rules; a named field
  goes through the name layer. Withheld now that was printed before: a numeric or array Value in a pair, the NewValue after an
  OldValue, a Value over 4,096 characters, `mysql -p`, `curl -u` and a bcrypt hash. The parser label of the three tools moves to 7.
  Reverse: a bare `token`, `signature` or `plaintext` assignment that is a placeholder (`redacted`, `true`, `null`) is still printed.
- Each tool of the 50 takes a new version, each of the eight packs a new patch version, and the packs are sealed.
