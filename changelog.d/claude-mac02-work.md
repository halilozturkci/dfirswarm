### Added: macos-forensics opens a login or System keychain with the password the case supplies

- New tool `keychain_open`, declared `secret_output: required`. It opens a keychain file (one that begins with
  `kych`) only when the case gives the password as a job input file, or the SystemKey file for `System.keychain`,
  and writes every item, metadata and value, to one 0600 file under the job's output. Its answer tells the outcomes
  apart (opened, partial, wrong secret, unsupported format, damaged, reader unavailable, clock, signal), counts
  records per class, decrypted and not, and gives the file's size and sha256; it prints no name, value or hash of
  one and no path it was given. The Local Items store (`keychain-2.db`) is answered `unsupported_format` with its
  reason. The password reaches the reader as a function argument, read from the file by the reader's own process:
  it is in no argument list, environment, stream or unsealed file. No password is guessed or cracked.
- The reader, chainbreaker, is pinned in `requires/host.json` at commit 2eb467d (the archive's sha256 recorded) in a
  virtual environment of its own with pycryptodome 3.23.0 in a hash lock (`requires/locks/chainbreaker.txt`). Its
  licence is GPL version 2; the entry says so, and says the older keychain file format is all it reads.
- New skill `security/keychains`: identify the System, login and Local Items stores from metadata, open a keychain
  only when the case supplies the secret, read the sealed file as the job's output, and keep values and their
  hashes out of the ledger. The router and the index list it; the README and `pack.json` no longer list Keychain as
  absent.
