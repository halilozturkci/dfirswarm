### Added: reverse-engineering `authenticode_verify` verifies a PE file's Authenticode signatures with osslsigncode

`authenticode_verify` runs `osslsigncode verify` (OpenSSL; never cryptography of
its own) over a PE file with trust material from the call only: `trust_ca` (the
roots the signer's chain must reach), `tsa_ca` (the timestamp authority's roots)
and `crl` (a revocation list). The program is always given an explicit
`-CAfile` and `-TSA-CAfile`, so it never reads its default CA store, and the tool
makes no network request itself (whether osslsigncode follows a CRL distribution
point by itself was not measured). For each signature the answer says whether the file's digest
is the signed one, whether the signature verified against the supplied roots,
the signer's and the other certificates' names and validity times, the signing
time, a timestamp counter-signature and whether it verified, and the result of
the revocation check when a list was supplied. A part it was given no material
for is `not_checked`, never `verified`: with no `trust_ca` a signature is
`not_checked` (only the digest is compared), with no `tsa_ca` a timestamp is
reported and not verified, with no `crl` revocation is `not_checked`. A verified
signature says the program accepted it against that material, not that the file
is safe or who the publisher is.

The PE headers are read as structure: a certificate table that is cut, runs
past the end of the file, is misaligned, is not at the end, or holds an entry
shorter than its header is a problem and the verification is `failed`; an
unsigned PE is `unsigned`; a .NET strong-name signature is not Authenticode and
is said so. The program's output is read line by line and every line must match
a rule: a signature's description and URL attributes are free text that the
program prints raw, so a file can make it print a line that looks like its own;
those attributes are not read or printed, a line printed twice or out of place
makes the signature `not_checked` and the answer `partial`, and a path with a
line break is refused. The reading was checked against osslsigncode 2.5
(Debian 12's package) only; another release is `unsupported`, because a newer
release changes the layout and may consult the network. Names out of a
certificate pass the shared sanitiser and the backstop: they are withheld by
shape only, and in the test no canary of any shape the block names reached the
answer; a secret of another shape is printed. Serial numbers and digests are not
printed and the program's own output is kept nowhere. A program that outlives
`max_seconds` or prints more than 16 MiB is ended with what it started and the
answer is `partial`; a stop signal ends it and answers with one document.

The tests use stand-ins that print the real program's words for files signed
with throwaway certificates (a signed file, a changed file, an untrusted chain,
a revoked certificate, a timestamp, a nested signature, a file whose attribute
text imitates the program's lines, an unsigned file, a damaged table). Cases that
sign a PE with the real program, make a timestamp with a local authority and
change a byte after signing run where osslsigncode and openssl are installed and
are skipped, naming them, elsewhere.

### Changed: reverse-engineering `pe/signature-and-resources` names the verifier

The note says that `authenticode_verify` is the one tool of the pack that checks
a signature, and only against trust material the call supplies; what it was
given nothing for is recorded as "not verified".
