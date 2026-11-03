### Added: reverse-engineering `doc_structure` can give a second reading of an encryption variant it leaves unsupported

`doc_structure` records the encryption of a PDF and of an Office file as
structure and interprets only the variants it knows. With `second_reading: true`
a variant it leaves unsupported (a PDF encryption dictionary whose handler is
not Standard, or whose version or revision is outside the ones the Standard
handler defines; an Office encryption record whose scheme it does not read) is
also read by a program that does not share its parser: `qpdf --show-encryption`
for a PDF, `msoffcrypto-tool -t` for an Office file. The result is
`second_reading`, beside the first reading and never in place of it; where the
two differ, neither is taken as right. Nothing is started unless the call asks
and the first reading left such a variant (`applicable` is false otherwise).

No password or key is passed to either program and no stream is read. One thing
is not in this tool's hands: qpdf opens a file with the empty password on its
own, and the answer says whether that opened it as the user or the owner
(`opened_with`); the line in which qpdf prints a password it recovered is never
kept. The tool's claims that no key is tried now say whose: this reader's, not
qpdf's. The programs' output
is read line by line against fixed rules and only numbers and words of a fixed
set reach the answer (permission flags, the encryption methods, R and P, a fixed
word for the program's exception); a line printed twice makes the reading
`ambiguous` and the answer `partial`, a program that is missing is
`not_installed`, and one that outlives 20 seconds or prints more than 1 MiB is
ended with what it started. A stop signal now also ends the program of the
second reading before the tool answers.

The tests use stand-ins that print what qpdf 11.3.0 and msoffcrypto-tool 6.0.0
printed, and the real programs where they are installed (skipped, naming them,
elsewhere).
