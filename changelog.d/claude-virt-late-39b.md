### Added: virtualization-backup-forensics: a guard on `_S_LINE`, and the free-text and false-positive rates of the one BOUNDARY text, measured

`_S_LINE` (`[ \t]*line[ \t]+[0-9]`, the second check's "line N" pattern) is still in the one BOUNDARY text, in all 16 carriers, and is quadratic under `.search` on a run of spaces or tabs (2.6 s at 32 KiB). Every carrier calls it with `.match` at one position, which is a linear step. `tests/pack-boundary-s-line.test.ts` pins that: it scans every `run.py` under `packs/` and `tool-library/` that defines the name, and fails on any use that is not `.match(` or `.fullmatch(` (a `.search`, a `.sub`, a bare use); it proves itself on a planted source. The tools' manifests (versions 6, 8 and 6) and the pack (1.2.1) are resealed; no tool code changed.

The rates below were measured on the text as it is now, with a script kept outside the repository: the tool loaded as a module, each string judged by `seal_text` as the field kind says, random plants from a fixed seed, 95% Wilson bounds. The three tools give the same figures for free text and for the corpus (they carry one text).

Free-text carry-over (a plant in an annotation, a description or a message, in three templates; 1,000 plants per shape; "shown whole" is the whole value present in the answer):

- `password-srv01-` and 8 characters: 1,000 of 1,000 in each of seven alphabets (base62, lower case, upper case, digits, lower case and digits, upper case and digits, hexadecimal): 100%, Wilson 99.6 to 100%. With 14 base62 characters 634 of 1,000, 63.4% (60.4 to 66.3%). With 24 base62 characters 1 of 1,000, 0.1% (0.0 to 0.6%). (The work list had 91.8%, 82 to 100%, 47 to 51% and 1%.)
- `password-` and two groups of 4 (base62, lower case and digits, hexadecimal, digits): 1,000 of 1,000 each, 100% (99.6 to 100%).
- a glued `--master-key` and 8 lower-case letters 87 of 1,000, 8.7% (7.1 to 10.6%); 8 hexadecimal digits 7 of 1,000, 0.7% (0.3 to 1.4%); 8 base62 characters 3 of 1,000, 0.3% (0.1 to 0.9%); 14 and 24 base62 characters 0 of 1,000 each (0.0 to 0.4%). (The work list had 100%, 63% and 3 to 54%.)
- In no plant was only a head of the value (its first 12 characters) shown while the rest was withheld.

These stay a listed residual: the manifests claim glued key flags for names, and a name that holds a secret's name and a value, not for free text. The three manifests now say the rates in their sentence "(2) Every other text ...".

False positives (strings that are not secrets, withheld; the corpus is made here, the figures are for it and not for a population):

- a secret word (`password`, `passwd`, `secret`, `token`, `apikey`, `pwd`, `passphrase`, `credential`, three of them also capitalised) joined by `-`, `_`, `.` or a space to `srv01`, `db02`, `web03`, `01`, a date (`20241031`, `2024-10-31`, `2024_10_31`) or a compact date and time (`20241031T0102`), with no tail, `-prod` or `_old`, 1,056 names: 176 withheld, 16.7% (14.5 to 19.0%). The cells: `20241031T0102` in all 132 (100%), `db02` followed by `-prod` in all 44 (100%), every other cell 0 of 880 (with no tail word, 44 of 352, 12.5%, are all `20241031T0102`). Before V11 and V12 the work list had 0.3 to 4.3% of its matrix cells.
- a VM or disk name made of a secret word, an optional suffix from the same list and `.vmdk`, `.vhdx` or `.qcow2`, as a name, a file name or a path: 110 of 594 withheld, 18.5% (15.6 to 21.8%): `20241031T0102` in all 66, `db02` in 44 of 66 (67%), the rest 0 of 462. (82.8% before V11 and V12.)
- Veeam-style job names (`Backup Job 1`, `Backup Copy Job 3`, `Replication Job 12` and the like, 21 plain and 672 with a secret word before, after or glued with `srv01`): 0 of 693 withheld (0.0 to 0.6% with a secret word, 0.0 to 15.5% for the 21 plain ones). Veeam-style backup file names (`<job>D2024-03-01T010000_AB12.vbk`, `.vib`, `.vrb`, `.vbm`, jobs with and without a secret word): 0 of 216 (0.0 to 2.0% with a secret word, 0.0 to 10.7% for the 32 plain ones). (48% before V11 and V12.)
- this repository's tracked paths at the base of this change, judged as paths: 104 of 4,285 withheld, 2.4% (2.0 to 2.9%), all 104 with a component of 64 hexadecimal digits (a content hash). The distinct file paths of the installed packages of a WSL Ubuntu 24.04 (the `.list` files of the package database, 55,833 paths): 115 withheld, 0.21% (0.17 to 0.25%); their 55,833 file names alone as names, 104 (0.2%).

`skills/evidence/boundaries.md` is at 794.8 of 800 tokens, so it does not take the clause on these rates; they are in this fragment and the manifests carry the free-text ones.
