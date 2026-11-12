### Fixed: what the test suites found on a Mac with the packs' real programs and libraries installed

The suites ran on the owner's Mac (macOS, arm64) with the programs and Python libraries the packs declare installed beside them (Homebrew's qpdf,
nfdump, osslsigncode, upx, binutils, e2fsprogs, the Sleuth Kit, ewf-tools; dotnet's ilspycmd; a venv of the pinned pyAesCrypt, regipy,
python-evtx, Pillow and pytsk3), so the cases gated on them ran there for the first time. Thirteen node cases and one pack case failed.

- **materialise_decrypted answered nothing for an AES Crypt container (encrypted-containers).** pyAesCrypt 6.1.1, the release the pack pins,
  names no version (no `get_version`, no `__version__`). The probe of the reader returned the version, or `None` once it had answered
  `unavailable`, and a module with no version was taken for the second: the tool ended with exit 0 and an empty standard output, nothing
  decrypted. The probe now says whether the module is available apart from its version; the version is null when the module names none. The
  stand-in pyAesCrypt of the tests had a `get_version` the real one does not have, which hid it; the stand-ins no longer have one, and the
  case of a missing module puts a module that raises `ImportError` first on `PYTHONPATH`, so a host with the real one installed runs it too.
- **A key or value name regipy cannot decode whole is said, not shown as the hive's (windows-forensics: regkv, shellbags, amcache_apps,
  userassist_bam_shimcache, persistence_normalise, registry_recover; the shared HIVE BOUNDS block, and the tool-library twins).** Windows
  stores a name one byte a character when every character of it is below U+0100 (`Müller`, `Café`), and regipy 6.3 decodes such a name as
  ASCII with errors replaced: each letter above 0x7F became U+FFFD, and the answer was `complete`. Every list of subkeys and values the tools
  read passes through the HIVE BOUNDS block, which now counts the names that hold U+FFFD and names them as a problem, so the answer is
  `partial` and says why. The test hive writer stores a name as Windows does (one byte a character, else UTF-16LE) and writes a key of more
  than 65,535 children as `li` leaves under an `ri` index (the 100,000-task TaskCache case could not be written at all); the stand-in regipy
  decodes a name as regipy 6.3 does. With the real regipy that case takes 119 to 136 s on an M3 Max and took 253 s on a loaded host, where
  the tool rightly answered `partial` for a list too long to put in print order in the time left: the case takes that partial too, and its
  file is one of the deep suites (it was cut off at 300 s).
- **nested_vdi gave FAT times shifted by the host's time zone (tool library).** The Sleuth Kit turns a FAT time, a wall-clock time with no
  zone, into seconds with `mktime` in the process's zone, and the tool writes those seconds as UTC: on a host in UTC+3 every FAT time was three
  hours early. The tool sets its zone to UTC before pytsk3 is loaded (its manifest is rehashed, version 2).
- **Cases that held a host's program to the image's release or to Linux.** The image carries Debian 12's qpdf 11.3.0, nfdump 1.7.1 and
  osslsigncode 2.5. The qpdf case now takes any release's version line (Homebrew's 12.4.2 gives the same answer); the nfdump case runs only
  with 1.7.1, whose words the parser was written from (1.7.10 prints `-o json` over many lines), and says so when it skips; the osslsigncode
  cases run with 2.5, and a new case holds that another release is `unsupported` with nothing verified. The readelf agreement cases read only
  ELF files and need a gcc that makes them (a Mac's is clang and makes Mach-O), and the real upx case needs `cc` to make an ELF. The clr_inspect
  case of a program found only through a relative PATH entry leaves out a PATH directory that holds a real `ilspycmd`. The real-pyAesCrypt
  round trip and layer_describe's real E01 case expect `CLEAN` (partial off Linux, where the orphans of a program cannot be adopted).
- **The million-line `pbs_task_log` case takes the partial a fast host gives (virtualization-backup-forensics tests).** An idle Mac reads all
  1,000,001 lines in about 29 s, before max_seconds; the run then reaches its cap of characters judged after about 604,000 rows of the paging
  file and withholds the 396,236 strings after it by their size. The answer is rightly partial and says so in `status_basis` and
  `boundary.stopped_by`, with no entry in `partial_reasons`, which the case required. It now takes either.
