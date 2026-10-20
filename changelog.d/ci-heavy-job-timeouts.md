### Changed: the heavy CI jobs have room for the suites they run

The Linux job (typecheck, node tests, shell suites, UI build) took up to 34 min 54 s of its 35-minute limit and 14 runs were cut off at the limit; the Node 22.19 and Node 24 jobs took up to 20 min 0 s and 19 min 12 s of 20. The pack tests (windows, reverse engineering, virtualization) made `npm test` 17 to 19 minutes and the shell suites 15 to 22. The limits are now 60 minutes for the Linux job and 35 for the two Node jobs; a hang is still stopped. No test is changed or skipped by this.

### Fixed: a capa-floss test no longer fails once in a thousand runs on Linux

The test of every withheld shape gave its capa stand-in a 4.3 KB here-document. dash, the CI runners' `/bin/sh`, forks a process to feed a here-document over 4096 bytes to its reader, and that process can outlive the stand-in by a moment; the recipe, which ends what an engine leaves behind, then counted it as an orphan, marked capa partial and wrote no `matches.tsv`. The stand-in now prints its output from a file, the test asserts capa is complete first, and the test harness refuses a stand-in with a here-document over 4096 bytes. The recipe itself is unchanged: ending an engine's orphans is its contract.
