### Changed: the investigation library's goals no longer require a number of ledger events

Forty-five goal files under `library/` and the standard checks in `library/README.md` ended with a line that counted `event` entries in the ledger against a minimum. A run could satisfy the count and answer nothing, and a case with few dated events could be complete and still fail it. The line is gone from all 46 files, as it went from the pack goal templates. Completion is judged by the answer dispositions `scripts/check-answers.ts` reads, which every goal still runs over each of its questions, the summary and the narrative. No other check was loosened; the dated-rows check of the timeline stays.

`tests/library.test.ts` no longer requires a ledger floor, and now fails a library goal (or the README's standard checks) that counts `event` entries in the ledger against a number.
