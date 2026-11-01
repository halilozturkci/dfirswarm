### Added: repo-wide tests that hold every bundled tool to the tool contract

`tests/tool-contract-static.test.ts` and `tests/tool-contract-run.test.ts` read or run all 87 tools under `packs/*/tools/` and check four things:

- a manifest with a `write_*`, `with_resident` or `extract_to` parameter declares `secret_output`;
- the version a tool states of itself (`TOOL = {"name": ..., "version": N}`, `VERSION = N`, and `PARSER = "<tool>/N"` in the linux-forensics and mobile-forensics packs, where that label is the tool's own version) equals its manifest's `version`; a `PARSER` label in any other pack is the version of a parser inside the tool and is not compared;
- given `{}`, and given a path that is not there, the tool answers JSON whose `status` is `complete`, `partial` or `failed` and whose `status_basis` is not empty;
- on Linux, given a file and given a directory named with the byte `0xff`, the tool answers one JSON document that is strict UTF-8 and leaves no JSON Lines file with a row that does not parse.

`tests/tool-contract-allowed.json` names every failure of the head with the item or package that removes it (6 declarations, 24 status pairs, 1 non-UTF-8 name, no version label), and may only shrink: a failure with no entry fails the test, and so does an entry that no longer fails. The run tests take about 5 seconds for the 87 tools; the recipes are not run (they need the programs they drive). Nothing under `packs/` or `tool-library/` changes.
