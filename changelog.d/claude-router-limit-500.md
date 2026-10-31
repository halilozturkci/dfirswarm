### Changed: windows-forensics, linux-forensics, memory-forensics, macos-forensics

The router limit is 500 tokens for these four packs (it stays 400 for every
other pack), and they may pass 1,000 tokens of index: such a pack is shown by
its router line alone, as the harness already does past its 1,000-token pack
budget, which is unchanged. The base pack keeps its index within 1,000. The
limits are held in one file, `scripts/skill-budgets.json`, read by
`scripts/skill-budgets.py` (the seal and the lint) and by
`tests/pack-index-budgets.test.ts`. The four READMEs say "at most 500 tokens".
No skill or router changed.
