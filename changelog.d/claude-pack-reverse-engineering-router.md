### Added: reverse-engineering has a router, so a run that carries it stays inside the skills index budget

The pack names one router, `reverse-engineering/router`, at most 400 tokens (about 350), opening with "Use when ... Not for ...". When a run's index is over its 2,500-token budget the prompt shows the pack by its router's one line, and the router names every other skill of the pack (all twenty) exactly once, grouped by topic (start, executables, code and packing, text and capabilities, documents and scripts, rules), with a few words on when to read it. The router holds no rule and names no tool or program; it is read alone. Every existing skill id is unchanged, so what other packs need or mention still resolves, and no leaf changed. The pack index grows by one entry (663 to 697 tokens of entries as the harness counts them; the limit is 1,000). `tests/pack-re-skills.test.ts` holds the router's checks through `tests/pack-router-checks.ts`. Pack `reverse-engineering`.

### Fixed: a timestamp request whose nonce began with a zero byte was refused by the authority

The nonce of the RFC 3161 request was written as a DER integer with its leading zero bytes kept, which is not minimal, and a strict authority (openssl's among them) answered with status 2 in about one request in 500. The nonce is now written minimally, so the release's timestamp no longer fails at random.
