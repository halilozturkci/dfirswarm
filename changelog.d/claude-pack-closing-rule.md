### Changed: the rule that closes a pack's review is written down

A new `AGENTS.md` states the rule once, in "Pack review and closing", and `CONTRIBUTING.md` and `docs/packs.md` point to it. A pack is closed when an independent verification of its head finds no P1; the remaining P2 and P3 findings are listed, not re-reviewed. Three review rounds in a row with a P1 send the review to the shared blocks instead of the tools one by one. The severity bar stays as decided, and every verifier states CLOSED or NOT CLOSED. No code or pack changes.
