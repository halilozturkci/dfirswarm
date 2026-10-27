# Agent instructions

This file is for every agent (and every person) working in this repository.
`CONTRIBUTING.md` holds the general rules of the house; this file holds the
rules an agent must not miss.

## Pack review and closing

This applies to every agent that reviews, fixes or verifies a pack. It exists so
that a pack's review ends: a pack is not made perfect, it is made safe to rely
on, and the remaining small findings are written down instead of being chased
round after round. This is the one full statement of the rule; other documents
point here.

1. **A pack is closed** when an independent verification of its current head
   finds no P1: every earlier P1 is closed and there is no new one. The P2 and
   P3 findings that remain are listed in the verification notes and in the pull
   request body. No new review round is opened for them.
2. **Three review rounds in a row that each find a P1 mean the cause is shared.**
   Stop reviewing the tools one by one. A defect that keeps coming back across
   tools sits in a block they carry in common (the process, stop, page,
   withholding and boundary blocks), so review those shared blocks across every
   tool that carries them, and fix each once.
3. **The severity bar stays the definition of P1, P2 and P3:**
   - Sensitive values are for agents to use; reads are recorded, not blocked
     (see `docs/packs.md`, "Secrets and sensitive output").
   - A size, time or order oracle is P3.
   - A value printed where the manifest says it is withheld is P2.
   - P1 is a hang or an overrun past the manifest's timeout, a wrong
     `complete`, an unsafe write, a widened kill set, a crash without JSON, or a
     false claim.
4. **Every verifier states its verdict as CLOSED or NOT CLOSED** by rule 1, so
   that the answer to "is this pack done?" is one word and its reason.

Pack authoring rules are in `docs/packs.md`, section 8.
