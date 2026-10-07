---
id: rules/authoring
title: Writing and validating a defensive YARA rule
when: You write a rule from a sample or test one against a corpus.
needs: []
tools: []
requires_host: [yara]
---

Use when you write a rule from a sample or test one. Not for publishing without authorisation.

- Decide what the rule claims: one specimen, a structural trait, a suspected family. Pick features the inspected evidence supports and combine them for that purpose. Mutexes, paths, user agents, resource data, certificate fields, Rich-header values and section layouts can be shared, absent or changed: none is stable or family-specific by itself. State which variants you tested; do not promise a rule survives rebuilds or repacking.
- Validate with `yara` against intended positives, held-out related samples where you have them, and representative benign software that shares the compiler, libraries, packer or document structure (system DLLs alone are too narrow). Record corpus provenance, exact hits, misses, scan failures and performance limits.
- Keep the rule with its rationale, sample references and authorship metadata. A rule built from sample A that matches sample B shows shared matching features, not family identity.
- Publish only with authorised disclosure. Keep credentials, private keys, victim-specific secrets and any hash of them out of rule strings, metadata and matched excerpts.

Shows: what a rule matched in a corpus. Does not show: that it survives change, or that two samples share an author. Record: rule hash, rationale, corpora, hits and misses.
