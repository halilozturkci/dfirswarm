---
id: evidence/coverage
title: What a search did and did not cover
when: Before writing "not found", "none", or a count of "all"; when a search returned nothing.
core: 3
needs: []
tools: [catalog_search]
requires_host: []
---

Use when an answer rests on something not being found, or claims a complete set. Not for how a catalogue was built (`evidence/catalog`) or what the case allows (`evidence/scope`).

An empty result has five readings. Name which one you have:
- **no hit**: the search ran over this object, with this query, and matched nothing;
- **not searched**: the object was not reached (a budget, a page, an exclusion);
- **unsupported**: the format, version or encoding is one the reader does not handle;
- **failed**: an error, a timeout or a partial job; a result from one qualifies, and cannot show absence;
- **no trace expected**: the source never recorded this kind of event (not logged, rotated away, not collected).

**Define the search before you run it:** the objects and areas (live files, deleted entries, unallocated space, slack, secondary copies such as snapshots, backups and a second log of the same thing), the time range, the literal forms a hit would take (name, id, address) in each encoding the source uses (UTF-8, UTF-16LE), the case and separator rules, and whether the artefact stores the name at all or only an id or hash.

**Read the whole result.** A page is not the result: when `catalog_search` returns `all_matches`, read that file or page with `offset`. `matched` is a lower bound when the answer says the search was interrupted by its time budget. Keep the query, exclusions, catalogue `revision` and generation with the finding (a partial one describes the preparation, not the exhibit).

**Check what the parser did** (`evidence/tool-validation`). Exit 0 and `complete` mean the engine finished, not that every parser read every source. Read its counts (parsed, empty, unsupported, failed, not attempted) and first failures; run the search over a source known to hold the answer.

**Detection opportunity.** Ask whether the event would have left a trace in these sources, given what they keep and how long (retention, rotation, logging level, collector scope). If not, the negative is about the source, not the event.

**Wording.** "No evidence of X was found in A and B, between T1 and T2, by query Q" is a bounded negative. "X did not happen" is never written, even after a search the harness found complete over sources that would have kept a trace: it answers whether X is in those sources, not whether the event occurred. When a source the evidence does not hold would settle the question, say so and ask for it (`evidence/scope`).

**Record.** A `kind=coverage` entry before the answer that rests on it: `value` (the proposition searched), `refs` (objects searched), `time_range`, `search_method`, `settings`, `coverage_actual`, `skipped`, `failures` ("none", and how you know), `result_refs`, `alternatives`, `detection_opportunity {trace_expected, why}`, `areas {allocated, deleted, unallocated, slack, secondary}` and `looked_for` (the literal strings; the hub sweeps every output the run holds for them).

**Does not show.** A search shows that these bytes, this query and these encodings produced nothing. It does not show that the exhibit holds nothing else, that the event did not occur, or that a partial source was whole.
