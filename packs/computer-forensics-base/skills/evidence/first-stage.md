---
id: evidence/first-stage
title: First-stage candidates
when: Which file started it on one machine.
card: first-stage-candidates (catalog_request target=<tree or member list> recipe=first-stage-candidates): ranks every macro-capable document of the WHOLE member list, wherever it lies, not only Documents, Desktop and Downloads; read coverage.json whole_list_read; the member list is catalog_search which=members. To answer "cannot be determined" to a "which file" question the whole member list must have been searched. A rank is a candidate with its signals named; a name found in a hive or log is a lead to the record, which regkv, evtx_query and prefetch_mam read.
needs: []
tools: [catalog_search]
requires_host: []
mentions: [regkv, evtx_query, prefetch_mam, doc_structure]
---

Use when the question is which file, document or attachment was the first stage on one machine. Not for what a macro does (the Windows pack's `doc_structure`, when loaded) or for persistence that followed.

    catalog_request target=<the profile tree, or the member list> recipe=first-stage-candidates

1. **Search the whole member list.** Take it from the catalogue (`catalog_search which=members`) or give the tree. A first stage is opened from where it landed: a temporary or attachment folder, an unpack folder, Music, Public. A search of Documents, Desktop and Downloads alone is not a search.
2. **The rule.** To answer "cannot be determined" to a "which file" question the whole member list must have been searched: `whole_list_read` in `coverage.json` says whether it was, and `limits_hit` what was left. A member list counts as whole only when its own `coverage.json` (beside the real file, which must be the generation's `members.tsv`) says `complete`: a list from a partial catalogue (a missing segment), another list, or one with no record gives `whole_list_read: false` (`list_coverage` says why).
3. **Read the ranking as leads.** `candidates.tsv` ranks macro-capable Office documents on named signals: the name, a VBA project inside (a tree only), the folder, a Recent shortcut of the same name, the name in the profile's `NTUSER.DAT` and in antivirus files (a tree only), the application's Prefetch file.
4. **Confirm with the records,** each on its own clock: Recent links and the Office MRU key (opened by this user, when), the antivirus detection event (what was detected, at which path), the application's Prefetch (it ran, and which files it loaded), the document's own structure. With the Windows pack: `regkv`, `evtx_query`, `prefetch_mam`. Two independent records that name the same file at fitting times make it the candidate to report; one signal does not.
5. **A member list has names only:** a macro in a file named `.docx`, the hive and the logs are not in its ranking. Extract the profile and run it on the tree.

**Record.** The target, `whole_list_read`, the candidate's path and signals, and each record that confirms it with its source and time.

**Shows.** Which documents could have carried a macro and what points at each. **Does not show.** That one was opened, that its macro ran, or who opened it; other first stages (a shortcut, a script, an installer, a disc image) are not ranked.
