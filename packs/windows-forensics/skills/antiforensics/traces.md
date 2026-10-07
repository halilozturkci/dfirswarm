---
id: antiforensics/traces
title: Absence and inconsistency before intent
when: Artefacts are missing or inconsistent: separate deliberate action from ordinary causes.
needs: []
tools: [evtx_query, mft_records]
requires_host: []
---

Use when artefacts are missing or inconsistent and you must decide whether anything was removed or altered. Not for recovering the content (`filesystem/deleted`, `logs/recovery`).

A first pass that found nothing, or a record that looks wrong, is an observation to explain, not yet a finding of concealment. Most absences come from what was never recorded, was kept briefly, was removed by routine maintenance, was missed by the collection or was not read by the parser. Work the explanations in that order, and move to deliberate action only on evidence that separates it from them.

State the detection opportunity for each missing artefact:
- Was it meant to be recorded here (feature enabled, audit policy or channel configured, software installed)?
- How long is it kept (log size and rollover, a journal or cache that wraps)?
- Was it in the acquisition (the profile, volume, hive, channel and generation, with sidecars and logs)?
- Did the parser read it? `status`, `parse_errors`, `problems` and `structural_errors` (`evtx_query`, `mft_records`) make a partial or failed run a coverage condition, not a negative.
- Is there routine removal (cleanup tasks, storage management, product updates, backup or management software)?

Word a negative with the objects, acquisition, interval, tool, and the condition under which it would have recorded the event. Never write "cannot be recovered" from one failed route: list the routes tried.

Which leaf:
- Only if overwriting or wiping tools or repeated names appear: `antiforensics/wiping`.
- Only if a log is cleared or empty, or snapshots are missing: `antiforensics/log-clearing`.
- Only if timestamps disagree or a clock moved: `antiforensics/timestamps-clock`.
- Only if a security control changed or a virtual machine was deleted: `antiforensics/controls`.

A driver, service, Prefetch entry or file made by acquisition, mounting or collection is not subject activity: check names and times against the acquisition and collection records (`evidence/collections`) before attributing one.

"Cleared" needs the clearing record with its subject and a coverage gap consistent with it. "Timestomped" needs the disagreement, an independent source for the true time and the ordinary explanations excluded. "Deliberate" needs an identified account performing the action and no administrative explanation. Write each as observation, inference and conclusion, with the alternatives that remain.

Shows: that something is missing or inconsistent, and what the sources can and cannot rule out. Does not show: who, why, or even that anything was removed. Record: the detection opportunity for each artefact, parser status, routes tried, the alternatives still open.

Sensitive output: `evtx_query` and `mft_records` (with `with_resident`) can return command lines and file content; run them as jobs (`secret_output: true`).
