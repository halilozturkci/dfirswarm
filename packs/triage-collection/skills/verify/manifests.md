---
id: verify/manifests
title: Baseline, manifest and provenance of a delivery
when: You take custody of a collection or rely on its manifest.
needs: [identify/collector]
card: collection_manifest_verify {"root": "<collection dir>"}: path, size and digest per claim, each matched, mismatch, missing (complete census only), unverifiable, ambiguous or read_failed; digests only in the collector's algorithm. A match is agreement with that manifest; a mismatch is unresolved. Does not show: that a claim is true or the collection complete.
tools: [check_inputs, collection_manifest_parse, collection_manifest_verify, archive_extract]
requires_host: []
---

Use when a delivery arrives with claims about itself. Not for an image's acquisition record (`evidence/verify`). Do not report a single "verified": give three results.

1. **Run baseline.** `check_inputs` compares `inputs/` with the run's own `inputs.json` (size and sha256, and additions). It shows the files are as handed to the run. It does not open a container: for an archive keep the delivered hash, check members apart (`collection-intake` recipe), extract only into a job's output (`archive_extract`) and keep the container-to-member mapping (`normalise/container-members`). It says nothing about the source host or the collector's manifest.
2. **Manifest agreement.** Read the manifest's schema and say which object and algorithm each digest covers: source content, uploaded content, reconstructed sparse content and container bytes are different objects, and MD5 or SHA-1 is never compared with SHA-256. `collection_manifest_parse` reads the records; `collection_manifest_verify` checks each claim's path, size and digest apart, an independent SHA-256 beside the collector's digest: each entry is matched, mismatch, missing, unverifiable, ambiguous or read_failed, and `unexpected` lists delivered files no record names (one an ambiguous record may name is counted apart). A size, a timestamp, a bodyfile row or an archive CRC is no substitute for a recorded content digest. A mismatch is unresolved: name the stage only where independent records support it. A match shows agreement with that manifest, not that the manifest is authentic or the acquisition complete.
3. **Acquisition provenance.** Record who supplied it, when and how; the source host or resource; who the record says ran the collector, under which account; collector version and binary identity where supplied; profile identity; privileges; mode; start and end with zones; any export or repackaging since. Cite each record; say which assertions you did not check. Name missing custody stages.

Then treat `inputs/` like an image: read-only, hashed before and after, never written.

Only if a skip, error or result log exists: `verify/target-outcomes`. Only if file times matter: `verify/time-layers`.

Shows: agreement between files and the claims about them. Does not show: that a claim is true, that the collection is complete, or who altered a file that disagrees.
Record: each result apart, the manifest path and schema, the algorithm per digest, every unmatched entry.
Sensitive output: the tools print digests of whole files (those of credential-store names are withheld); run them as jobs with `secret_output: true`, and never copy a secret file's digest (a key file, a verifier store) into a post, report or indicator list.
