---
id: verify/manifests
title: Baseline, manifest and provenance of a delivery
when: You take custody of a collection or rely on its manifest.
needs: [identify/collector]
tools: [check_inputs, collection_index]
requires_host: []
---

Use when a delivery arrives with claims about itself. Not for an image's acquisition record (`evidence/verify`). Do not report a single "verified": give three results.

1. **Run baseline.** `check_inputs` compares `inputs/` with the run's own `inputs.json` (size and sha256, and additions). It shows the files are as they were handed to the run. It does not open a container, so for an archive keep the delivered hash, inventory the members apart (the base `archive-members` recipe), extract only into a job's output (neither this pack nor the base ships an extractor yet: use the archive's own program in a job that writes under `$OUT`) and keep the container-to-member mapping. It says nothing about the source host or the collector's manifest.
2. **Manifest agreement.** Read the manifest's actual schema and say which object and which algorithm each digest covers: source content, uploaded content, reconstructed sparse content and container bytes are different objects, and MD5 or SHA-1 is never compared with SHA-256. Give each entry one of matched, mismatched, missing, unreadable or unverifiable, and list delivered objects the manifest does not name. A size, a timestamp, a bodyfile row or an archive CRC is no substitute for a recorded content digest. A mismatch is an unresolved discrepancy: name the stage only where independent records support it. A match shows agreement with that manifest, not that the manifest is authentic or the acquisition complete. No tool of this pack reconciles a manifest with the files yet: `collection_index` lists what was delivered, with SHA-256 of whole files, and pairs paths with a KAPE copy log's rows.
3. **Acquisition provenance.** Record who supplied it, when and by what route; the source host or resource; the claimed operator and execution account; collector version and binary identity where supplied; profile identity; privileges; mode; start and end with zones; any export or repackaging since. Cite each record and say which are assertions you did not check. Name the custody stages that are missing.

Then treat `inputs/` as you would an image: read-only, hashed before and after, nothing written into it.

Only if a skip, error or result log exists: `verify/target-outcomes`. Only if file times are in play: `verify/time-layers`.

Shows: agreement between files and the claims made about them. Does not show: that a claim is true, that the collection is complete, or who altered a file that disagrees.
Record: each result separately, the manifest path and schema, the algorithm per digest, every unmatched entry.
Sensitive output: `collection_index` prints digests of whole files; run it as a job with `secret_output: true`, and do not copy the digest of a file that is itself a secret (a key file, a verifier store) into a post, report or indicator list.
