---
id: identify/collector
title: Which tool made this, and what that tells you
when: The evidence is a directory tree or an archive rather than an image.
needs: [evidence/collections]
tools: [collection_id, file_type]
requires_host: []
---

Run `collection_id` on the tree. It recognises the shape each collector leaves
and reads that collector's own log, which is the fastest way to learn what was
collected and — far more importantly — what failed.

    KAPE            a tree mirroring C:\, often with $MFT and $J at the root,
                    and a *_CopyLog.csv and *_SkipLog.csv beside it
    UAC             a .tar.gz with [root], [bodyfile], [live_response] and
                    per-artefact directories, plus uac.log
    Velociraptor    a container zip with uploads/ and JSON result files per
                    artefact, and an uploads.json index
    CyLR            a zip mirroring the source paths, NTFS files pulled through
                    the raw handle
    a hand-made copy   no manifest, no log, and no way to know what was left out

**The collector's log is evidence.** Preserve every failed target and the
collector's recorded reason. A failure may mean a lock, a permission boundary,
an absent path, an unsupported object, or a collector defect; failure alone
does not make the target suspicious. The recorded failure is a fact about the
collection and belongs in the report.

**The artefact list is the scope of the collection**, and it is usually a
profile somebody chose. KAPE targets, UAC profiles and Velociraptor artefact
sets each define a different subset, and a question outside that subset cannot
be answered no matter how carefully you look. Name the profile in the report.

**A collection made on a running machine is a smear.** Files were copied over
minutes while the system kept writing, so two artefacts can disagree without
either being wrong. Where the log records start and end times, quote them.

Then go to `normalise/layout`, because the paths in the tree are not the paths
that were on the machine.
