# Triage and Collection Pack

What to do when the evidence is a collector's output rather than an image — the
shape most cases arrive in.

Depends on the Computer Forensics Base Pack, whose `evidence/collections` skill
introduces the problem. This pack is the work.

## What it carries

**Five skills**: `identify/collector`, `normalise/layout`,
`gaps/what-is-missing`, `verify/manifests`, `plan/what-to-collect`.

**Two tools.** `collection_id` recognises KAPE, UAC, Velociraptor and CyLR from
the shape of the tree, reads that collector's own log, and lists **the targets
that failed together with the recorded reasons**. A failure is a collection
fact, not proof that the target was in use or suspicious. `collection_index` builds the index
everything else needs: every file with its hash, the path it has now and the
path it had on the machine, plus two losses that are otherwise silent — a named
stream whose colon was rewritten, and a tree whose files all share one
modification date because an intermediate copy dropped the originals.

**One goal template**: `collection-intake.md`.

## Why this is a pack and not a paragraph

Citing a path from a collection without the mapping cites something that never
existed. Reporting "no deleted files were recovered" from a logical acquisition
states a limit of the evidence as a finding about the case. Both are easy, both
are common, and both are what this pack exists to prevent.

`plan/what-to-collect` is the other direction: occasionally the examination
happens before the collection, and then a specific list is worth more than any
analysis.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/triage-collection
    scripts/swarm.sh start --pack computer-forensics-base,triage-collection,windows-forensics ...
