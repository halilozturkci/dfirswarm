# Triage and Collection Pack

What to do when the evidence is a collector's output rather than an image — the
shape most cases arrive in.

Depends on the Computer Forensics Base Pack, whose `evidence/collections` skill
introduces the problem. This pack is the work.

## What it carries

**Five skills**: `identify/collector`, `normalise/layout`,
`gaps/what-is-missing`, `verify/manifests`, `plan/what-to-collect`.

**Two tools.** `collection_id` surveys a delivered directory. It classifies every
object in it (copied files, disk containers, memory captures, archives) from its first
bytes and its name and says which of the two the class rests on, so a memory capture
beside a copied tree makes the delivery `mixed` instead of a "physical image" (a note
or a log beside an image is another file, not a second kind). It names the collectors
that left records by the paths of those records (KAPE, UAC, Velociraptor; a top-level
`C` directory is only a layout clue, and nothing names CyLR) and reads each recognised
log whole: the columns and rows of a KAPE copy and skip log, the date-and-level lines of
a UAC log (both the forms UAC 3.4.0 and 2.9.1 write), and a Velociraptor container's
`uploads.json`, `results/*.json` and `log.json` (the version pinned here records a failed
upload in the last two and never in `uploads.json`). The failures it lists are the
collectors' own recorded skips and errors in their own words, which are collection facts
and not proof that a target was in use or suspicious. It is a hypothesis from names and
limited log parsing and not an audit of the collection: a log whose columns or lines it
does not recognise is `partial` or `unsupported`, and the failure count is then `null`,
never a zero (it is a number only when every failure-source log was read whole, the walk
was complete and no archive went unopened; `failed_targets_seen` says how many rows were
read all the same). `collection_index` builds the census everything else needs: every
object with its size, its modified time to the nanosecond (`modified_epoch_ns` is a
decimal string) and the SHA-256 of the whole file; a labelled hypothesis for the path
each file had on the machine (`source_path_hypothesis`, with its method, confidence and
alternatives), and the path a KAPE copy log itself records where a row of the log
belonging to the file's own directory says it (`source_path_observed`); links, special
files, empty directories and every object it could not read as rows of their own; a
credential-store name (`may_hold_secrets`) is marked and not hashed unless asked, in a
job, with the digest going only to the sealed values file; and a distribution of
modification times that puts most files on one date, reported with its counts and no
cause, because a copy that reset times and real activity look alike. Both write the whole
of a long result to a file and name it, withhold strings shaped like a credential from
every channel (run them as jobs with `secret_output: true`: the tools cannot see whether
the job was run so), and put the summary first and the long pages last.

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
