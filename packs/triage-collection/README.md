# Triage and Collection Pack

What to do when the evidence is a collector's output rather than an image — the
shape most cases arrive in.

Depends on the Computer Forensics Base Pack, whose `evidence/collections` skill
introduces the problem. This pack is the work.

## What it carries

**Fourteen skills**: five decision-rule skills, `identify/collector`, `verify/manifests`,
`normalise/layout`, `gaps/what-is-missing` and `plan/what-to-collect`, and nine
second-level skills they point to when a case needs them (`identify/collector-clues`,
`identify/acquisition-mode`, `verify/target-outcomes`, `verify/time-layers`,
`normalise/inventory`, `normalise/parsers`, `gaps/coverage-statement`,
`plan/sources-windows`, `plan/sources-linux`). The skills that read an artefact say what it shows, what it does not show and what to record, and none runs live collection.

**Two tools.** `collection_id` surveys a delivered directory. It classifies every
object in it (copied files, disk containers, memory captures, archives) from its first
bytes and its name and says which of the two the class rests on, so a memory capture
beside copied files makes the delivery `mixed` instead of a "physical image". It names
the collectors that left records by the paths of those records (KAPE, UAC,
Velociraptor; a top-level `C` directory is only a layout clue, and nothing names CyLR)
and reads each recognised log whole: the columns and rows of a KAPE copy and skip log,
the date-and-level lines of a UAC log, the rows of a Velociraptor `uploads.json`. The
failures it lists are the collectors' own recorded skips and errors in their own words,
which are collection facts and not proof that a target was in use or suspicious. It is a
hypothesis from names and limited log parsing and not an audit of the collection: a log
whose columns or lines it does not recognise is `partial` or `unsupported`, and then
there is no failure count at all, never a zero. `collection_index` builds the census
everything else needs: every object with its size, its modified time to the nanosecond
and the SHA-256 of the whole file; a labelled hypothesis for the path each file had on
the machine (`source_path_hypothesis`, with its method, confidence and alternatives),
and the path a KAPE copy log itself records where one row says it
(`source_path_observed`); links, special files and every object it could not read as
rows of their own; and a distribution of modification times that puts most files on one
date, reported with its counts and no cause, because a copy that reset times and real
activity look alike. Both write the whole of a long result to a file and name it.

**One goal template**: `collection-intake.md`.

## Why this is a pack and not a paragraph

Citing a path from a collection without saying whether the collector recorded it
cites a guess as a fact. Reporting "no deleted files were recovered" from a
delivery whose limits nobody wrote down states a limit of the evidence as a
finding about the case. Both are easy, both are common, and both are what this
pack exists to prevent.

`plan/what-to-collect` is the other direction: when a question needs evidence the
delivery does not hold, the harness never collects (it examines what it is given),
and the skill writes the request an operator can act on, with a specific list of
sources by platform.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/triage-collection
    scripts/swarm.sh start --pack computer-forensics-base,triage-collection,windows-forensics ...
