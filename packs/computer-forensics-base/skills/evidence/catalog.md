---
id: evidence/catalog
title: Use the catalogue with its coverage and revision
when: At the start, before repeating preparation, interpreting a listing, or reporting a catalogue search.
needs: [evidence/verify]
tools: [catalog_search]
requires_host: [fls, mmls, fsstat, istat, mactime]
---

The kickoff can run the first pass over the evidence before any agent starts, so
seven agents do not each pay for the same `fls -r`. When it did, `catalog/` holds,
per image and partition: the partition table (`mmls`), `fsstat` output, a file
listing and a body file from `fls` (and the `mactime` timeline of it), and for memory images the output
of the usual first plugins. The recipes that make it run as jobs while you work:
check for planned or running ones before you repeat any of it.

Read `catalog/README.md` first, then the current revision and the coverage
receipt of each generation you rely on; older runs may name the overview
differently. A generation that is missing, pending, partial, failed or
unsupported describes the preparation, not the evidence: it may be work not yet
done, a program the image lacks, a format no reader handles, a timeout, or
missing symbols. Record the reason, and decide whether another reader or a
capability from the operator is needed. What the catalogue did not list is not
what the exhibit does not hold.

Search it before you image anything yourself. `catalog_search` takes a regex
over one catalogue file at a time and returns one page plus the revision it read.
Name what you want: `which=generations` lists each generation, what it is, over
which object, and how far it got; `which=filelist`, `bodyfile`, `timeline`,
`fsstat` or `partitions` read a disk's files (name the partition when there are
several), `members` an archive's or an AD1's. An inventory names objects; a broad
extraction parses selected contents, and the two answer different questions.
Record the revision and the generation behind a conclusion.

Read the whole result. When the page is not all of the matches the answer names a
file that holds them (`all_matches`): read it, or page with `offset`, rather than
searching again with a bigger `limit`. Keep the query and any exclusion with the
finding. A search with no match says only that this catalogue file did not match
this query; before it becomes a material negative, establish what the source
covered, whether its parser succeeded, how names were encoded and whether the
event would have left a trace there (`kind=coverage`).

On NTFS, named `$DATA` streams show in the path field of the listing as
`name:stream`, with the attribute in the address (`168-128-4`). The colon that
ends every `fls` address is not a stream marker, so a search for any colon finds
every line. Search the path part (`catalog_search pattern=":\t[^\t]*:"`), confirm a
candidate with `istat`, and extract the stream by its full address
(`filesystem/extract`). A partial listing cannot show there are no other streams.

**Does not show.** The catalogue shows what the preparation listed and parsed, as
of its revision. It does not show that the exhibit holds nothing else, that a
partial generation is the whole, or that a file was ever opened.

If the catalogue is missing or empty, say so on the board once and build only the
part you need. Do not rebuild the whole thing in every pane. An input the catalogue
did not cover is open for you to read with other tools.
