### Fixed: the ledger and inputs tools and the regroup post are paged under the inbox page bound

One `ledger` reply of 654,942 characters locked a seat's context for a quarter of
an hour. `ledger` and `inputs` now answer one page of whole items under
`SWARM_INBOX_PAGE_CHARS` (40,000 by default) with `next` and `remaining`; when a
page holds anything back, the whole result is kept under `tool-output/<seat>/`
and named as `kept_as` with its size and sha256. `ledger` takes `from` (the
`E-<seq>` a page named as `next`; entries recorded since come after it, none
shifts or repeats) and `ids` (exact `E-<seq>` reads, each whole with its hash,
supersession, attestations, disputes and answer review; ids that do not exist
are in `not_found`). An entry larger than the bound comes whole, alone on its
page. The regroup post lists at most 50 items per list (fewer if the post would
pass the bound), with the count of the rest and a file the harness wrote that
holds every list whole, named with its size and sha256: a first post is
delivered whole whatever the page bound, so the bound is in the post itself.
On a ledger of 1,000 entries at the per-field maxima the default `ledger` call
was one reply of 1,494,257 characters; it is now 37,881.
