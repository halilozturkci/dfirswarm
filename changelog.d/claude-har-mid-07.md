### Fixed: harness

The rival-area check (`rival_area_uncovered`) runs for every answer review. It
used to run only when a review gave `reproduced_at`, so a review that gave no
locator and no derivation passed where one that supplied more was capped, and
an agent could pass by dropping review metadata. Without locators the check
now follows the inputs the answer's support reaches (the answer's refs, the
refs of the entries it cites, and the derivation's inputs); with them it follows
the located objects, as before. The same answer gets the same verdict whatever
the review gives. The warning `no_locator_or_derivation` stays a warning.
