### Fixed: the two Node jobs of CI have an hour, not 45 minutes

Part 1 of 2 of the Node 24 job took 44.5 minutes on the batch of 2026-11 and was cancelled at its limit with no failed test; the Node 22.19 part took 38 minutes. Both jobs now have 60 minutes. Every test still has its own 5-minute limit, which is what stops a hang.
