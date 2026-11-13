### Fixed: an AD1 image's further segments (.ad2, .ad3 …) belong to its set, as an E01's do

The census counted EWF (.E01 …), EnCase 7 (.Ex01 …), SMART (.S01 …) and split raw (.001 …) sets, not FTK Imager's AD1 sets. A job that
declared an image's `.ad1` was given that segment alone, so `ad1_extract` read 1 of 12 segments and said the other 11 were "not there", and
the kickoff catalogue listed the items of the first segment only (30,315 of 399,836 on a real image). The `.adN` names are now segments of
the `.ad1` beside them, ordered by their number (`.ad10` after `.ad9`, as the AD1 reader takes them), so the scope and the catalogue get the
whole set.

### Fixed: a page of the ledger a seat read is an echo in the store sweep, not a new hit

The harness's own `ledger`, `leads` and `questions` tools read the run's registers alone, but their kept outputs name no path in their
arguments (`{limit: 12}`), so the sweep could not tell what they read and held their hits. A seat that read the ledger after recording an
answer made a new hit for the answer's own strings; the coverage record that had to name it made the next. In one run a question's answer was
written 18 times in an hour and the finish loop never settled. Those outputs are now echoes (`REGISTER_READERS`), and a sweep line written
under the earlier rules is read again when the hub starts (sweep rules version 2).
