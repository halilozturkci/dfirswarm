### Fixed: network-forensics tool versions and parser labels follow one written rule

`docs/packs.md` section 8 ("The tool contract") now says when a tool's `version`
and its `PARSER` label move. In all six network scripts `TOOL`'s version equals
the manifest's (pcap_summary said 5 against 6), and `tests/pack-network-manifests.test.ts`
asserts it for every network tool. beacon_score (4 to 5), network_log_summary
(5 to 6) and pcap_summary (6 to 7) took the version bump that the 2026-10-27
reader fixes did not give them.

The five `PARSER` labels under the rule, from each script's history since its
label last moved:

- pcap_summary 5 to 6: the unsupported block types became a lossless page of
  every type (a tally in bounded memory, spilled past 4,096 types), and the
  endpoint row counts are null when the sums were cut: records read and typed
  differently.
- pcap_extract/5, zeek_run/5, suricata_run/5, network_log_summary/5 stay: since
  they last moved the changes are clocks and cadence of clocks, a long target or
  referer whose query is withheld by length, the order of the last word, and the
  shared blocks, which are bounds, withholding and stop handling, not what a
  record says.
