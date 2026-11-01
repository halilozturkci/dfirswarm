### Fixed: pcap_summary says when its block types spilled, and how large its whole-result files can grow

- `spilled_to_disk` is now true when only the tally of unknown pcapng block types was moved to the temporary SQLite file (more than 4,096 distinct
  types); it used to look at the tuple, endpoint, talker and port tables alone and answer false for such a capture.
- The manifest and `capture/what-you-have` state the worst-case size of the whole-result files against the capture, measured on synthetic captures on
  2026-11-01 with `group: endpoint` and an `out_dir`: 12.7 times for 3,000,000 TCP packets (210 MB in, 2.67 GB out), 26.8 times for 1,000,000 raw-IP records of 40
  bytes (an IPv4 header and the two UDP ports; 40 MB in, 1.07 GB out; the largest of the shapes tried), 3.5 times for the block-type file of 6,000,000
  blocks (72 MB in, 252 MB out), and up to 46.8 times at the peak while the temporary aggregate file exists. Nothing is cut; a caller gives `$OUT` that room.
- Packs: network-forensics (`pcap_summary`).
