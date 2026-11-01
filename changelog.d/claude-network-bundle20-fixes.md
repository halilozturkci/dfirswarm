### Fixed: network-forensics never waits on a file that became a pipe, answers a second stop signal with no second document, and states pcap_summary's real worst case

- Every read of a path the caller or the engine supplied (the capture and the log of `pcap_summary` and `network_log_summary`, a Zeek log, `eve.json`,
  a rules file, an exported object's digest, the recipe's target and capture) goes through `open_regular`: opened without blocking, the type taken from
  the descriptor, anything but a regular file refused as JSON (a Zeek log or `eve.json` that a symbolic link would replace is refused too). A name that
  was a regular file when it was checked and a pipe when it was opened used to wait for a writer until the harness killed the tool.
- A second stop signal during the answer to the first no longer gives a traceback (`beacon_score`) or a second document (`pcap_summary`, and
  `suricata_run`, `zeek_run`, `pcap_extract` and `network_log_summary` when it landed while a refusal was written): the first signal counts. A refusal
  is written with the stop signals held.
- `zeek_run`'s answer to a stop prints no token-shaped log name (the word `withheld` stands for it) and lists at most 200 names, with the total; the
  setting aside of token-shaped log names writes its index once, with one `fsync`, under the tool's own clock, and the mode loop is under it too.
  `suricata_run`'s answer to a stop lists at most 200 files and the total.
- `network_log_summary` registers its values file the moment it exists, with the stop signals held, so a stop between the two leaves no empty values file.
- `pcap_summary`'s worst case was stated too low. Re-measured with `group: endpoint` and an `out_dir`: a raw-IP record of 40 bytes (a 24-byte capture
  of an IPv4 header and the two UDP ports), each from a source of its own, leaves 26.8 times the capture, and 46.8 times at the peak with the temporary
  aggregate file (500,000 records: 20 MB in, 536 MB out, 935 MB at the peak; 1,000,000 records: 1.07 GB, 1.87 GB). Other shapes tried were lower
  (IPv6 18.1, TCP in an Ethernet frame 12.7, 20 to 28 captured bytes 23.8 to 26.8 times). The manifest and `capture/what-you-have` say so; the leaf
  stays within its budget.
- The start-up figures in the README and the manifests are stated for a quiet host: a busy one sees more. `recipe.json` carries the same sentence.
- Packs: network-forensics (the six tools and the recipe).
