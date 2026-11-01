### Fixed: the network tools look at one entry of out_dir to know whether it is empty

- `beacon_score`, `network_log_summary`, `pcap_extract`, `pcap_summary`, `suricata_run` and `zeek_run` read the whole listing of a directory the caller
  named (`os.listdir`) only to refuse it when it was not empty, with no clock and a list as long as the directory. They now ask `holds_files`, which
  looks at the first entry and stops. The refusal ("out_dir already holds files") is the same.
- Packs: network-forensics (the six tools).
