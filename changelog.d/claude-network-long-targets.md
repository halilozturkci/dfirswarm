### Changed: network-forensics says that a request target or referer over 64 KiB loses its parameter names with its values

- Route chosen: the accepted residual is written down, not removed. A target or referer over 64 KiB keeps its scheme, host and path and has its query
  and fragment withheld whole by their length, so the parameter names (which are not secrets) go with the values; the original stays in the values file
  with `write_values`. `logs/web-proxy-firewall` and the `network_log_summary` manifest now say so, and the leaf stays within its 800 tokens
  (about 798 by the pack test's count; two words dropped elsewhere in it, no rule lost). A bounded name-keeping pass would have to be added to three
  copies of the rule (`network_log_summary`, `pcap_extract`, `zeek_run`) beside the shared withholding block, for names that carry no secret.
- A test holds the residual to the code: a 72,000-character query keeps no parameter name, and a random value in the target and in the referer is
  printed nowhere.
- Packs: network-forensics (`network_log_summary`, `logs/web-proxy-firewall`).
