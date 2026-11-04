---
id: flows/interpret
title: Flow records, exporter semantics and volume bounds
when: The evidence is NetFlow, IPFIX, sFlow or cloud flow-log records rather than packets.
needs: []
tools: [flow_reader, pcap_summary]
requires_host: [nfdump]
---

Use when the evidence is flow records. Not for packets (`capture/what-you-have`) or text proxy and firewall logs (`logs/web-proxy-firewall`). `flow_reader` reads an nfcapd file (NetFlow v5, v9 or IPFIX records as `nfdump`'s collector stored them; set `declared_format`) and refuses a capture and sFlow by name; any other flow format is read with the exporter's or collector's own tools. What the records say is settled here first.

1. **Identify the producer before any number.** Exporter and its address, the protocol version, observation domain, the templates in force, sampling, active and inactive timeouts, and whether a record is one direction or both. `flow_reader` gives the first four per file (`exporters`, as the collector saw them); an nfcapd file keeps no templates, timeouts or direction-pair marker (`not_provided`), so ask for the exporter's configuration. A template that was not seen leaves records undecodable; say so.
2. **Sampled is not exact.** With sampling, counts are estimates and a short flow can be missing. A volume is a bound with its sampling rate, never a measured total. `counters_exact` is false for a record nfdump flagged sampled and never true for any record: a record that is not flagged is not shown to be unsampled.
3. **A record is not a connection.** The active timeout cuts a long flow into several records, and a flow can end early on a cache limit or a reset. Times are the exporter's clock (first and last switched): state its source and zone. `flow_reader` prints UTC; `received` is the collector's clock, not the exporter's.
4. **Counters.** Know whether they are delta or cumulative, and do not sum cumulative ones. Octets are layer-3 bytes, so they differ from `pcap_summary`'s counts and from application bytes (`exfil/counters`).
5. **Addresses.** Pre- or post-NAT depends on where the exporter observes; keep both where the record has both (`nat`). An address is an observed endpoint, not a person.
6. **No payload.** A record shows that two endpoints exchanged volume in a window. It does not show content, success or intent, and a missing record does not show missing traffic: export loss, collector loss and filtered interfaces look alike.
7. **The tool's own checks.** A `status` other than `complete` means nfdump said something about the file or the counts disagree; nfdump exits 0 on a file it cannot read, so quote the `problems`, not the exit code. A cloud flow log is a flow record with its own schema, delay and sampling: this note holds the general semantics, and the cloud pack's notes the provider's. Volume questions: `exfil/volume`.

Shows: that a producer saw this volume between two endpoints in a window. Does not show: content, delivery or the endpoint's identity. Record: producer, version, domain, sampling, timeouts, clock, counter semantics.
