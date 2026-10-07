---
id: capture/derivatives
title: Making a working derivative of a capture
when: You need to filter, split, merge, deduplicate or build a capture from a hex dump.
needs: []
tools: []
requires_host: [capinfos, editcap, mergecap, tcpdump, text2pcap]
---

Use when you must change what a capture holds to work with it. Not for judging the original (`capture/what-you-have`).

- The original stays untouched. Every derivative is a new file under `work/` (in a job, `$OUT`) with its command, settings, the input and output hashes and packet counts in and out, recorded with `capinfos FILE` of both. `editcap -h`, `mergecap -h` and `tcpdump -h` print the installed options.
- `editcap` removes duplicates and splits by time or count: removing duplicates can delete genuine retransmissions or the same packet seen by two sensors, so say what rule was used and what it removed.
- `mergecap` interleaves captures by timestamp: it does not correct unsynchronised clocks and cannot order input that is unordered inside. Record each input's clock source first.
- `tcpdump -r IN 'FILTER' -w OUT` is offline filtering only; record the filter text. Never capture live. A filter that selects a host drops the rest of the conversation's context.
- `text2pcap` builds a capture from a hex dump with headers and times it makes up. Label the result synthetic: it shows what the dump contained, never that traffic occurred.

Shows: which packets your working copy holds and how they were chosen. Does not show: that a packet you filtered out was irrelevant. Record: command, filter, hashes, counts, what each step removed.
Sensitive output: a derivative holds the original's payload; keep it under `$OUT`, run a job that writes one with `secret_output: true`, and cite packet numbers, not content.
