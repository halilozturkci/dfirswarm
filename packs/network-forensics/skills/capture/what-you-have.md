---
id: capture/what-you-have
title: What the capture can and cannot contain
when: The evidence includes a pcap, a pcapng, or flow logs.
needs: [evidence/verify]
tools: [pcap_summary]
requires_host: [capinfos, editcap, mergecap, zeek]
---

Run `pcap_summary` first. Before any question about content, four properties of
the capture decide what an answer can possibly be worth.

**The snap length.** A capture taken with a snap length of 96 bytes holds
headers and no payload. Every question about content is unanswerable on it, and
that is a fact about the evidence rather than a failure of the analysis. Say it
once, early, in the report.

**The capture point.** Inside the network, outside the firewall, on a span port,
on the host itself. It decides whether you see internal traffic at all, whether
addresses have been translated, and whether both directions are present. A
capture from outside a NAT shows one address for a hundred machines.

**The clock.** Packet times come from the capturing machine, not from either
endpoint, and nothing in the file says whether that machine's clock was right.
Where the case has host artefacts, find one event visible in both and use it to
measure the offset. State the offset you applied.

**The gaps.** Look at dropped-packet counts where the format records them, and
at the time between the first and last packet against the file size. A capture
that rolled, or that was filtered before it was written, is missing exactly the
part somebody chose not to keep.

Then the shape: `pcap_summary` returns the link type, the address pairs, the
ports, the byte counts per conversation and the time range. That shape is the
map for everything after it, and on a large capture it is also the only part you
should read end to end.

Before changing a capture, record `capinfos -M -c -a -e -u -s -x FILE`. Make a
working derivative for filtering, deduplication, splitting or merging; never
replace the original. `editcap` can remove exact duplicates and split by time,
and `mergecap` makes a time-ordered working copy, but each changes the evidence
view and belongs in the derivation record with input/output hashes.

Two formats: classic `pcap` with one global header, and `pcapng` with blocks and
possibly several interfaces in one file. The parser here reads both. Where the
host has `zeek`, run it as well — structured logs per protocol are the form
every later question wants.

If no capture was supplied, do not pretend a disk or memory image is one. Fetch
`capture/carve-from-images`; its output is explicitly a carved derivative with
weaker time and completeness claims.
