---
id: correlate/host
title: Correlating network and host evidence
when: Network and host records may corroborate an endpoint, a process, a transfer or a time window.
needs: [capture/what-you-have, timeline/build]
tools: [timestamp_decode, zeek_run]
requires_host: []
---

Use when you hold network and host evidence about one event. Not for assuming either names the actor: a capture can show a NAT gateway, proxy or spoofed source, and a host image may hold no process-to-connection record.

1. A capture records traffic at one point; host evidence may tie a transaction to a process, account or file if the artefacts were kept. Together they support only what their records connect.
2. **Clocks before joins.** Name each clock and what each time means (start, completion, logging). Keep original times and decode each with `timestamp_decode`. Use several independent anchors across the window to estimate offset, drift and uncertainty. A service start is not automatically visible on the wire. With one anchor the correction is local; with none, correlate over a stated uncertainty interval.
3. **Build the chain:** sensor observation, address owner in the interval, any NAT, proxy or VPN translation, endpoint connection record, process identity, file or account evidence. Use full tuples and transaction ids (`zeek_run` gives per-connection records) and a process start time against PID reuse; DHCP, IPv6 changes and shared gateways change ownership. Label each link observed, inferred or unresolved.
4. A DNS cache, browser record, Zone.Identifier stream, staging timestamp or TLS fingerprint is a pivot, not a unique join. If the memory or Windows packs are loaded (check the run's tool inventory), their network-state and usage records are pivots of the same kind.
5. **When they disagree**, keep the discrepancy and test explanations: different observation points, a wrong endpoint, NAT or proxying, time uncertainty, parser limits, collection gaps, retention, event meaning. Cleared host logs or a missed capture is one explanation, not a conclusion from the mismatch; record what would tell them apart.

Shows: what two independent records support together. Does not show: who was at the keyboard, or intent. Record: clock evidence, uncertainty, each link and its label.
