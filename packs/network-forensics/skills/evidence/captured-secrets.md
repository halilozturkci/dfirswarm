---
id: evidence/captured-secrets
title: Authentication material in captures and logs
when: A capture, log or export may hold passwords, tokens, cookies, keys or key logs.
needs: []
tools: [pcap_extract, zeek_run, network_log_summary, feature_scan]
requires_host: []
---

Use when authentication material may be in the evidence or in a tool's output. Not for deciding rotation (the case owner does).

1. Run the job with `secret_output: true` before any extraction; sensitive bytes and indexes stay under `$OUT`.
2. It occurs in auth headers, protocol exchanges, cookies, URLs, bodies, exported configs and key logs: `pcap_extract`, `zeek_run`, `network_log_summary`, base `feature_scan`.
3. Record a locator, the type, the service and what rotation implies. An attempt is not a success. Never the value, a fragment or a hash.

Shows: material exists at a place. Does not show: that it was valid or used. Record: locator, type, service, rotation.
Sensitive output: this note concerns exactly that; cite locators, never values.
