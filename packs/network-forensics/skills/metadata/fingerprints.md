---
id: metadata/fingerprints
title: TLS fingerprints and Suricata output, with limits
when: A finding rests on a JA3 or JA4 value or a Suricata match.
needs: []
tools: [suricata_run]
requires_host: [suricata, tshark]
---

Use when a finding rests on a fingerprint or a Suricata match. Not for names and handshake facts in general (`metadata/dns-tls`).

- Record the real versions of `tshark` and `suricata` first, then verify the fingerprint fields in produced output: check `tshark -G fields` for the field and look at one real value. Do not assume what a version supports.
- `suricata_run` writes an explicit configuration (`home_net` sets HOME_NET; a rule using any other variable needs your own `config`), tests it with `suricata -T` and runs nothing if that fails. A rules file or config from `inputs/` is refused: copy it out, read it, and say so. When `rule_load.known` is false nothing shows a rule loaded. Read `tls_fingerprints`: what the configuration asks for, the TLS events logged and the fingerprints produced are three numbers. Zero produced with events present does not show the build lacks the feature, and a clean exit does not show the settings took effect.
- A fingerprint describes how a client implementation speaks. Libraries share values, browsers imitate each other, GREASE and configuration change them. Use one only as a pivot beside SNI, certificate, destination, timing and host-process evidence, never as a binary's identity.
- `checksum_mode` is `none` by default because capture offload leaves invalid checksums in valid traffic; use `all` when checksum integrity is the question, and record the mode either way.
- An alert is a rule match on reassembled traffic, not a finding. The rules are the caller's (none ship): record the rules file's SHA-256, its source and its licence, and never download rules during the case.
- EVE can carry SNI, URLs, DNS names and file names: run as a job with `secret_output: true`.

Shows: what this engine, this configuration and this ruleset produced. Does not show: what a different build or ruleset would. Record: versions, configuration and rules hashes, checksum mode, the three fingerprint counts.
