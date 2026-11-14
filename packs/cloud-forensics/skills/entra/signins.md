---
id: entra/signins
title: Entra sign-ins and their evidential limits
when: Supplied Entra sign-in exports need authentication, client, policy or account-activity analysis.
needs: [logs/what-exists]
card: signin_analyse {"path": "<export>"}, one export a call: read status and pagination_markers first. A time with no zone fails unless {"assume_utc": true} on the export's own say-so. success null (Interrupted, a prompt code) is never a failure. Leads (single_factor_successes, failure_bursts_before_success, impossible_travel) are hypotheses; an empty list excludes nothing. Does not show: a person, token use after the sign-in.
tools: [signin_analyse, cloud_normalise]
requires_host: []
---

Use when you hold Entra sign-in exports and must say who authenticated, from where, how, and with what result. Not for directory changes (directory audit: cloud_normalise), token or containment questions (`identity/tokens`) or the unified audit log. Offline: never authenticate to the tenant.

**Sources.** Interactive, non-interactive, service-principal and managed-identity sign-ins are separate exports: record which. A successful sign-in does not show a human acted or that a resource operation followed.

**Read the coverage `signin_analyse` returns first.** `status` complete means every record was read and the analysis not cut; `rejected_records`, `pagination_markers`, `file_problems` say what was not. One export a call; leads are per export. A time with no zone fails unless `assume_utc` is set on the export's own say-so; a Date (UTC) column is read as UTC; `assumptions` records either. An ambiguous day/month needs `date_order`. Cite `event_id`, `correlation_id`, record and line.

**Outcome.** `success` is true, false or null. A portal `Status` of Interrupted, and a code the tool lists as a prompt (50074, 50076...; a heuristic), are null (`outcome_class: interrupt`), never a failure; any other non-zero code is one, 50072, 50097 and 50199 too. Quote the result code with `failure_reason` as written; `result` is the tool's gloss. `prompts_before_success` is a hypothesis, not proof of MFA fatigue: read what was issued and satisfied in `authentication_details`.

**`single_factor_successes`** on an account expected to need more factors are a lead, not a bypass. Read `conditional_access_policies`, `authentication_details`, client and token context: an exemption, an earlier claim, a legacy protocol or a stolen token look alike (`identity/tokens`).

**Heuristics are bounded by the export.** `addresses_seen_once` is once among these events, not never before. `failure_bursts_before_success` needs `burst_min_failures` consecutive failures within `burst_window_seconds`, per account (object id, else user name) and application. `impossible_travel` has a speed only where both events carry coordinates; VPNs, carrier routing and cloud clients produce it too. An empty list excludes nothing.

**Non-interactive sign-ins** are not a ledger of every token use: no fixed cadence; absent rows do not show access ended. A location is the provider's estimate.

**Does not show:** a person; intent; token use after the sign-in; activity outside the supplied events.

**Sensitive output:** names, addresses and devices are personal data. Withheld credential-shaped values go to `signin-values.jsonl` only with `write_values` in a `secret_output: true` job. Never test or replay a token.
