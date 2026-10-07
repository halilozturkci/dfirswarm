---
id: entra/signins
title: Entra sign-ins and their evidential limits
when: Supplied Entra sign-in exports need authentication, client, policy or account-activity analysis.
needs: [logs/what-exists]
tools: [signin_analyse]
requires_host: []
---

Use when you hold Entra sign-in exports and must say who authenticated, from where, how, and with what result. Not for changes to identities, applications or policy (directory audit: no reader here), for token or containment questions (`identity/tokens`), or for the unified audit log. Offline: supplied exports only; never authenticate to the tenant.

**Sources.** Sign-ins describe authentication and access attempts; directory audit describes changes. Interactive, non-interactive, service-principal and managed-identity sign-ins are separate exports: record which were supplied. A successful sign-in does not show a human acted or that a resource operation followed.

**Read the coverage `signin_analyse` returns first.** `status` is complete only if every record was read; `rejected_records`, `pagination_markers`, `file_problems` say what was not. One export per call; leads are per export. A time with no zone fails the call unless `assume_utc` is set on the export's own say-so, and a column named Date (UTC) is read as UTC; `assumptions` records either. An ambiguous day/month string needs `date_order`. Cite `event_id`, `correlation_id` and the record and line of each event.

**Outcome.** `success` is true, false or null. A portal `Status` of Interrupted, and a code the tool lists as a prompt (50074, 50076...; a heuristic), are null (`outcome_class: interrupt`), never a failure. Quote the result code with the provider's `failure_reason` as written; `result` is the tool's gloss, not the provider's text. Many prompts (`prompts_before_success`) then a success is a hypothesis, not proof of MFA fatigue or password guessing: establish what was issued and how it was satisfied from `authentication_details`.

**Single-factor success** (`single_factor_successes`) on an account expected to need more than one factor is a lead, not a bypass. Read `conditional_access_policies`, `authentication_details`, the client and token context: an exemption, an earlier claim, a legacy protocol or a stolen token can look alike (`identity/tokens`).

**Heuristics are bounded by the export.** `addresses_seen_once` means once among these events for the account, not never before. `failure_bursts_before_success` needs `burst_min_failures` consecutive failures within `burst_window_seconds`, per account (object id, else user name) and application; failures days apart are not a burst. `impossible_travel` has a speed only where both events carry coordinates; a country-only pair is coarse. VPNs, carrier routing, shared egress and cloud clients also produce them. An empty list excludes nothing.

**Non-interactive sign-ins** are a separate export and not a ledger of every token use: expect no fixed cadence; absent rows do not show access ended. A location is the provider's estimate for the address; quote the address.

**Does not show:** a person; intent; token use after the sign-in; activity outside the supplied events.

**Sensitive output:** names, addresses and devices are personal data. Withheld credential-shaped values go to `signin-values.jsonl` only with `write_values`, in a `secret_output: true` job. Never test or replay a token.
