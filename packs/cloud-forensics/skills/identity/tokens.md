---
id: identity/tokens
title: Tokens, grants and evidence of containment
when: Assessing whether account or application access could continue after a containment action.
needs: [logs/what-exists]
card: No containment action certifies that access ended: record each (identity, method, target, result, evidenced time) from ual_parse {"path": "<audit export>"}, signin_analyse or cloud_normalise. Keep apart the action, effective, last-use and end-of-coverage times; unsettled effect is unknown. Never replay, refresh or submit a recovered token. Does not show: that a token was valid, used or stolen, or that nothing survived.
tools: [ual_parse, signin_analyse, cloud_normalise]
requires_host: []
---

Use when a case asks whether access could continue after a containment step. Not for the first sign-in (`entra/signins`) or for what a consent or mailbox rule grants (`identity/grants`).

**Boundary.** Work offline, never from the tenant. Do not authenticate with, replay, refresh or submit a recovered token, cookie, key or client secret. Decode a token's claims only as data: decoding does not validate a signature, prove who issued it, or show a resource accepted it. A missing grant inventory, revocation record or resource log is an acquisition limit, not permission to query the tenant.

**Containment actions are different things.** A password reset, an MFA requirement, a session or token revocation, the removal of an application grant and a resource-side control each affect different mechanisms; none is a certificate that access ended. Record for each the identity, method, target, result and evidenced time (`ual_parse`: M365 audit records; `signin_analyse`: later sign-ins; an Entra directory-audit export: `cloud_normalise`, which also reads Workspace token activities, actor kept apart from target).

**Evaluate by provider, principal, client and token class.** Access tokens, refresh tokens, browser or application sessions and application credentials behave differently, and so do providers; do not state a rule about which ones a reset ends. A successful revocation request does not show the last moment every resource accepted an existing token: expiry and resource enforcement matter. Look for later sign-in and resource activity, and state the observation window and where logs stop. If the evidence does not settle effectiveness, record it as unknown, neither "tokens survived" nor "everything revoked".

**Four separate times:** the action, the effective time if evidenced, the last observed use, the end of reliable coverage. A reset-to-revocation interval is potential exposure, not proof an attacker held or used access. Do not claim a complete session inventory or tenant state the acquisition does not support; keep partial and unknown outcomes as they are.

**Durable state outlives sessions** (consent, application credentials, delegation, mailbox rules): `identity/grants`, only if the case holds such evidence.

**Does not show:** that a token was valid, used or stolen; that a person acted; that nothing else survived.

**Sensitive output:** run any job that may expose a credential value with `secret_output: true`. Describe an artefact by place, type, length and what it grants, key ids in full; never its value or a hash of a secret, and of a random secret at most its first and last 4 characters, of a password or a short secret none (the worker rules).
