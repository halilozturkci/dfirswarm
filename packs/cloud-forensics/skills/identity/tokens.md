---
id: identity/tokens
title: Tokens, grants and evidence of containment
when: Assessing whether account or application access could continue after a containment action.
needs: [logs/what-exists]
tools: [ual_parse, signin_analyse]
requires_host: []
---

Use when a case asks whether access could continue after a containment step, and what the supplied evidence shows about it. Not for the first sign-in (`entra/signins`) or for what a consent or mailbox rule grants (`identity/grants`).

**Boundary.** Work offline from supplied exports, never from the tenant. Do not authenticate with, replay, refresh or submit a recovered token, cookie, key or client secret. Decode a token's claims only as data: decoding does not validate a signature, prove who issued it, or show a resource accepted it. A missing grant inventory, revocation record or resource log is an acquisition limit, not permission to query the tenant.

**Containment actions are different things.** A password reset, an MFA requirement, a session or token revocation, the removal of an application grant and a resource-side control each affect different mechanisms; none is a certificate that access ended. Record, for each: the identity, the method, the target, the result and the time actually evidenced (`ual_parse` for Microsoft 365 audit records, `signin_analyse` for later sign-ins; an Entra directory-audit export has no reader here: read it in a recorded job).

**Evaluate by provider, principal, client and token class.** Access tokens, refresh tokens, browser or application sessions and application credentials behave differently, and so do providers; do not state a rule about which ones a reset ends. A successful revocation request does not show the last moment every resource accepted an existing token: expiry and resource enforcement matter. Look for later sign-in and resource activity, and state the observation window and where logs stop. If the evidence does not settle effectiveness, record it as unknown, neither "tokens survived" nor "everything revoked".

**Build the timeline with four separate times:** the action time, the effective time if the evidence gives one, the last observed use, and the end of reliable coverage. The interval between a password reset and a later revocation is a potential exposure interval, not proof an attacker held or used access through it. Do not claim a complete session inventory or tenant state the acquisition does not support; keep partial and unknown outcomes as they are.

**Durable state outlives sessions** (consent, application credentials, delegation, mailbox rules): `identity/grants`, only if the case holds such evidence.

**Does not show:** that a token was valid, used or stolen; that a person acted; that nothing else survived.

**Sensitive output:** run any job that may expose a credential value with `secret_output: true`. Describe an artefact by where it sits, its type, its length and what it grants, with key ids in full; never its value or a hash of a secret, and of a random secret at most its first and last 4 characters, of a password or a short secret none (the worker rules).
