---
id: identity/tokens
title: Tokens, consents, and why a password reset did not help
when: The account was recovered but the access continued.
needs: [entra/signins]
tools: [ual_parse, signin_analyse]
requires_host: []
---

This is the single most common failure in cloud incident response. The account
is compromised, the password is reset, multi-factor is enforced — and the
attacker is still in, because none of those revoke what they actually hold.

**A password reset is not a complete token-revocation procedure.** Entra's
published revocation table differs by how the token was obtained and where the
password was reset: some password-based tokens are revoked, while some
non-password-based cookies/tokens and confidential-client tokens can remain.
Google automatically revokes OAuth tokens for some products on password change,
with documented exceptions. Do not infer either survival or revocation from the
reset alone: record the reset method, explicit session/token revocation, grant
removal, and subsequent non-interactive use. Entra non-interactive sign-ins are
a separate export, so an examiner looking only at interactive sign-ins can miss
continued access.

**An application consent is separate durable state.** "Consent to application"
in the unified audit log, or a Token audit entry in Workspace, means a user or
administrator granted an application scopes. Revoking a session does not remove
the grant. Whether an existing token survives a password change is provider- and
token-specific, but a remaining grant or domain-wide delegation can permit new
tokens. Record both token revocation and grant removal.

**A mailbox rule survives too**, and it is quieter than either. A rule that
forwards to an external address, or moves anything matching "invoice" to a
folder and marks it read, keeps working with no session at all.

So the questions a cloud report must answer, in this order:

1. What sessions and refresh tokens existed, and were they revoked? When?
2. What applications hold a consent, with which scopes, granted by whom and when?
3. What mailbox rules, filters and forwarding addresses exist, and when was each
   created?
4. What delegations and mailbox permissions were added?
5. What did the attacker do that survives their access entirely — a shared
   Drive link, a downloaded archive, a created account?

And the timeline must say when each was **revoked**, not only when it was
created. "The password was reset at 14:02 and refresh tokens were revoked at
18:40" describes a four-hour window in which the attacker still had access, and
that window is usually where the rest of the incident happened.
