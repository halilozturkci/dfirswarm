---
id: entra/signins
title: Sign-ins, and what a successful one does not tell you
when: You must establish who got in, from where, and how.
needs: [m365/unified-audit-log]
tools: [signin_analyse]
requires_host: []
---

The Entra sign-in log is richer than the audit log and it is a separate export.
Per attempt: the account, the application, the address and its resolved
location, the device and operating system, the authentication requirement, which
factors were satisfied, the conditional access policies evaluated and their
outcome, and a result code.

**The result code is the field people skip.** 0 is success. 50126 is a wrong
password. 50076 and 50079 mean multi-factor was required and the user was
prompted — and a long run of those followed by a success is consistent with an
MFA-fatigue hypothesis, but also with legitimate retries. 50158 is a conditional access
failure, and 53003 is access blocked by policy.

**A success with `authenticationRequirement: singleFactorAuthentication` on an
account expected to require multi-factor is a high-priority lead, not proof of
bypass.** Confirm which conditional-access policies applied, the authentication
details, client and token context. A legitimate exemption, previously satisfied
claim, legacy protocol or stolen token can produce superficially similar data —
see `identity/tokens`.

**Impossible travel is a hypothesis, not a conclusion.** Two sign-ins from
distant countries minutes apart is what a VPN, a mobile carrier's routing and a
cloud-hosted mail client all look like. `signin_analyse` flags the pairs and
computes the implied speed; what turns it into a finding is the rest — an
unfamiliar device, a legacy client, a new application, a consent granted in the
same window.

**Non-interactive sign-ins are a separate export and they are where the
long tail is.** A refresh token being used every hour for weeks appears there
and not in the interactive log at all. Ask for both, and say which you had.

Finally, the geography in these logs is the provider's guess from the address.
Quote it as such, and quote the address itself, because the mapping changes
and the address does not.
