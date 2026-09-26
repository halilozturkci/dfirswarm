---
id: google/workspace
title: Google Workspace
when: The tenant is Google.
needs: [logs/what-exists]
tools: [signin_analyse]
requires_host: []
---

Workspace keeps several separate audit logs and they are exported separately.
Ask for each by name: admin, login, Drive, Gmail, Token, Groups, and Mobile.

Use `signin_analyse` for the Login audit export. It understands both the
Reports API activity shape (`actor`, `id.time`, nested `events`) and flat CSV;
it does not pretend that a row with no outcome field was a successful login.
The AWS-only `cloudtrail_parse` tool is not a Workspace parser.

    Login audit     every sign-in attempt, the type, the address, and whether
                    a challenge was issued
    Drive audit     view, download, edit, share, and change of visibility; only
                    on the business tiers
    Admin audit     settings changed, users created, roles granted, 2-step
                    enforcement turned on or off
    Token audit     OAuth grants: which application, which scopes, which user —
                    this is the one that matters most and is checked least
    Gmail logs      in BigQuery on the higher tiers, message-level, not content

**The Token audit is where durable delegated access is found.** A password
change can revoke Google OAuth tokens for some products, but it does not by
itself prove that every grant, Apps Script authorization, domain-wide delegation
or documented exception is gone. Enumerate grants and scopes, record explicit
revocation/removal, and look for later use. `https://mail.google.com/` is full
mailbox access whatever the application is called.

**Drive sharing is the exfiltration route.** Look for a change of visibility to
"anyone with the link", a share to an address outside the domain, and a
download burst from one account. A file shared rather than downloaded leaves
almost nothing on any endpoint, which is why the Drive audit is not optional.

**Gmail filters and forwarding** are the mailbox-rule equivalent: a filter that
forwards and deletes is how a conversation is read without anything appearing in
the sent items. The setting is in the admin audit when an administrator made it
and in the user's own settings when they did.

Two limits to state in the report: the Drive and Gmail logs exist only on
certain tiers, and Workspace retention for most logs is six months. Where a tier
did not include a log, that is what makes a question unanswerable, and it is a
fact about the tenant rather than about the analysis.
