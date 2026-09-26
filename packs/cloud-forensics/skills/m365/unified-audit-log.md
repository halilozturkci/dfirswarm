---
id: m365/unified-audit-log
title: The Microsoft 365 unified audit log
when: The tenant is Microsoft and something happened in it.
needs: [logs/what-exists]
tools: [ual_parse]
requires_host: [pwsh]
---

One log for every workload — Exchange, SharePoint, OneDrive, Teams, Entra,
Power Platform — with a row per operation. It is exported as CSV, and **the
column that matters is a JSON blob**: `AuditData` carries almost everything,
and a spreadsheet view of the export hides it. `ual_parse` explodes it.

The operations worth knowing by name:

    UserLoggedIn, UserLoginFailed          sign-in, with the client and address
    MailItemsAccessed                      an item was read: the exfiltration
                                           question, and only on premium licences
    New-InboxRule, Set-InboxRule, UpdateInboxRules   a rule was created or changed
    Set-Mailbox with ForwardingSmtpAddress mail being sent somewhere else
    Add-MailboxPermission, Add-RecipientPermission   delegation
    FileDownloaded, FileSyncDownloadedFull SharePoint and OneDrive
    FileAccessed, FileModified, FileDeleted
    AnonymousLinkCreated, SharingSet       a link anyone can use
    Consent to application, Add service principal   an application was granted access
    Add member to role                     privilege

**`MailItemsAccessed` is the closest thing to evidence a mailbox item was
accessed**, but it does not prove a human read the content. Bind operations
within a two-minute interval are aggregated; duplicate bind and sync records
can be filtered at one-hour intervals. Check `MailAccessType`, `OperationCount`,
`Folders` and licensing before interpreting a quiet period as absence.

**`ClientIP` is the address the provider saw.** For a modern client that is
often a proxy or a mobile carrier, and for Exchange operations it may be an
internal Microsoft address. Do not attribute on it alone; pair it with the
sign-in log, which carries far more context.

Two habits. Filter by `RecordType` and `Operation` rather than by free text,
because the same word appears in a dozen workloads. And quote the `Id` of the
record you cite — every row has one, and it is what lets somebody else find it
again in an export of half a million rows.
