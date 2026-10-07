---
id: google/workspace
title: Google Workspace exported audit evidence
when: Supplied Google Workspace logs concern account access, administration, OAuth grants, Drive or Gmail.
needs: [logs/what-exists]
tools: [signin_analyse]
mentions: [cloudtrail_parse]
requires_host: []
---

Use when you hold Google Workspace exports (login, admin, OAuth and token, Drive, Groups, mobile, Gmail) and must say what they show about access or activity. Not for Google Cloud audit logs (Workspace and Google Cloud keep different audit sources: no Google Cloud reader is here), and not for grants, delegation, sharing or forwarding detail (`google/workspace-access`). Offline: supplied exports only; never authenticate to the tenant.

**Inventory each source on its own** (`logs/what-exists`, `logs/sources`): edition and privileges, filters, collection interval, pages, excluded or unsupported events, failures. Missing coverage limits a particular question; look at the other supplied sources before answering not determinable.

**The login parser.** `signin_analyse` reads Reports API login activities (nested events become one event each, with the activity id and the event's position kept) and flat login CSV. It rejects, counted and named, an activity whose `id.applicationName` is not login (admin, Drive, Token, Gmail), and a login row is not every session, token use or resource access. Check its field mapping against the original export. `cloudtrail_parse` is an AWS parser and is never used on Workspace evidence.

**One API page is not an acquisition.** A response that names a next page (`pagination_markers`) is partial. Overlapping exports and late-arriving events: compare what was supplied, and keep the original activity id and the record and line of every cited event.

**What each source shows, and not.** Login events show the authentication activity that source represents. Admin events show supported administrative actions. Drive events show access and changes subject to event coverage. OAuth and token events show grant and application activity, read by event name and parameters. Gmail log events, message-level exports and a BigQuery export have different schemas and different limits: say which one you hold. Verify availability and retention from the supplied collection records, not from a rule about editions.

**Time and zone.** Quote the time with its zone; a time with no zone fails the call unless `assume_utc` is set on the export's own documentation, and the answer records it.

**Does not show:** a person behind a login; that a grant was used; that a sharing or forwarding setting caused a transfer or a delivery.

**Sensitive output:** logins carry user names, addresses and devices; a value named or shaped like a credential is withheld, other secrets are not recognised. Run as a `secret_output: true` job when the case treats the export as sensitive. Never test or replay a recovered token or key.
