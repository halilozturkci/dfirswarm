---
id: logs/what-exists
title: What the provider actually keeps, and for how long
when: The evidence is a cloud tenant rather than a machine.
needs: [evidence/verify]
tools: []
requires_host: []
---

There is no disk. Everything you will have is a log the provider chose to keep,
for a period the licence decides, exported by somebody with an administrator
account. Three consequences shape the whole examination.

**Retention is the clock you are racing.** As of 2026, Purview Audit Standard
defaults to 180 days for records generated since 17 October 2023; Premium and
custom policies can differ. Entra audit and sign-in logs are seven days on Free
and 30 days on P1/P2 unless routed to storage or analytics. AWS CloudTrail Event
history keeps 90 days of regional management events; data events require a
trail or event data store. These are product defaults, not evidence of this
tenant's settings. **Record the licence, retention policy, export query, earliest
and latest returned records, and therefore what could not have been examined.**
A gap at the edge of the window is not a finding about the attacker.

**The log arrives late.** The unified audit log has a lag of between thirty
minutes and a day depending on the workload. An export taken during an incident
is missing the most recent hours, and an examiner who does not know that reports
that activity stopped.

**Acquisition is somebody exercising an administrator right**, and that is part
of the record. Who exported, with which account, when, over what date range, and
with which tool. Put it in the custody section as you would the imaging of a
disk, and hash the export.

Ask for these, by name, before anything else:

    Microsoft 365   the unified audit log for the whole period, per workload;
                    Entra sign-in and audit logs; mailbox audit; message trace;
                    inbox rules and forwarding; enterprise application consents
    Google          the admin audit, login audit, Drive audit and Gmail logs
    AWS             CloudTrail management and data events, Config, VPC flow logs
    Any             the current configuration, which is evidence of what changed

And ask what was **not** enabled. Mailbox auditing off, no CloudTrail data
events, no Drive audit: each is a set of questions that cannot be answered, and
naming them is part of the answer.
