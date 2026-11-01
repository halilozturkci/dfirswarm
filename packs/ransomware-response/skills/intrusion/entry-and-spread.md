---
id: intrusion/entry-and-spread
title: Reconstructing entry, persistence and spread
when: You must say how the adversary got in, stayed, and reached each machine.
needs: []
tools: []
requires_host: []
mentions: [evtx_query, auth_log, cloudtrail_parse, network_log_summary]
---

Use when you must say how the adversary first got in, how they stayed, and how the encryptor or its precursors reached each machine. Not for ordering the phases (`scope/phase-timeline`) or for what the encryptor did to files (`encryptor/traces`).

**Build a graph, not a story.** One node per asset and account, one edge per
observed step: from where, to what, by which means, at what time and from which
record. Three kinds of edge stay apart: initial access, persistence, and
deployment or spread. An edge with no record is a hypothesis and is drawn as one.
The first machine you found encrypted is a leaf of the graph, not its root.

**Correlate several record families.** Entry and spread are rarely in one source.
Line up remote-access and VPN records, identity-provider and directory sign-ins,
mail delivery, endpoint-detection alerts, service and scheduled-task creation,
remote-management and remote-execution tools, and cloud audit records. Two families
agreeing on an account, an address and a time support an edge; one family alone
supports a candidate. Keep each source's clock and its offset.

**Hold the alternatives open.** Valid credentials, an exposed service, a
phishing delivery, a third party's access, an insider and a previous compromise
each leave a different pattern, and more than one may be true. Name the routes
you could not test and the records that would separate them. Dwell can include
quiet periods and several actors: do not merge two clusters of activity because
they share a host.

**Bound the observation window.** State the earliest and latest record you
examined for each source, and the retention that ended it. An entry you cannot see
before that window is not an entry that was absent.

**Tools.** If the windows-forensics, linux-forensics, cloud-forensics or
network-forensics pack is loaded (check the run's tool inventory), `evtx_query`,
`auth_log`, `cloudtrail_parse` and `network_log_summary` read those families;
check that each answer says what it did not read. Where a pack is not loaded, say
that no tool read that family.

No exploit is reproduced, and no vulnerable service is probed, to test a route.

**Shows.** Which edges the records support, from how many families, and the window
that bounds them.

**Does not show.** A successful sign-in does not show it was the adversary's; the
earliest record does not show the entry; a tool or credential seen on two hosts
does not show one actor moved between them.

Record: the graph (nodes, edges, source records), each edge's strength, the
window per source, the alternatives left open.
Sensitive output: sign-in, VPN and mail records can hold credentials, tokens and
personal data; cite the record, never the value.
