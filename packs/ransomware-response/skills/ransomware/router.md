---
id: ransomware/router
title: Ransomware notes by question
when: Pick one when none is listed, or you cannot choose.
router: true
---

Use when the index shows only this line and you need a ransomware note. Not for a note's own rules; those below hold for every note.

Always
- Chain deployment, execution and file change per asset, and say which links the evidence supports.
- A missing binary does not show it was deleted; a service installed does not show it ran.
- A matching note or extension names a family candidate, not the variant or a decryptor's fit.

Scope
`scope/first-hour` first report, containment, preservation
`scope/phase-timeline` phases, start and end
`scope/triage-tools` survey and note scan counts
`scope/triage-tools-names` withheld paths
`intrusion/entry-and-spread` entry, persistence, spread

Encryptor
`encryptor/traces` what executed, as whom, on what
`encryptor/windows-evidence` NTFS records, services, tasks, log clears
`encryptor/samples-and-notes` recovered binary, tails, note placement
`encryptor/destroyed-backups` recovery impairment, surviving paths
`encryptor/backup-infrastructure` backup server, immutable store
`platforms/esxi-hypervisors` hypervisor host, datastore
`platforms/nas-storage` storage appliance, shares

Impact
`impact/services-and-data` services, datasets, outage

Family and data
`identify/family` family candidates, limits
`identify/samples-and-decryptors` sample, behaviour
`exfil/before-encryption` did data leave, by which route
`exfil/measure-and-claims` transfer counts, leak-site claims

Recovery
`recovery/what-is-possible` recovery position, restore plan
`recovery/preserve-and-restore` preserve before rebuild
`recovery/public-decryptors` public decryptors, tested on copies
`recovery/routes-and-decryptors` partial damage, deleted originals
`recovery/scheme-from-sample` key scheme from sample, dump, files

Reporting
`reporting/conclusions-and-controls` conclusions, control findings
`reporting/for-regulators` legal, regulatory, insurance
`reporting/notification-register` notification duties, clocks
