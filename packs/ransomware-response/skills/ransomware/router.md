---
id: ransomware/router
title: Ransomware notes by question
when: Pick one when none is listed, or you cannot choose.
router: true
---

Use when the index shows only this line and you need a ransomware note. Not for rules: each note holds its own.

Scope
`scope/first-hour` first report, containment, preservation
`scope/phase-timeline` phases, start and end
`scope/triage-tools` survey and note scan counts
`scope/triage-tools-names` withheld paths
`intrusion/entry-and-spread` entry, persistence, spread

Encryptor
`encryptor/traces` what executed, as whom, on what
`encryptor/windows-evidence` NTFS records, service, task, log-clear events
`encryptor/samples-and-notes` recovered binary, tails, note placement
`encryptor/destroyed-backups` recovery impairment, surviving paths
`encryptor/backup-infrastructure` backup server, immutable store
`platforms/esxi-hypervisors` hypervisor host, datastore
`platforms/nas-storage` storage appliance, shares

Impact
`impact/services-and-data` services, datasets, outage

Family and data
`identify/family` family candidates, attribution limits
`identify/samples-and-decryptors` sample, behaviour, decryptors
`exfil/before-encryption` did data leave, by which route
`exfil/measure-and-claims` transfer counts, leak-site claims

Recovery
`recovery/what-is-possible` recovery position, restoration plan
`recovery/preserve-and-restore` preservation before a rebuild
`recovery/routes-and-decryptors` partial damage, deleted originals

Reporting
`reporting/conclusions-and-controls` conclusions, control findings
`reporting/for-regulators` legal, regulatory, insurance review
`reporting/notification-register` notification duties and clocks
