---
id: encrypted/router
title: Encrypted-container notes by question
when: Pick an encrypted-container note when none is listed, or you cannot choose.
router: true
needs: []
tools: []
requires_host: []
---

Use when the index shows only this line and you need an encrypted-container note. Not for rules: each note holds its own.

Identify
`identify/headers` what protects a volume, archive or document
`identify/by-format` naming a format from a signature

Volumes
`volumes/bitlocker` BitLocker protectors
`volumes/bitlocker-opening` opening it with supplied material
`volumes/luks-filevault` LUKS or FileVault route
`volumes/luks` LUKS header, keyslots, copies, backups
`volumes/filevault-apfs` Apple volume, Core Storage or APFS
`volumes/veracrypt-truecrypt` no signature, VeraCrypt or TrueCrypt
`volumes/layered-reading` encrypted volume inside other layers

Archives and documents
`archives/protected` password-protected archive or document
`archives/formats` ZIP, 7-Zip, RAR, Office, PDF structure

Key material the case supplies
`keys/where-they-hide` where to look, and under what authority
`keys/recovery-key-scan` reporting a key scan's result
`keys/other-sources` stores, memory, escrow, shell history

Messages and files
`messages/openpgp` an OpenPGP message's packets
`files/aescrypt` an AES Crypt file

Password recovery
`recovery/authorised` authorising an attempt to recover a password
