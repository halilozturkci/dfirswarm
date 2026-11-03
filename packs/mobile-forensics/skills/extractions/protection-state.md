---
id: extractions/protection-state
title: Protected data and acquisition boundaries
when: Data is missing, unreadable or encrypted: a gap or an absence?
needs: []
tools: [manifest_db]
requires_host: []
---

Use when data is missing, unreadable or encrypted and you must say why. Not for choosing a source (`extractions/what-you-have`) and not for a method to open protected data: this note asks for more evidence and never prescribes a bypass.

**Take the state from the record.** Lock state, passcode, profile unlock and the keys the acquisition had come from the operator and the acquisition log, not from a label or from what the files look like. If the record is silent, say the state is unknown.

**iOS.** Files carry a protection class; a class that needs the passcode-derived key is readable only after first unlock, and one that needs the device unlocked only then. "Before first unlock" and "after first unlock" describe the phone's state at acquisition: context for what the extraction could read, not a result. In a backup, `manifest_db` reports the flag (`encrypted`, `not_encrypted`, `unknown`) and the protection class of each row; a wrapped file key is present or not. An encrypted backup is not empty and an unknown flag is not unencrypted.

**Android.** Storage is split into credential-encrypted (CE) and device-encrypted (DE) areas, per user and per profile. CE data is readable once that user has unlocked; DE data earlier. An acquisition made before that unlock holds the DE area and a CE area that is ciphertext. Work profiles unlock separately. Say which user and which profile each source belongs to.

**App-layer and hardware-backed protection.** An app can encrypt its own database or keep its key in hardware-backed storage that no file copy carries. A readable file whose content looks random is a coverage gap for that app, not proof of deletion or of a wipe.

**Feasibility is not authority.** What can technically be read is separate from what the case allows. A supplied extraction does not authorise a new acquisition, a cloud account or a password attempt: ask the operator, name the evidence that would settle it (a key bag, a profile unlock record, the acquisition tool's own log) and stop there.

Shows: where the boundary lies between what was readable and what was not, and why.

Does not show: that unreadable data holds anything, that it was deleted, or that a bypass exists.

Record: the state source, the user and profile, each protected source unread and the reason, who was asked for what.

Sensitive output: never write a passcode, key or key bag into a note; record that it exists and who holds it.
