---
id: apps/identity-containers
title: App identity across containers, packages and restores
when: You must say which app, user and device a directory or package belongs to.
needs: []
card: A container directory name is not an identity. In a backup the domain manifest_db lists (AppDomain-, AppDomainGroup-, AppDomainPlugin-) is the mapping; on a file system read the container's metadata plist with plist_read {"path": "<plist>"}. On Android map every path to package, user and root (CE or DE); ab_layout's derivative carries no user number. The same bundle id on two devices is the same app, not the same data: say fresh install, restore or migration, and from what. An unresolved mapping limits attribution to the app; never fill it from a listing. Does not show: who used the app, that data was created here, or that two roots are one account.
tools: [plist_read, manifest_db, ab_layout]
requires_host: []
---

Use when you must attribute data to an app, a user and a profile, and say whether it moved between devices. Not for iOS container metadata plists and time conversion (`ios/containers-and-time`, only if you read them).

**iOS.** A container directory name is not an identity. App, app extension and shared app group are different containers with different bundle ids. In a backup, the domain `manifest_db` lists (`AppDomain-<bundle id>`, `AppDomainGroup-<group id>`, `AppDomainPlugin-<id>`) is the mapping; on a file-system extraction use the container's metadata plist read with `plist_read`.

**Android.** The package name is the identity, and the owner is the user: the same package has a separate data root for each user and each work profile, and a credential-encrypted and a device-encrypted root (`extractions/protection-state`). Map every path to package, user and root before you compare two. In an adb backup, `ab_layout` keeps the package from `apps/<package>/` and lays the data under `data/data/<package>/`; that layout is a derivative and carries no user number.

**Reinstall, restore and migration.** A restore from a backup or a transfer to a new device recreates containers with new directory names; a reinstall can reset data or keep it; an app's id in a store can change. The same bundle id on two devices is the same app, not the same data. Say which of fresh install, restore or migration the evidence supports, and from what (an install record, a restore marker, a container creation time you read as a creation time of that directory only).

**Unresolved mappings** limit attribution to an app; the original path and file id stay citable. Do not fill a gap with a guess from a directory listing.

Shows: which app, user and profile a path belongs to, where a mapping exists.

Does not show: who used the app, that data was created here, or that two roots are one account.

Record: each mapping and its source (plist, domain, package list), each one unresolved, and the restore or migration finding.

Sensitive output: container and account plists can hold tokens; read the keys you need or run `plist_read` as a job with `secret_output: true`.
