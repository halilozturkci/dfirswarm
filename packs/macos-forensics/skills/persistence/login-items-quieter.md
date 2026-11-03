---
id: persistence/login-items-quieter
title: Login items, background items and the quieter routes
when: A sweep reaches login items, cron, profiles, extensions or privacy permissions.
needs: []
tools: [plist_read, macos_login_items, macos_tcc]
requires_host: []
---

Use only if the sweep reaches login or background items, cron or periodic tasks, shell startup files, profiles, extensions or privacy permissions. Not for launch daemons and agents (`persistence/mechanisms`).

**Login and background items.** Read the user's legacy store (`~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm`) and, on newer builds, the registrations under `/private/var/db/com.apple.backgroundtaskmanagement/` (versioned `BackgroundItems-v*.btm` where present); also look at services embedded in application bundles and login items registered through ServiceManagement. Check the stores and their schema against the build the evidence carries. `plist_read` shows these keyed archives as structure; `macos_login_items` resolves them into items, with the path of references behind each field and the archive's own state fields raw. Keep item identifier, parent application, program, user or domain and recorded state. A registration is not execution, and what System Settings shows now is not a historical inventory.

**The quieter ones.** A `cron` table, `/etc/periodic/`, a line in `~/.zshrc` or `~/.bash_profile`, `emond` rules on older systems, configuration profiles under `/var/db/ConfigurationProfiles/`, kernel extensions in `/Library/Extensions/` and system extensions. Profiles are how a managed Mac is legitimately configured, so compare with the estate's management baseline and the install and update records before calling any of them foreign.

**Separate questions.** Approving, loading and holding a privacy permission are different things. A system extension's approval can be shaped by management policy, and registering one does not by itself create a privacy-permission record. Privacy permissions are in the TCC databases (system and per user, with their sidecars), which `macos_tcc` reads through a private copy: do not read an Accessibility permission as root or SYSTEM, or a TCC row's modified time as the time of a grant.

Shows: a registration or a configured entry, with its recorded state. Does not show: that it ran, that a permission was granted at a given time, or that a profile or extension is foreign.
Record: the store and its schema version, item identifier, parent application, program, user or domain, recorded state, and the baseline compared.
Sensitive output: `ProgramArguments` and `EnvironmentVariables` rules in `persistence/mechanisms` apply to every item read here.
