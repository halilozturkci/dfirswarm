---
id: packages/integrity
title: Package integrity against the local database
when: Checking packaged files for differences against the acquired package database.
needs: []
tools: [package_verify]
requires_host: [debsums, rpm]
---

Use when you verify packaged files on an acquired Debian or Red Hat family system. Not for what the comparison covers and for an independent baseline (`packages/baseline`, only if you report a result as more than triage).

Package verification compares installed files with what a package database says they should be. Used on an acquired system the database is the examined machine's own, so the comparison is triage against that database and not an independent trust anchor. Record where the package database is, its backend and whether the analysis tool can read it.

    package_verify root=<evidence-root> family=debian|rpm packages=[...]
                          Debian: debsums -r on the evidence's md5sums; RPM: rpm -V --root --dbpath, the flags decoded to attributes
                          one row per difference; config_files=false (Debian) leaves out configuration files

The tool points the program at the evidence root (and for rpm at the database inside it) and records every difference, the program's exit status and its first error lines; check that `scope` names the evidence path, since a wrong root verifies the analysis VM and says nothing about the target. **Run no verification script from the evidence.** An RPM database carries package-defined `%verifyscript` scriptlets, which are evidence-controlled code. The tool passes `--noscripts --nodeps` to `rpm`, but it has not shown on a trial database that the installed version suppresses them, and its `safeguards.rpm` says so: where you cannot show that the invocation runs nothing from the evidence, do not run it, and use the independent route in `packages/baseline`. The tool finds the database in the evidence (`var/lib/rpm`, `usr/lib/sysimage/rpm`, `var/lib/rpmdb` or your `dbpath`) and names its backend.

**Reading a result.** The `rpm -V` mask has one position per attribute: `S` size, `5` file digest, `T` mtime, `M` mode, `U` user, `G` group, `L` link target, `D` device, `P` capabilities; take the installed version's own definitions, and record unreadable and missing results. `S.5....T.` on `/usr/bin/ssh` says the size, digest and mtime differ from the database. It does not say the binary was maliciously replaced: expected upgrades, administrative changes, a restore and a repackaged file do the same. A `T`-only result is a timestamp difference, not a content edit. Compare the difference with the package-manager logs and trusted package contents before classifying it.

Shows: differences from the acquired database. Does not show: that an unlisted file is benign, that a matching file is the distribution's file (the database could have been changed with it), or when or by whom a difference arose. Record: the answer's scope, the program's version and exit status, and the paging file of the differences.

Sensitive output: none beyond file paths.
