---
id: packages/integrity
title: Package integrity against local and independently trusted baselines
when: Checking packaged files for differences and establishing what the comparison covers.
needs: [triage/system-profile]
tools: []
requires_host: [debsums, rpm]
---

Package verification compares installed files with what a package database says they should be. Used on an
acquired system the database is the examined machine's own, so the comparison is triage against that database
and not an independent trust anchor. Record where the package database is, its backend and whether the analysis
tool can read it.

    debsums --root=<evidence-root> --admindir=<evidence-root>/var/lib/dpkg -c
                          Debian family: packaged files whose hash differs from the recorded one
    debsums --root=<evidence-root> --admindir=<evidence-root>/var/lib/dpkg -a
                          include configuration files, which change legitimately
    rpm --root <evidence-root> --dbpath <database-path-inside-the-root> -Va --noscripts --nodeps
                          Red Hat family: one flag position per attribute that differs

Point both the root and the administrative directory at the evidence and confirm the command's output names the
evidence path: getting this wrong verifies the analysis VM and says nothing about the target. Keep the whole
stdout, stderr and exit status. **Run no verification script from the evidence.** An RPM database carries
package-defined `%verifyscript` scriptlets, which are evidence-controlled code; `--noscripts` and `--nodeps`
exist to keep them and the dependency checks out of an offline comparison. Confirm those options on the
installed `rpm` version against a trial database before relying on them, and where you cannot show that the
invocation runs nothing from the evidence, do not run it: use the independent route below. Locate the acquired
RPM database from the evidence's own configuration instead of assuming `/var/lib/rpm`, since the path and the
backend vary.

**Reading a result.** The `rpm -V` mask has one position per attribute: `S` size, `5` file digest, `T` mtime,
`M` mode, `U` user, `G` group, `L` link target, `D` device, `P` capabilities; take the installed version's own
definitions, and record unreadable and missing results. `S.5....T.` on `/usr/bin/ssh` says the size, digest and
mtime differ from the database. It does not say the binary was maliciously replaced: expected upgrades,
administrative changes, a restore and a repackaged file do the same. A `T`-only result is a timestamp
difference, not a content edit. Compare the difference with the package-manager logs and trusted package
contents before classifying it.

**What the comparison covers.** Coverage follows package manifests, not directory names: a package can own
files outside `/usr` and files nobody owns can sit inside it. Identify separately the unowned files, files
with no recorded checksum, diversions and alternatives, configuration changes, permissions, capabilities, ACLs
and security labels. Anything in `/opt`, `/usr/local`, a home directory or a container layer that no package
claims was never compared, so a clean report is not a clean machine. A package database written during the
incident window is a stronger lead than one modified binary, and the database's and a binary's timestamps are
leads whose meaning you check against package-manager logs, snapshots and deployment records.

**An independent baseline.** Run trusted tools against explicitly scoped evidence or a documented working
copy, and confirm no path resolves into the analysis host. To compare against something the examined machine did
not write, obtain an authorised offline copy of the exact package for the exact architecture, with its
repository's or its signer's provenance, extract it without running its scripts, and compare payload and
metadata. Record the package version, its source, the signature or repository verification result, the scope
and the legitimate configuration exceptions. Where no trusted baseline is available, report only differences
from the acquired database and say that is all this is.

**Does not show.** That an unlisted file is benign, that a matching file is the distribution's file (the
database could have been changed with it), or when or by whom a difference arose.
