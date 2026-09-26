---
id: packages/integrity
title: Which binary on this machine is not the one the distribution shipped
when: You suspect a replaced system binary, or you need to clear thousands of files quickly.
needs: [triage/system-profile]
tools: []
requires_host: [debsums, rpm]
---

Linux ships with a hash database of almost every file it installed. It is the
cheapest strong answer on the whole machine, and first passes skip it.

    debsums --root=/evidence/root --admindir=/evidence/root/var/lib/dpkg -c
                          Debian/Ubuntu: list packaged files whose hash differs
    debsums --root=/evidence/root --admindir=/evidence/root/var/lib/dpkg -a
                          include configuration files, which change legitimately
    rpm --root /evidence/root -Va
                          Red Hat family, with a flag per attribute that changed
    rpm --root /evidence/root -Va | grep '^..5'
                          digest changes (keep the unfiltered output too)

`rpm -Va` output is a nine-character mask: `5` is the digest, `S` size, `T`
mtime, `M` mode, `U` owner, `G` group. `S.5....T.` on `/usr/bin/ssh` is a
replaced binary. `.......T.` on a config file is somebody editing it.

Three things to know before you quote the result:

1. **A clean report is not a clean machine.** Only packaged files are covered.
   Anything in `/opt`, `/usr/local`, a home directory or a container layer was
   never hashed by anyone.
2. **The database is on the machine being examined**, so a sufficiently careful
   operator could have updated it after replacing a binary. Check the
   database's own mtime (`/var/lib/dpkg/info/`, `/var/lib/rpm/`) against the
   incident window; a package database written during the intrusion is a far
   louder finding than a modified binary.
3. **Run it against an extracted read-only root, not against your own host.**
   Point both debsums' root and admin directory at the evidence; point rpm's
   root at it. Confirm the command echoed the evidence path. Getting this wrong
   verifies the analysis VM and tells you nothing. These checks cover the
   package database's expected hashes; they do not fetch a trusted package or
   prove that database was not altered.

Where neither tool exists, the fallback is the distribution's published hashes
for the exact package version, taken from outside the evidence. Say which route
you used.
