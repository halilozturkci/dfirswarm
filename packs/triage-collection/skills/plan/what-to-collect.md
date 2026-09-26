---
id: plan/what-to-collect
title: What to ask for, when a collection is still being planned
when: The operator can still influence what is collected.
needs: [gaps/what-is-missing]
tools: []
requires_host: [uac, velociraptor]
---

Occasionally the examination happens before the collection, and then a list is
worth more than any analysis. Ask for these, and say why, because "collect
everything" gets refused and a specific list usually does not.

**Windows, in order of value per megabyte:**

    $MFT, $J, $LogFile, $Boot          the file system's own record
    Windows/System32/config/*          SYSTEM, SOFTWARE, SAM, SECURITY
    Users/*/NTUSER.DAT, UsrClass.dat   per user
    Windows/System32/winevt/Logs/*     all of them, not just Security
    Windows/Prefetch/*                 execution
    Windows/AppCompat/Programs/Amcache.hve
    Users/*/AppData/**/PowerShell/PSReadLine/ConsoleHost_history.txt
    Users/*/AppData/**/Recent/, AutomaticDestinations/
    Windows/System32/sru/SRUDB.dat     network and resource usage per application
    Windows/Tasks/, System32/Tasks/    scheduled tasks
    the shadow copies, if the tool can

**Linux:**

    /var/log/** including rotated and gzipped, /var/log/journal/**
    /etc/passwd, shadow, group, sudoers, sudoers.d/**, ssh/**
    /home/*/.ssh/**, .*history, /root/ the same
    /etc/systemd/**, /etc/cron*, /var/spool/cron/**
    /var/lib/docker/containers/**/config.v2.json and *-json.log
    the package database

**Anywhere:** memory first if the machine is running, and the shadow copies or
snapshots if they exist.

Two asks that cost nothing and are usually forgotten: **the collector's own log
and manifest**, and **the time on the machine** compared with a reference —
because a clock that was wrong is discovered too late almost every time, and it
is one command at collection and an unanswerable question afterwards.

And ask for the **configuration as well as the logs**: the current state of the
scheduled tasks, the services, the firewall rules and the accounts is evidence
of what was changed.
