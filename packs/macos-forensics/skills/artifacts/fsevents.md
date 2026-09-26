---
id: artifacts/fsevents
title: FSEvents, the change log nobody turns off
when: A file was created, renamed or deleted and you need to prove it happened.
needs: [triage/system-profile]
tools: [fsevents_parse]
requires_host: []
---

`/.fseventsd/` on every volume holds a per-volume log of file system changes,
written by the operating system for Spotlight and backup software and kept
whether anyone wants it or not. It survives the file it describes.

    /.fseventsd/fseventsd-uuid    the volume's identity for this log
    /.fseventsd/0000000000abcdef  gzip-compressed record files, named by event id

`fsevents_parse` decompresses and reads them. Each record is a path, an event
id and a flag word saying what happened: created, removed, renamed, modified,
an inode-metadata change, whether it was a file or a directory, and whether it
was the last event known for that path.

**Event ids are a counter, not a clock.** They increase monotonically per
volume and there is no timestamp in the record at all. That makes FSEvents
excellent for *order* and useless for *time* on its own. To place it in a
timeline, anchor it: find an event whose path you can date from another
artefact, and every id before and after it is bracketed. That anchoring step is
what separates a usable FSEvents finding from a suggestive one.

**A rename flag does not identify both names.** FSEvents reports that an item at
a path was involved in a rename, but coalescing and implementation behaviour
mean you cannot assume a one-record old-path/new-path pairing. Correlate nearby
event ids, file-system metadata and other artefacts before claiming where an
item moved.

The log is not complete. Records are coalesced — many changes to one path
collapse into one record with the flags accumulated — and files roll off as the
volume fills. A path that is absent was not necessarily never touched.

An external volume carries its own `/.fseventsd/`. That can prove changes on the
volume and their order, but the log travels with the volume: by itself it does
not prove which Mac made the changes. Attribute a host only with a separate
machine-specific artefact such as a mount, device or unified-log record.
