---
id: artifacts/knowledgec
title: KnowledgeC and the activity databases
when: You must say what a person was doing, and when, rather than what exists on disk.
needs: [artifacts/plists]
tools: [knowledgec_query, timestamp_decode]
requires_host: []
---

macOS keeps a usage database for its own features and it is the closest thing
the platform has to a record of a person's day.

    ~/Library/Application Support/Knowledge/knowledgeC.db     per user
    /private/var/db/CoreDuet/Knowledge/knowledgeC.db          system-wide
    ~/Library/Biome/…                                        newer, protobuf streams

`knowledgec_query` reads the SQLite file, joins `ZOBJECT` to `ZSTRUCTUREDMETADATA`
and `ZSOURCE`, and converts the times. The streams worth knowing:

    /app/inFocus         which application was in the foreground, and for how long
    /app/usage           application use, with the bundle id
    /display/isBacklit   the screen on and off, which is a proxy for presence
    /device/isLocked     locked and unlocked
    /safari/history      browsing, even where the Safari database was cleared
    /app/webUsage        per-application web use, with a domain

**Every time in it is Apple absolute**: seconds since 2001-01-01 UTC. A tool
that reads them as Unix time reports 1970 and looks broken; a tool that adds the
wrong constant reports a plausible wrong date and does not. The conversion is
`value + 978307200` for Unix seconds, and `knowledgec_query` does it for you.

**`/app/inFocus` with `/display/isBacklit` is the strongest presence evidence on
the platform.** The screen was on, this application was in front, for this
many seconds. Three of those in a row is a person at the keyboard in a way that
a file timestamp never is.

Two cautions. Retention varies by OS version and device state, so measure the
earliest and latest rows actually present before treating absence as meaningful.
And it records the machine's activity, not a named human: tie it to a session
from the unified log or a login before you put a name on it.
