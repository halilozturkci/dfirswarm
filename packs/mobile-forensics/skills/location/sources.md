---
id: location/sources
title: Where a phone says it was
when: The question is where the device was, and when.
needs: [apps/databases]
tools: [sqlite_query, protobuf_peek, timestamp_decode]
requires_host: []
---

A phone carries several independent location records and they are not equally
good. Use more than one, and say which you used.

    iOS  Cache.sqlite in com.apple.routined      significant locations, with a
                                                 confidence and a source
         Photos.sqlite, and EXIF in the files    where a photo was taken
         Health, where the user had it on        movement, not coordinates
    Android  usagestats and cached network data  coarse, from cell and wifi
         Photos and their EXIF                   the same as iOS
         App-specific: maps, ride hailing, fitness

**Every one of these is a claim by software, not an observation.** A "location"
is a fix the operating system computed from GPS, wifi or cell, each with a very
different accuracy, and the record usually carries which — read that field and
quote it. A 3-kilometre cell fix reported as a location puts somebody somewhere
they were not.

**The horizontal accuracy field is part of the finding.** "At 09:14 the device
recorded a position at X with a horizontal accuracy of 65 metres" is a
defensible sentence. "The device was at X" is not.

**Photo EXIF is the strongest of these** because it is tied to an object with
its own timestamps and its own hash — but it is also the easiest to fake, and a
photo received in a message carries the sender's coordinates, not the holder's.
Check where the file came from before you use it.

Use `Photos.sqlite` with its WAL to map the library record to the exact media
file, then run `exiftool -json -n -- FILE`. Compare EXIF GPS time, filesystem
times and the Photos database record; preserve disagreements rather than
choosing the convenient timestamp.

**A wifi network name is location evidence too**, and often better than a fix:
a phone that joined a named network was within its range, and the network's
location can be established independently.

Two absences worth stating: location services can be off per app or entirely,
and a device in airplane mode still records what its GPS sees. Neither absence
means the phone was not there.
