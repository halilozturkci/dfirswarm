# Skills in this pack

Fetch a body with `skill("<id>")`. A body may name others; fetch those the same way.

- `android/artifacts` Android artefacts by build, user and protection state: Use when the evidence holds Android application or system data. Not for an adb backup's layout (extractions/backup-detail) or location questions.
- `apps/databases` App databases, transaction state and deleted fragments: Use when an answer rests on an application's SQLite records or on possibly deleted content. Not for the meaning of one app's tables.
- `apps/fragments` Reading a sqlite_freespace answer: Use only if you ran sqlite_freespace and must report what its fragments are. Not for choosing whether to run it.
- `extractions/backup-detail` iOS backups and Android .ab files: what the tools read and do not: Use only if the evidence is an iOS backup directory or an Android adb backup. Not for a file-system extraction.
- `extractions/what-you-have` Mobile extraction scope, protection state and authority: Start here for any phone evidence. Use when the evidence is a phone, a backup or an app export and you have not yet said what it can answer. Not for parsing artefacts.
- `ios/artifacts` iOS artefacts by build, acquisition and application: Use when the evidence holds iPhone or iPad application or system data. Not for one stream's detail (ios/biome-segb, ios/unified-logs) or for where the device was (location/sources).
- `ios/biome-segb` Biome and SEGB records by format and stream: Use when an activity question depends on an iOS Biome or other SEGB stream. Not for KnowledgeC or unified logs.
- `ios/containers-and-time` iOS containers, bundle identity and time conversion: Use only if you must attribute an app container to an application or convert an iOS time value. Not for choosing sources.
- `ios/unified-logs` iOS unified logs on Linux with explicit coverage: Use when an iOS question depends on retained diagnostic or operational logs. Not for app databases.
- `location/sources` Mobile location records, provenance and uncertainty: Use when a question asks where a device, a media item or a person was. Not for the meaning of an app's tables.
