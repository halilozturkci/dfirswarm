---
id: ios/artifacts
title: iOS, and where each answer lives
when: The extraction came from an iPhone or an iPad.
needs: [extractions/what-you-have]
tools: [manifest_db, sqlite_freespace, plist_read, unified_log]
requires_host: [ileapp]
---

Paths below are as they appear in a full file-system extraction; in a backup,
resolve them through `Manifest.db` first.

    private/var/mobile/Library/SMS/sms.db              messages and attachments
    .../Library/CallHistoryDB/CallHistory.storedata    calls
    .../Library/AddressBook/AddressBook.sqlitedb       contacts
    .../Library/Safari/History.db                      browsing
    .../Library/Caches/com.apple.routined/Cache.sqlite significant locations
    .../Library/BiomeStreams/, .../Library/Biome       newer activity streams
    private/var/db/diagnostics/, .../uuidtext/          unified-log trace and strings
    private/var/Keychains/keychain-2.db                 keychain metadata and protected blobs
    private/var/mobile/Media/PhotoData/Photos.sqlite    photo-library metadata
    .../Library/Preferences/*.plist                    per-app settings
    private/var/mobile/Containers/Data/Application/<uuid>/   one app's sandbox
    private/var/mobile/Containers/Shared/AppGroup/<uuid>/    shared between apps
    private/var/installd/Library/MobileInstallation/   what is installed, and when

Start a broad pass with iLEAPP, writing to a new empty output directory:

    mkdir -p work/<agent>/ileapp
    ileapp -t tar -i /absolute/path/to/extraction.tar -o work/<agent>/ileapp

Use `-t fs` for an extracted directory. Keep iLEAPP's stdout and report tree:
the stdout names modules that found nothing, parser errors and records the
report UI can omit. A successful exit is not proof that every module parsed.

**Two epochs and you will meet both.** Apple absolute is seconds since
2001-01-01 UTC and is what most iOS databases store. Unix seconds appear in
anything with a Unix heritage. `timestamp_decode` in the base pack settles a
bare number; getting it wrong is a thirty-one-year error that still looks
plausible.

**The application UUID directories are meaningless names.** Map each one to its
bundle identifier through the `.com.apple.mobile_container_manager.metadata.plist`
inside it, or through `MobileInstallation`. Reporting evidence from
"Application/4F2C…" without that mapping is unciteable.

**`sms.db` keeps deleted messages** in its own free pages until it is vacuumed,
which iOS does rarely. `sqlite_freespace` recovers text from those pages. A row
recovered that way has no reliable timestamp and no guaranteed thread — say
which parts you recovered and which you inferred.

**Knowledge and Biome are activity records**, the same idea as macOS
`knowledgeC`, but they are not interchangeable formats. KnowledgeC is SQLite.
Biome streams use SEGB containers whose payloads may include protobuf. Do not
run `protobuf_peek` on a whole SEGB file and call the result a Biome record;
fetch `ios/biome-segb` and use the stream-specific iLEAPP parser.

The keychain database does not make secrets plaintext. Protection-class and
item metadata can be visible while data blobs remain wrapped by a class key.
Record the extraction state, keybag and unlock assumptions before interpreting
an empty or undecodable value.

For photos, query `Photos.sqlite` with its WAL and hash the media file it names.
Run `exiftool -json -n -- FILE` on that exact file; `-n` keeps coordinates and
other numeric values machine-readable. Treat EXIF as file metadata, not proof
that the device owner was at that position.
