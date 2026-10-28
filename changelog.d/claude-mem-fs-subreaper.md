### Fixed: `mem_fs` ends what its engine left when a subreaper, not init, adopts it

The clean-up of the `mem_fs` engine ends the processes it listed below the engine and finds still there once the engine has stopped (they hold the engine's pipes for as long as they live). It took a listed pid whose parent was alive, not pid 1 and not listed for a pid reused since the listing, and left it alone. That held only where init adopts an orphan. Under a live subreaper that is not pid 1 (WSL's relay, a service manager, a container's init) the orphan is adopted by it, so on WSL 2 the program the engine left was never ended and held the engine's pipes until it ended by itself.

A listed process is now known by its pid and its start (the kernel's start time from `/proc/<pid>/stat`, or `ps`'s `lstart` where there is no `/proc`), and it is ended while it is still the process that was listed, whoever adopted it. A pid reused since the listing has a later start and is not signalled, nor is a process below the tool or beside it.

Pack memory-forensics. Tests: `tests/pack-memory-engine-descendants.test.ts` (a new case starts the tool below a subreaper).
