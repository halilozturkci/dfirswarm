### Fixed: the Windows pack's Eric Zimmerman downloads follow the publisher's move to .NET 10

- Eric Zimmerman's download site dropped its `net9/` directory on 25 October 2026 and now
  serves the .NET builds from `net/`, built for .NET 10; the pinned `net9/` addresses answered 404
  and the weekly `image boot` build of the full and disk images failed on MFTECmd, EvtxECmd and
  RECmd. The windows-forensics pack now pins the `net/` zips (MFTECmd 2026.10.6, EvtxECmd
  2026.10.2, RECmd 2026.10.2) with their new SHA-256 values, and the .NET runtime they run on moves
  from 9.0.20 to 10.0.14 (both architectures, checked against the publisher's own SHA-512).
