### Changed: memory-forensics, triage-collection, cloud-forensics

`avml`, `uac`, `velociraptor`, `pwsh` and `aws` are marked `not_in_image`, so the images no longer install them (OD-10): they are an operator's acquisition programs, run on the host to be collected or where the cloud credentials are. Their pinned downloads stay declared, so the operator still has the exact binary and checksum to take to the source. `python3 images/recipe.py build <profile>` lists them under `not_applicable` for memory, triage, cloud and full.

### Changed: network-forensics, mobile-forensics

`tcpick` and `idevicebackup2` are no longer declared. The network pack's `sessions/reconstruct` skill no longer names `tcpick`, and the mobile pack no longer keeps an `unreferenced_ok` entry for `idevicebackup2`.
