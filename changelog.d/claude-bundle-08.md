### Changed: memory-forensics, triage-collection, cloud-forensics

`avml`, `uac`, `velociraptor`, `pwsh` and `aws` are marked `not_in_image`, so the images no longer install them (OD-10): they are an operator's acquisition programs, run on the host to be collected or where the cloud credentials are. Their pinned downloads stay declared, so the operator still has the exact binary and checksum to take to the source. `python3 images/recipe.py build <profile>` lists them under `not_applicable` for memory, triage, cloud and full.

### Changed: network-forensics, mobile-forensics

`tcpick` and `idevicebackup2` are no longer declared. The network pack's `sessions/reconstruct` skill no longer names `tcpick`, and the mobile pack no longer keeps an `unreferenced_ok` entry for `idevicebackup2`.

### Added: images, network-forensics

A `requires/host.json` entry can name `facts`: commands about its program whose output the image build keeps under `/etc/dfirswarm/facts/`, with each file's sha256 and status in `image.json` and the files named in `tools.md`. A failing or hanging command is recorded as failed (it fails the build only for a required program); an over-long output is capped and said to be. The network pack's `tshark` entry records `tshark --version` and `tshark -G fields`.

### Added: pinned-download check

`.github/workflows/pins.yml` runs weekly (and by hand) `scripts/check-pins.ts`: a HEAD request for every URL a pack pins, and a fetch with the sha256 compared for a URL that names no version (Eric Zimmerman's `net/<tool>.zip`). It fails and names a pin that rotted, changed or did not answer. `images/README.md` says how to re-pin a download.
