### Added: reverse-engineering declares the approved programs, pinned

`requires/` now declares, all optional and not redistributable: Ghidra's
headless analyzer (12.2, upstream zip, sha256 as the release publishes it) with
the Eclipse Temurin JDK 21.0.13+9 it needs; Detect It Easy's `diec` (3.21,
Debian 12 package, amd64 only because upstream builds no Linux arm64 package);
the .NET runtime 10.0.14 (the same pin as the Windows pack, declared here
because the `re` profile holds no Windows pack); qpdf and osslsigncode from
Debian 12 (the apt snapshot date pins them); LIEF 1.0.0 and msoffcrypto-tool
6.0.0 in `requires/python.lock`. FLOSS (flare-floss 3.2.0) and oletools
(0.60.2) are now pinned and hash-locked (`requires/locks/`), a wheel hash per
architecture where PyPI has one plus the sdist. The locks were resolved from
PyPI's metadata for CPython 3.11 on Linux glibc; nothing was installed or
downloaded to make them, so the first image build is their first install. No
skill or tool names the new entries yet; each is in `unreferenced_ok` with
the reason. The ILSpy command line (`ilspycmd`) is not declared yet: its
NuGet package needs its sha256 computed from the file.
