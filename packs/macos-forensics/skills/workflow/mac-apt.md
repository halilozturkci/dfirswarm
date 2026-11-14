---
id: workflow/mac-apt
title: Running mac_apt over a macOS acquisition
when: A macOS image or folder is to be parsed broadly with mac_apt, or a run of it is to be judged.
needs: []
card: macos_triage gives each plugin parsed, empty, unsupported or failed under plugins, from mac_apt's log; status_basis says why a run is not complete. parsed is not a record count, and mac_apt was never run here (not_observed): check a record against the raw artefact. Does not show: that a plugin read everything.
tools: [macos_triage]
requires_host: [mac_apt.py]
---

Use when `mac_apt.py` is to parse a macOS acquisition, or a run of it must be judged. Not for choosing one artefact to read (its own leaf) or establishing what was acquired (`triage/system-profile`).

**Is it here.** `mac_apt.py` is installed in the amd64 worker image only. On arm64 `macos_triage` answers `failed` and the `macos-artefacts` recipe's detect exits 1: that says nothing about the subject. Cite the version the tool reports from `mac_apt.py -h`. `mac_apt.py -h` should print its input modes and plugin names (not observed).

**Input mode.** Give `input_type` as the acquisition is: a folder for MOUNTED, a file for AFF4, AXIOMZIP, DD, DMG, E01, SPARSE, UAC, VMDK or VR. A mismatch and a link are refused before the program starts; for DD only a non-regular path is, and no signature is checked. A FileVault password goes only as `password_file`, a sealed 0600 file; there is no password argument.

**Plugins.** Name them (upper case; a trailing `-` excludes one). FAST and ALL expand to plugins nothing here lists, so such a run is at most `partial`. Presence shows no support for the subject's build; the log shows whether it finished.

**Judge the run by its log.** mac_apt exits 0 after errors it has logged, so `macos_triage` reads the log and gives each plugin `parsed`, `empty`, `unsupported` or `failed` under `plugins`, and `status_basis` says why a run is not `complete`. `parsed` is not a count of records. A child mac_apt leaves behind is ended before anything is measured, and the answer is `partial`. A cut log read, a line over 1 MiB, log lines not shaped time|logger|LEVEL|message (never observed) or an error word ending stdout or stderr also give `partial`. Keep stdout, stderr, the log and output files; no log line is in the answer.

**What was never observed.** mac_apt was never run here: the tool and the recipe were written from its source and tested with stand-ins (`not_observed` in the answer). The prefix of a log line, the wording behind `empty` and `unsupported` and the per-plugin file names are unverified, and a failure below ERROR level or without an error word can still read `parsed`. Check one record against the raw artefact (file, key, row) before a finding rests on a plugin. A negative from a plugin that read `parsed` is not yet a negative.

Shows: what the log says each plugin did, and the files mac_apt wrote. Does not show: that a plugin read everything, deleted or snapshot content, or a volume mac_apt could not open.
Record: the version, `input_type`, the plugins and each one's status, the log file, the exit code, the spot checks.
Sensitive output: the tool declares `secret_output` required; the recipe marks its files `secret_bearing`. The output holds keychain metadata, password hashes, browser data and user files. Cite file and row, never a value, fragment or hash.
