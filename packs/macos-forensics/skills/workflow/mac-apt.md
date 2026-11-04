---
id: workflow/mac-apt
title: Running mac_apt over a macOS acquisition
when: A macOS image or folder is to be parsed broadly with mac_apt, or a run of it is to be judged.
needs: []
tools: [macos_triage]
requires_host: [mac_apt.py]
---

Use when `mac_apt.py` is to parse a macOS acquisition, or a run of it must be judged. Not for choosing one artefact to read (its own leaf) or for establishing what was acquired (`triage/system-profile`).

**Is it here.** `mac_apt.py` is installed in the amd64 worker image only. On arm64 `macos_triage` answers `failed` with the packaging reason and the `macos-artefacts` recipe's detect exits 1: that says nothing about the subject. Check the tool inventory first. The tool runs `mac_apt.py -h` and reports the version it found; cite that version. `mac_apt.py -h` prints its input modes and plugin names.

**Input mode.** Give `input_type` as the acquisition is: a folder for MOUNTED, a file for AFF4, AXIOMZIP, DD, DMG, E01, SPARSE, UAC, VMDK or VR. A mismatch, and a link, are refused before the program starts. A FileVault password goes only as `password_file`, a sealed 0600 file; there is no password argument.

**Plugins.** Name them (upper case; a trailing `-` excludes one). FAST and ALL expand to plugins nothing here lists, so such a run is at most `partial`. Presence shows neither support for the subject's macOS build nor that a plugin finished; its log does. Keep each plugin's log.

**Judge the run by its log.** mac_apt exits 0 after errors it has logged, so `macos_triage` reads the log and gives each plugin `parsed`, `empty`, `unsupported` or `failed` under `plugins`, and `status_basis` says why a run is not `complete`. `parsed` is not a count of records. Keep the whole stdout, stderr, log and output files the answer names; no log line is copied into the answer.

**What was never observed.** mac_apt was never run here: the tool and the recipe were written from its source and tested with stand-in programs (`not_observed` in the answer). The prefix of a log line, the wording behind `empty` and `unsupported` and the per-plugin file names are unverified, and a failure logged below ERROR level, or without an error word, can still read `parsed`. Before a finding rests on a plugin, check one record against the raw artefact (file, key, row). A negative from a plugin that read `parsed` is not yet a negative.

Shows: what the log says each plugin did, and the files mac_apt wrote. Does not show: that a plugin read everything it could, a record count, deleted or snapshot content, or the contents of a volume mac_apt could not open.
Record: the version, `input_type`, the plugin list, each plugin's status, the log file, the exit code, and the spot checks with what each compared.
Sensitive output: the tool declares `secret_output` required, so every job of it is a secret job; the recipe marks its files `secret_bearing`. The output holds keychain metadata, password-hash plists, browser data and user files. Cite file and row, never a value, a fragment or a hash.
