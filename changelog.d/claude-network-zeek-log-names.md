### Fixed: zeek_run withholds a token-shaped log name

- A log file's name is chosen by the engine (Zeek's scripts and the policies the tool loads), and it was printed whole: as a key of `logs`, in `file`,
  in `malformed_files` and in `malformed-<name>.jsonl`, in the lists of logs. A name shaped like a token or user-info is now shown as `withheld-NNNNNN`
  everywhere, the log is renamed to that in the output directory, and the real name is kept in `zeek-log-names.jsonl` (mode 0600, named in the answer
  as `log_names_file`, written at the moment of the rename). Every other name is printed as Zeek wrote it; the manifest says both.
- A test with a stand-in engine that writes logs named after random token shapes holds it: no such name is in the answer or in a file name, the
  malformed file follows the shown name, and the index holds the real names.
- Packs: network-forensics (`zeek_run`).
