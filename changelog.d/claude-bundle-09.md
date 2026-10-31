### Fixed: linux-forensics tools carry one marked text for paging, text files and the stop signal

auth_log, cron_dump, journal_export, shell_history and utmp_parse had five drifting copies of the paging and text code, and auth_log had no stop handling at all. The copies now sit between `# BEGIN LINUX PARTS` and `# END LINUX PARTS` (and the stop part and the disk-image block between their own markers), and a test walks the tools and holds each text byte-equal. auth_log, cron_dump, shell_history and utmp_parse install their stop handlers on the first line after the imports, so a SIGTERM, SIGINT or SIGHUP gives one JSON last word from then on; auth_log names its kept paging files and text file like the others. A paging file that cannot be written (a full disk) is kept under its name or removed, and the error says which; a text file that cannot be flushed in the last word no longer prints an error document before it. The text file is capped (256 MiB) like the paging files (128 MiB together): past it the records are counted in `not_written` and the answer is partial.

### Fixed: linux-forensics text-writing tools declare secret_output and check SECRET_OUTPUT

auth_log, cron_dump, journal_export, shell_history and utmp_parse now declare `secret_output` for their text flags (`write_text` and `preview_text`; `write_commands` and `preview_commands` for shell_history), so a job that sets one is sealed as secret output without the agent saying so, and each tool refuses such a flag as JSON, before it opens or creates anything, when `SECRET_OUTPUT` is not `1`. linux_triage does not declare it.

### Fixed: linux-forensics journal_export keeps journalctl's stderr in its file and tells its own journal by machine id

The answer gives the name, size and sha256 of journalctl's stderr file and no longer quotes its first lines (they can carry paths and entry text). A journal is this machine's own when the machine id in the header of its files is the one in `/etc/machine-id`, or the directory is named by it, wherever it is and however it is spelled; a path under `/var/log/journal` that carries another machine's id is no longer refused for its place. The place is used only where this machine's id cannot be read.

### Fixed: linux-forensics linux_triage refuses the analysis machine's root, holds out_dir to work/<agent>/ and counts on the clock

`source` is refused when it resolves to the root directory (`/`, `//`, `/..`, a link to it) or lies outside the run directory, before target-query is started. Outside a job, in a run directory, `out_dir` must resolve under `work/<agent id>/` (`work/ag/../../escape` and a link out are refused). The counting of each function's records and the hashing of the files it wrote read the clock and stop at the total deadline: what they did not do is listed in `not_hashed`, a stopped count is marked `records_counted_to_the_end: false`, and the run is partial.

### Fixed: linux-forensics cron_dump bounds its answer, names cronie's extensions and withholds odd keys

The entries cron_dump shows inline now stop at 1 MiB of JSON (`answer_budget`, `truncated`); the rest, and the ones shown, are whole in `pages.entries.all_results`, named with its size and sha256, and the status is unchanged (300 timers with long `OnCalendar` values made a 22.9 MB answer). The manifest and `persistence/cron-timers` say that cronie's `L`, `W`, `#` and `?` and a numeric user read as unparsed. A timer's unit key or section name that systemd does not define is withheld with its length (`key_withheld`, `section_withheld`) instead of printed cut at 128 characters, so a pasted token that stands where a key goes is not shown.

### Fixed: linux-forensics records name the version of the tool that made them

In all six linux tools `PARSER` (the `parser` of every record) lagged the manifest's version, so a record did not say which behaviour produced it. Each tool's `PARSER` now carries its manifest version and moves with it, and a test that walks the pack's tools holds the two equal.

### Changed: linux-forensics auth_log says how weak the year of a traditional syslog line is

The dating rule and the status are unchanged. Per file the answer now lists every forward step of more than 62 days between two consecutive lines in order (`forward_steps`, the first 20 inline and all of them in `pages.forward_steps`) and marks every traditional-stamp record before the last such step `year_assumed`; `year_anchor` names the line and the modification time that dated the file; `mtime_may_be_copy_time` says when that time may be the time of a copy (more than 7 days after the last dated line, one modification time shared by every file of a call, or a gzip header time that differs), with the gzip header time beside it. A new `years` argument gives a year per file and line range. The first pass keeps one byte per dated line instead of seventeen. `logs/auth-time` and `triage/system-profile` say to fix the year from a source with full dates, and linux_triage's `authentication` and `logs` families say how dissect.target 3.25 dates a traditional line.
