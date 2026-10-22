### Added: the hub records which seat reached a sensitive output

A seat can read any sensitive output of its run, and now the trace says who did. Every trace row a seat sends passes the hub; when the row's tool call names a sensitive job's output, the hub adds a `sensitive_access` line of its own after it. Nothing is blocked, held back or changed for the seat.

- **What is noted.** A `read`, `grep`, `find` or `ls` given a path in a sensitive job's `out/`, logs, blob, catalogue generation or alias; a `bash` or `powershell` command that holds such a path, a job id, or a whole output the harness kept under `tool-output/` from an earlier access; a command or search that walks a root or a glob over the jobs (a `maybe`, with the sensitive jobs it could reach); and a page of a sensitive job's stdout, or the tail of its stderr, that a status answer returns.
- **What a line says.** The seat, the time, the job, the part and the paths, how the harness came to see it (`path`, `text`, `api_page`) and how sure it is (`certain`, `path`, `text`, `maybe`), and the row it was made from. Never the value, a digest or a range of its bytes; a blob is named by its part.
- **Bounds.** A row sent again is noted once, also after the hub is brought back; a seat and a job have at most 200 lines, then one that says the rest are on the trace as the rows they come from. The record is a lower bound: a path a program computes, a copy that was not a kept output, or a program that opens a file by a name the command does not hold are not seen.

`docs/protocol.md` has the line's shape; `tests/hub-sensitive-access.test.ts` holds the cases.
