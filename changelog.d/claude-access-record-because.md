### Added: a sensitive job records why it is sensitive, and a job that names one runs and says so

A job made from a sensitive output now says why, and a job that declared no scope and names a sensitive job's output is no longer only held sensitive in silence. Nothing is refused or hidden: this records data the agents could already reach.

- **`job_committed.sensitive.because`** lists, for a derived job, each sensitive job it came from and the way: `declared` (a file of that job in its scope), `digest` (bytes with that job's digest, wherever they sat), `generation`, `alias`, `named_in_text` (no scope, and its command, arguments, source or targets name the job) or `same_bytes` (a file it sealed is byte for byte one that job wrote), with the path that matched. A job id and a path, never a value or a digest.
- **`job_started`** records, for a job with no declared scope, `scope.auto_declared` (the sensitive jobs its text names) and `scope.could_read_sensitive` (the sensitive jobs sealed when it started, which its mounts let it read), and `sensitive_at_start` when it is already derived. The job runs as before.
- **`similar` entries** carry `sensitive: true` when the other job's outputs are sensitive.

`docs/protocol.md` describes the fields; `tests/job-sensitive-because.test.ts` holds the cases.
