### Changed: README

The README says, in one line, that the prebuilt container images once published
on the container registry were withdrawn on 2026-10-06 and that images are
built from source (`images/README.md`).

### Added: --pack-tools-as-jobs, a pilot of pack tools that are not Pi tools

`swarm.sh start --pack-tools-as-jobs PACK[,PACK]` leaves the named packs' tools
out of Pi's tool schemas. `SWARM.md` gains a "Pack tools run as jobs" section
that lists each of them with its description and parameters, and a seat runs
one as `job_run(tool: NAME, args: {...})` in a worker VM of its pack's image,
sealed like any job. An argument the manifest refuses (a missing one, an
unknown one, one of the wrong type) is refused with the tool's parameters
named. The option is refused where a tool would be lost: in a host run, with
`--no-jobs`, for a pack the run does not carry or one that has no tool, and
for a pack that declares secrets (a job does not carry them); a resume keeps
the mode the run started in. A seat with no hub to take the job (a host run) keeps
the tools registered. The run record carries `pack_tools_as_jobs`. Without the
option nothing changes. The tools of no pack are named in the code.
