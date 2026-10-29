### Changed: Pi 1.4.0

`@earendil-works/pi-coding-agent` goes from 0.87.1 to 1.4.0, in `package.json` and in the base image (`images/base.Dockerfile`). What it changes here:

- Pi 1.0.3 renamed its Azure provider from `azure-openai-responses` to `azure` (the `AZURE_OPENAI_*` variables are unchanged; the API it speaks is still `azure-openai-responses`). The kickoff's key and host lookups, the console's, the tests and `docs/credentials-and-teams.md` now use `azure/<model>`; the API names stay. An operator whose `~/.pi/agent/auth.json` holds the old key renames it or runs `/login` again, as Pi's own note says.
- Pi 1.2.0 fires `before_agent_start` also for runs an extension starts with `pi.sendMessage(..., { triggerTurn: true })`, so the self-compaction hand-off's run now carries the swarm's system prompt like any other.
