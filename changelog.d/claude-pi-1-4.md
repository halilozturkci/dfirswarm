### Changed: Pi 1.4.0

`@earendil-works/pi-coding-agent` goes from 0.87.1 to 1.4.0, in `package.json` and in the base image (`images/base.Dockerfile`). What it changes here:

- Pi 1.0.3 renamed its Azure provider from `azure-openai-responses` to `azure` (the `AZURE_OPENAI_*` variables are unchanged; the API it speaks is still `azure-openai-responses`). The kickoff's key and host lookups, the console's, the tests and `docs/credentials-and-teams.md` now use `azure/<model>`; the API names stay. An operator whose `~/.pi/agent/auth.json` holds the old key renames it or runs `/login` again, as Pi's own note says.
- Pi 1.0.1 ships no shrinkwrap, so npm puts `pi-ai` beside `pi-coding-agent`, and Pi 1.4 keys its catalogue `<type>:<id>` with image and classifier models beside the chat ones. `scripts/provider-hosts.mjs` finds the catalogue in either place, and the model gateway counts chat models only (it had declined to front `openai` and `openrouter`).
- Pi 1.2.0 fires `before_agent_start` also for runs an extension starts, so the self-compaction hand-off's run now carries the swarm's system prompt like any other, without the inputs guard the pane measured for its first run.
- Pi 1.4 keeps a "Sign in with ChatGPT" login under `openai` (beside `openai-codex`), with a token of about an hour refreshed at `auth.openai.com`: the host allow-list opens that host for an `openai` OAuth login, and the record calls it a consumer plan.
