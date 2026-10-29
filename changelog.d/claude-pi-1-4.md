### Changed: Pi 1.4.0

`@earendil-works/pi-coding-agent` goes from 0.87.1 to 1.4.0, in `package.json` and in the base image (`images/base.Dockerfile`). What it changes here:

- Pi 1.0.3 renamed its Azure provider from `azure-openai-responses` to `azure` (the `AZURE_OPENAI_*` variables are unchanged; the API it speaks is still `azure-openai-responses`). The kickoff's key and host lookups, the console's, the tests and `docs/credentials-and-teams.md` now use `azure/<model>`; the API names stay. An operator whose `~/.pi/agent/auth.json` holds the old key renames it or runs `/login` again, as Pi's own note says.
- Pi 1.0.1 ships no shrinkwrap, so npm puts `pi-ai` beside `pi-coding-agent`, and Pi 1.4 keys its catalogue `<type>:<id>` with image and classifier models beside the chat ones. `scripts/provider-hosts.mjs` finds the catalogue in either place, and the model gateway counts chat models only (it had declined to front `openai` and `openrouter`).
- Pi 1.2.0 fires `before_agent_start` also for runs an extension starts, so the self-compaction hand-off's run now carries the swarm's system prompt like any other, without the inputs guard the pane measured for its first run.

### Added: Cursor's models through Pi

`extensions/cursor-provider.ts` registers a provider, `cursor`, that serves a Cursor account's models to Pi through Cursor's own CLI, `cursor-agent`, run headless as the model only: Pi keeps the loop and the tools. The CLI's own tools are refused by a deny-all permissions file in a workspace of each chat's own, Pi's tools are offered as `pi__<tool>` in a text protocol the extension parses, a chat is resumed with only what is new, and each call's process group is ended with it (the CLI leaves a node process and a language server behind). `docs/credentials-and-teams.md` says what was measured and what it does not hold: usage is the CLI's token count, the cost is zero. `tests/cursor-provider.test.ts` runs it against a stand-in CLI; it was also run in Pi against the real one with DeepSeek V4.1 Flash, Grok 4.7 and Kimi K3. The kickoff does not start Cursor seats yet.
