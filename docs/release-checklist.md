# Open-source release checklist

Status as of 2026-09-17. Everything an engineer could do is done; the three
steps at the end are the maintainer's, in order.

## Done

| # | Item | Where |
| --- | --- | --- |
| 1 | License: GNU AGPL v3 or later, copyright Halil Öztürkci, 2026, with a commercial licence offered alongside it. The console and the server banner carry the section 13 source offer | `LICENSE`, `NOTICE`, `COMMERCIAL-LICENSE.md`, `package.json` `license`, README § License, `ui/src/components/app-shell.tsx`, `scripts/ui-server.ts` |
| 2 | Name: **Agent Swarm** everywhere (was "Simple Swarm" during development) | `package.json`, `ui/index.html`, the wordmark, the server's placeholder page, `extensions/agent-swarm.ts` (renamed), every doc |
| 3 | Security policy: threat model, scope, reporting, operator hardening | `SECURITY.md` |
| 4 | CI: typecheck, the node suites, every shell suite (`scripts/test-bash.sh`), UI build, a guard that no run state is tracked — no model, key, Herdr or Pi needed; and on a KVM runner the VM suite, with the base and disk images built from the recipes. `images.yml` builds every profile, `full` included. Every job but one runs on amd64 Linux; one job, in four parts (two of node suites, with the typecheck in the first, and two of shell suites), runs the typecheck, the node suites and the shell suites on a hosted macOS runner (Apple silicon). No arm64 image is built or booted, and `spikes/` is neither typechecked nor re-run (see below) | `.github/workflows/ci.yml`, `.github/workflows/images.yml` |
| 5 | Contributing guide with the house rules (tests in `tests/`, bash 3.2, English only, harness owns its files) | `CONTRIBUTING.md` |
| 6 | Code of conduct: Contributor Covenant 2.1 | `CODE_OF_CONDUCT.md` |
| 7 | Issue and PR templates, Dependabot for npm and Actions | `.github/` |
| 8 | `package.json` metadata: name, version 0.3.0, description, license, author, repository, bugs, homepage, keywords; stays `private` (a CLI + web app, not a library) | `package.json` |
| 9 | README is a landing page: why, a feature tour where each screenshot is a published forensic run, a quick start, what the harness enforces, a documentation table; everything else lives in `docs/` | `README.md`, `docs/quick-start.md`, `docs/architecture.md`, `docs/safety.md`, `docs/observability.md`, `docs/why-the-incident-inverted.md`, `docs/screenshots.md`, `docs/roadmap.md`, `docs/protocol.md`, `docs/usage.md`, `docs/component-map.md`, `docs/verified-runs.md`, `docs/troubleshooting.md` |
| 10 | English only: the one Turkish document translated; the worker prompt asks agents to post in English; screenshots recaptured from English runs | `docs/feature-evidence.md`, `prompts/worker-system.md`, `docs/screenshots/` |
| 11 | Screenshots captured with Playwright from real runs: the README and the gallery use the forensic series, and every image links to the case whose board and report are in the repository | `docs/screenshots.md`, `docs/use-cases/*/screenshots/`, `docs/screenshots/` |
| 12 | Changelog from the commit history | `CHANGELOG.md` |
| 13 | Node pin | `.nvmrc` (22) |
| 14 | A finished swarm's netguard sidecar is stopped by the last agent to leave | `stopNetguardSidecarIfOver` in `extensions/protocol.ts` |
| 15 | GitHub description and topics | repository settings |
| 16 | No secrets and no run state in tracked files: grepped for API-key and token shapes and for private-key blocks, in the working tree and across the whole history. The one private-key hit is a forensic finding in a report table, not key material | — |
| 17 | The maintainer's home path appears 2,594 times in published run artifacts, all of it `~/DFIR/SampleCases` and `~/Library/Python` in verbatim pane captures and custody sections. Reviewed and kept: the username is already the GitHub handle, nothing else is disclosed, and rewriting a terminal capture would cost it the thing it is published for | `docs/use-cases/*/run/panes/`, `docs/use-cases/*/run/summary.md` |
| 18 | Contributor agreement, referenced from the contributing guide and ticked in the pull-request template | `CLA.md`, `CONTRIBUTING.md`, `.github/PULL_REQUEST_TEMPLATE.md` |
| 19 | Trademark policy: what the Apache licence deliberately does not grant, and what a fork may call itself | `TRADEMARK.md`, README § License |
| 20 | Every relative link in every Markdown file resolves (259 files, 0 broken) | — |
| 21 | Issue chooser routes a vulnerability to the security policy instead of a public issue | `.github/ISSUE_TEMPLATE/config.yml` |

## Not done, on purpose

| Item | Why |
| --- | --- |
| A hosted demo | Impossible by design: a run needs Herdr panes and a paid or subscribed model. A screen recording linked from the README would be the substitute. |
| Publishing to npm | It is a CLI and a web app you clone; `private: true` stays. |
| macOS `pf` enforcement for netguard | Still **UNKNOWN**; the proxy mode is what is verified on macOS. Listed in the README roadmap. |
| CI on arm64 images and the macOS VM path | The macOS job runs the typecheck, the node suites and every shell suite (the seatbelt guard, `--inputs-image`) on a hosted runner, but a hosted runner cannot boot a microVM. The Apple-silicon VM path and the arm64 image builds (their pinned downloads and compiled tools) are run by hand on the development Mac before a release. |
| Typechecking or re-running `spikes/` | The spikes record measurements taken once (the shared-directory losses, the five-second cache); they are outside `tsconfig.json` and CI. A new msb version is the time to re-run `spikes/microvm-smoke/shared-fs.sh` by hand. |

## The maintainer's own steps

These are the ones no contributor can do. In order.

1. ~~**Make CI able to run.**~~ Done 2026-09-20: GitHub Actions was blocked
   by the account's billing until then, and the workflows run now.
2. **Enable private vulnerability reporting the moment the repository is
   public.** It cannot be switched on while the repository is private, and
   `SECURITY.md` names it first. The published fallback is
   halil@halilozturkci.com, which is now a real address in a public file and
   will be scraped; a filter for it is worth setting up before the flip.
3. **Register the name.** [TRADEMARK.md](../TRADEMARK.md) claims "DFIR Swarm"
   as an unregistered mark, which is worth something and worth less than a
   registration. Section 6 of the Apache licence is what makes the name the
   part worth protecting.
4. **Have a lawyer read `CLA.md`.** It is a working document, not reviewed
   advice, and it is the instrument that decides whether this project can ever
   change its own licence.
5. **Decide the version.** `package.json` says 0.3.0 and the changelog's
   `[Unreleased]` section has held every change since. Nothing was ever tagged
   or released, so the first public tag can be 0.3.0 or a new minor; pick one,
   cut the changelog section to match
   (`node --experimental-strip-types scripts/changelog.ts --fold --release X.Y.Z`
   folds the `changelog.d/` fragments in, newest first, and cuts it), then
   `git tag -a vX.Y.Z && git push origin vX.Y.Z` and a GitHub release with
   that section as its body.
6. **Flip the repository to public** (Settings → General → Danger Zone →
   Change visibility), then immediately enable **private vulnerability
   reporting** (Settings → Security) and set the description and topics.

Optional afterwards: a 60-second recording of `swarm.sh start` → the console → the sentinel; a pinned issue for "first run help"; the `pi`/`herdr` versions tested, kept current in the quick start.
