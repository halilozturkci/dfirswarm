# Feature evidence (goal audit)

Per-feature evidence from the first live runs, on DeepSeek V4 Pro with API
keys held in the shell (never written to a file). The screenshots this audit
referred to (`media/*.png`) were working files and are not in the repository;
the console screenshots that are kept live under `docs/screenshots/` and are
described in [ui-coverage.md](ui-coverage.md).

The lines quoted below are historical: they show the paths and fields of the
run they came from (a screenshot under `work/.browser/`, for instance, is now
under `work/<agent>/.browser/`).

| # | What | Command | Evidence | Status |
| --- | --- | --- | --- | --- |
| 1 | Event log | `SWARM_SANDBOX=sandbox-runs/s9091 scripts/watch.sh --once`; probe: `start … --probe-violation` | `s9091/traces/events.jsonl`, 38 lines: `post` `inbox` `claim_file` `release_file` `done` `playwright`. `sfd9e` `2026-09-16T08:26:43.891Z` `sfd9epv` `claim_violation` `blocked=true` `work/hello.txt (no lock)`. | **proven** |
| 2 | Real budget | `jq '{spent_usd,tokens,calls}' sandbox-runs/s9091/budget.json` | `s9091`: `spent_usd=0.061282` `tokens=243160` `calls=34`. `sbeef` N=30: `$0.724719` / 1,989,624 tok / 244 calls. Source: `pi.sessionManager.getEntries`. jsonl `tool:"budget"`. | **proven** |
| 3 | Kickoff UX | `scripts/swarm.sh start --model deepseek/deepseek-v4-pro --cap-usd 3 --n 2 --goal "…"`; `list`; `status`; `stop` | Consecutive ids: `sbeef` `s0e5a` `s70a4` `s9091`. No `agent_name_taken`. `stop s9091` closed workspace `wH`. | **proven** |
| 4 | LAN UI | `scripts/swarm.sh ui --port 43173`; `curl http://172.30.0.2:43173/api/health` | Bound `0.0.0.0:43173` (`/proc/net/tcp` `00000000:A8A5`). curl from the container IP: `{"ok":true,"runs_dir":"/workspace/sandbox-runs"}`. One screen (`sd169`): ≥2 swarms, `main` **dim**, `?` + **✓ done**, raw trace. | **proven** |
| 5 | File history | Live N=2 `s9091`: `work/notes.md` v1→v2 → `file_history` → `file_restore` rev 1 (claim held) | `09:14:26Z` `file_history` `path=work/notes.md` `n=3`. `09:14:29Z` `file_restore` `rev=1` `ok=true`. On disk: `notes.md` = `v1`. `history/` 4 revisions (`s909100`). Restore without a claim is refused: `tests/dry-run.test.ts`. | **proven** |
| 6 | Reaping | Live N=3 `start --n 3 --cap-usd 1`; SIGSTOP `sd16901` after its claim; `scripts/swarm.sh reap sd169 --stall-sec 20`. Fixture: `reap s0e5a --stall-sec 1` | Live `rplive`/`sd169`: `done/agents/sd16901.dead` `locks_released=2` `idle_seconds=37`; jsonl `tool:"reap"` `reaped=true`. The remaining agents reached `SWARM_DONE` (`hello.txt`+`summary.md`, 3 ids). UI: `sd16901` `marker=dead` → **?**. | **proven** |
| 7 | Playwright | `start … --playwright`; agent calls `playwright` (`work/index.html`) | `09:14:40.396Z` `s909100` `tool:"playwright"` `target=work/index.html` `title=swarm-ok` `screenshot=work/.browser/20260916T091440317Z-s909100.png`. | **proven** |
| 8 | N=10–30 and concurrency | `start --n 10` / `--n 30`; a second `start --n 2` alongside | N=10 `s7e50` `SWARM_DONE` yes, ~73 s, `$0.190515`. N=30 `sbeef` **yes**, 128 s, `$0.724719`, 30 posts, 40 conflicts, 0 dead; Herdr 30 panes / 1 tab (`tabs=1` `split_failures=0`). Concurrent: `s8218` N=2 + `s7e50` N=10, `list` shows both `running`. | **proven** |
| 9 | Netguard (default) | `start` (no flag); agent runs `bash` `curl https://example.com/` | `s9091` Net: `netguard.sh default`. Log: `ALLOW api.deepseek.com:443` + `DENY example.com:443`. Post: curl HTTP `000`, `CONNECT tunnel failed, response 403`. `SWARM_DONE` still reached. `--no-netguard` opts out. | **proven** |
| R | README | README "Goal-audit proofs" | 9 items, each with the command behind its evidence. | **proven** |

## 1. N=30 (`sbeef`)

| Field | Value |
| --- | --- |
| SWARM_DONE | **yes** (`complete`) |
| Wall | 128 s (`2026-09-16T08:47:59Z` → `08:50:07Z`) |
| Spend | $0.724719 / 1,989,624 tok / 244 calls (cap $3) |
| Posts | 30 |
| Conflicts | 40 `claim_file` |
| Dead | 0 |
| Herdr | 30 panes, 1 tab `wF`, `split_failures=0`, `extra_workspaces=0` — no pane ceiling reached |

## 2. Netguard by default, agent `bash` denied (`s9091`)

Spawn line: `Net: netguard.sh default (proxy http://127.0.0.1:43178; PATH wrap …/s9091/bin/pi)` (the sidecar port is now allocated per swarm from 43178 up).

```
ALLOW connect api.deepseek.com:443
DENY  connect example.com:443
```

The agent (`threads/main/000006-s909100.md`): `curl https://example.com/` → HTTP `000`, `CONNECT tunnel failed, response 403`. The swarm still reached `SWARM_DONE` in ~110 s for $0.061.

**Caveat:** `NODE_USE_ENV_PROXY=1` needs Node ≥ 22.21 (22.22.2 here, honoured). Older Node ignores the proxy for `fetch`; **netns** mode still fails closed. Bun uses `HTTPS_PROXY` natively. Docker's default **seccomp** blocks `unshare` → `netguard.sh` falls back to `--mode proxy-only` with a WARNING. macOS `pf` enforcement is **UNKNOWN**.

## 3. Live `playwright` (`s9091`)

```
{"ts":"2026-09-16T09:14:40.396Z","agent":"s909100","tool":"playwright",
 "args":{"target":"work/index.html","screenshot":true},
 "result":{"ok":true,"title":"swarm-ok",
           "screenshot":"work/.browser/20260916T091440317Z-s909100.png"}}
```

## 4. Live `file_history` / `file_restore` (`work/notes.md`)

```
file_history  path=work/notes.md  n=3
file_restore  path=work/notes.md  rev=1  ok=true
```

On disk `notes.md` = `v1`.

## 5. UI `?` and dark threads

- `sd169`: ≥2 swarms, `main` dim (orange bar), `sd16901` **?**, `sd16900`/`sd16902` **✓ done**, raw traces.
- `s0e5a`: agents `?` / dead; `main` idle-dim; `ops` hold-dim.
- Live N=3 at the moment of the reap: `sd16901` **?** / dead, `sd16902` ✓ done.
- `curl http://172.30.0.2:43173/api/health` → ok.

## 6. Live reap (`sd169` / `rplive`)

| Field | Value |
| --- | --- |
| Model / cap | `deepseek/deepseek-v4-pro` / `$1` |
| N | 3 (`sd16900` `sd16901` `sd16902`) |
| Freeze | SIGSTOP `sd16901` at `2026-09-16T09:24:27Z` while holding `work/hello.txt` + `work/summary.md` |
| Reap | `scripts/swarm.sh reap sd169 --stall-sec 20` at `09:25:04Z` |
| `.dead` | `done/agents/sd16901.dead` |
| `locks_released` | **2** |
| Event | `{"ts":"2026-09-16T09:25:04Z","agent":"sd16901","tool":"reap","args":{"timeout_seconds":20,"reason":"stall"},"result":{"reaped":true,"idle_seconds":37,"last_activity":"2026-09-16T09:24:27Z","locks_released":2}}` |
| UI `?` | `/api/swarms/sd169` `marker=dead` |
| SWARM_DONE | **yes** (`done`) at `09:26:57Z` — `sd16902` wrote both artifacts (all 3 ids) then called `done` |
| Spend | `$0.053274` / 185,768 tok / 32 calls |
| Wall | ~170 s (`09:24:07Z` → `09:26:57Z`) |

The fixture `s0e5a` (`--no-start` plus a backdated lock) and the `rplive00` pane close were earlier, provisional evidence; this row is the live N=3 run.

## UNKNOWN / partial

Nothing partial: every row is **proven**. What no evidence settled (the hard-kill default, the thread idle threshold, macOS `pf`, a Herdr pane ceiling) stayed speculative and is marked as such in the code.
