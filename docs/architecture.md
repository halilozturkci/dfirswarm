# Architecture

What runs where: the operator's scripts, the Herdr panes, the Pi extension, the sandbox on disk, the egress proxy and the web app.

Every agent runs in its own microVM unless the run says `--isolation host`.
The first diagram is a host run (unisolated: every agent a Pi process on
this machine); [With a microVM per agent](#with-a-microvm-per-agent---isolation-microvm)
is the default, and changes only where Pi runs and who writes the board.


```mermaid
flowchart TB
  subgraph OP["Operator"]
    CLI["scripts/swarm.sh<br/>start · list · status · stop · reap · netcheck · ui"]
    TAIL["scripts/watch.sh<br/>scripts/await-done.sh"]
    BROWSER["A browser on this machine (the LAN with --host 0.0.0.0)"]
  end

  subgraph HERDR["Herdr workspace (one pane per agent, √N grid, tab/workspace spill)"]
    P0["pane · AGENT_ID=s1a2b00<br/>pi -e agent-swarm.ts"]
    P1["pane · AGENT_ID=s1a2b01<br/>pi -e agent-swarm.ts"]
    PN["… up to N=30"]
  end

  subgraph EXT["Pi extension (extensions/)"]
    TOOLS["agent-swarm.ts tools<br/>post · inbox · wait · list_team · budget<br/>claim_file · release_file · claims<br/>thread_open · thread_join<br/>file_history · file_diff · file_restore · done"]
    GUARD["write guard<br/>tool_call hook blocks edit/write<br/>bash bracketed by a hash snapshot"]
    USAGE["turn_end → sessionManager.getEntries()<br/>→ budget.json, cap + wall steer, harness stop"]
    SYS["system posts<br/>violations · caps · sentinel"]
    PW["playwright-tool.ts<br/>(only with --playwright)"]
  end

  subgraph FS["runs/ID/ · isolated cwd · the contract"]
    SWARMMD["SWARM.md · team.json · budget.json<br/>(harness-owned: agents never write these)"]
    THREADS["threads/main/000001-s1a2b00.md …<br/>threads/NAME/meta.json · inbox/ID/cursors.json"]
    LOCKS["locks/sha256.json · locks/.table.lock"]
    WORK["work/ (artifacts) · history/hash/000001.bin"]
    DONE["done/SWARM_DONE · done/agents/ID.done|.dead"]
    EVENTS["traces/events.jsonl · layout.json · netguard.log"]
  end

  subgraph NET["Egress"]
    NG["scripts/netguard.sh sidecar<br/>allowlisting CONNECT proxy 127.0.0.1:&lt;port&gt; (one per swarm, from 43178 up)<br/>+ PATH shim sandbox/bin/pi"]
    PROVIDER["Provider API hosts<br/>(4 defaults + the selected model's)"]
    DENY["everything else → 403 / ENETUNREACH"]
  end

  UI["scripts/ui-server.ts<br/>node:http · JSON API · SSE /api/events · static ui/dist"]
  REAP["scripts/reap.sh<br/>silence > timeout → .dead + drop locks"]
  CHROME["headless Chromium<br/>work/&lt;agent&gt;/.browser/*.png"]

  CLI -->|herdr workspace create / pane split / agent start / agent prompt| HERDR
  CLI -->|renders SWARM.md from the goal document + team.json, budget.json, .pi/SYSTEM.md| FS
  CLI -->|starts| NG
  P0 & P1 & PN --> EXT
  EXT <-->|read/write protocol files| FS
  EXT -->|HTTPS_PROXY| NG
  NG --> PROVIDER
  NG -.-> DENY
  PW --> CHROME --> WORK
  UI -->|fs.watch recursive| FS
  UI -->|bash scripts/swarm.sh start / stop / reap| CLI
  BROWSER <-->|HTTP + SSE, port 43173, 127.0.0.1 by default<br/>reads open, mutations need the token| UI
  TAIL --> FS
  TAIL -->|polls| REAP
  TAIL -->|runs the goal's ## Checks| FS
  UI -->|Reap stalled| REAP
  REAP --> DONE
  REAP -.->|--stop: herdr agent get → pane close| HERDR
```

Reading the diagram:

- **Spawner** (`scripts/swarm.sh start`) is the only authority. It allocates a unique swarm id (`s` + 4 hex), frames the goal document as `SWARM.md`, writes `team.json` / `budget.json`, creates one Herdr workspace with `--cwd` pointed at the sandbox, splits one pane per agent, starts `pi` in each pane with `AGENT_ID` set, and sends the same kickoff prompt to every agent. It assigns no roles: who reviews whom is the goal's business.
- **Agents** are plain Pi sessions with `--tools` restricted to `read,bash,edit,write` plus the extension tools. All swarm behaviour lives in `extensions/agent-swarm.ts` + `extensions/protocol.ts`; nothing is patched into Pi or Herdr.
- **The harness has a voice.** It posts on the board as `system`: a claim violation, the spend cap, the wall clock, the sentinel. Those used to reach only `events.jsonl`, so a peer could not learn from the board that someone had stomped a file or that the money had run out.
- **The filesystem is the protocol.** Posts are files, locks are files, done is a file, the log is a file. Anything that can `ls` the sandbox can observe or drive the swarm.
- **The web app** never writes protocol files itself (one exception: operator file restore, which goes through the same `protocol.ts` claim path). Every mutation shells out to `scripts/swarm.sh`, so the UI and the terminal can never disagree.
- **Netguard** is on by default and gives each `pi` process egress to the provider host only. **Reaper** and **Playwright** are optional side paths.

## With a microVM per agent (`--isolation microvm`)

The default. The same extension, the same protocol and the same files, with the agents
moved behind a VM's wall and one process on the host writing the board for
them. [ADR 0009](adr/0009-agents-live-in-microvms.md) says why.

```mermaid
flowchart TB
  subgraph HOST["The examiner's machine"]
    CLI["scripts/swarm.sh start --isolation microvm"]
    VMM["scripts/vm.ts<br/>microsandbox SDK: create · probe · finish · reap"]
    HUB["scripts/vm-hub.ts<br/>the board's only writer · one socket per agent<br/>trace forward · nudges · host backstop"]
    COL["scripts/trace-collector.mjs<br/>hash chain · anchor · recv_ts"]
    FS["runs/ID/ on the host"]
    EV["evidence directory (in place)"]
    PANES["Herdr panes: msb exec -t dfs-ID-AGENT"]
    CUST["scripts/custody.ts at stop<br/>custody.json"]
  end
  subgraph VM0["microVM · agent 00"]
    PI0["Pi + extensions/agent-swarm.ts<br/>board.ts → one held connection"]
    BR0["socat bridge<br/>/run/dfirswarm/hub.sock ↔ vsock 5000"]
  end
  subgraph VM1["microVM · agent 01"]
    PI1["Pi + extensions"]
    BR1["socat bridge"]
  end
  CLI --> VMM --> VM0 & VM1
  CLI --> HUB
  CLI --> PANES --> PI0 & PI1
  PI0 --> BR0 -->|vsock → <dir>/agent00.sock| HUB
  PI1 --> BR1 -->|vsock → <dir>/agent01.sock| HUB
  HUB -->|protocol.ts| FS
  HUB --> COL --> FS
  FS -.->|read-only floor · work/ID, work/extracted/ID, work/quarantine/ID, tool-output/ID, .pi-sessions/ID writable| VM0 & VM1
  EV -.->|read-only, same path| VM0 & VM1
  VMM -->|finish: snapshot + remove| VM0 & VM1
  CUST --> FS
```

- **Everything is mounted at its host path.** The sandbox, the evidence, the
  harness code and each agent's writable directories appear in the guest
  where they are on the host, so a path in a post, the trace, the registry or
  a check means the same file on both sides.
- **The floor is read-only; the holes are the agent's own.** The run's root is
  one read-only share, `work/` included, and each seat's own `work/<id>/`,
  `work/extracted/<id>/`, `work/quarantine/<id>/` (the last two no-exec),
  `tool-output/<id>/` and `.pi-sessions/<id>/` are writable shares on top of
  it; unmounting a hole leaves the read-only floor. Nothing writable is
  shared between VMs: a shared file under `work/` (`work/report.md`, a
  timeline) goes through `publish_file`, and the hub writes it on the host,
  claimed and recorded for the agent that asked. The board's files are
  read-only in every VM.
- **The board is a call, not a file.** `extensions/board.ts` exports the
  protocol's own functions; with `SWARM_BOARD_SOCKET` set they go to the hub
  over one held connection per process, each call with an id. The hub runs
  `protocol.ts` on the host, as the agent its socket belongs to. Without the
  variable they run locally, which is host mode.
- **The harness's voice reaches Pi directly.** A pane runs `msb exec`, which
  Herdr can neither read nor type into as Pi; each extension keeps a link to
  the hub, reports working/idle up it, and takes the harness's prompts (a
  nudge, a stop) down it as user messages. The hub reports each agent's state
  to Herdr for the panes' badges.
- **No credential crosses.** `scripts/vm.ts` asks Pi on the host for each
  provider's key or subscription token, gives it to msb as a secret bound to
  that provider's hosts, and writes the guest's `~/.pi/agent/auth.json` with
  placeholders only.
