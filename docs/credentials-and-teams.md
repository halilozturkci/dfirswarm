# Credentials, subscriptions, and mixed-model teams

## Credentials: ask Pi, do not guess

A swarm can authenticate four different ways, and the harness does not try to
tell them apart:

| How | Set up with | What the preflight prints |
| --- | --- | --- |
| A ChatGPT/Codex **subscription** (OAuth) | `pi /login` | `openai-codex subscription (OAuth, refreshed by Pi): consumer plan; not for customer data` |
| A stored **API key** | `pi /login` | `deepseek api_key via Pi's own store` |
| A provider configured in **models.json** (self-hosted, local, a gateway) | edit `models.json` | `mockswarm api_key via Pi's own store` |
| A key exported into the shell | `--key-from-env` | `$DEEPSEEK_API_KEY passed to each pane` |

The gate is one call to `pi auth check --model <provider/id> --json`, run once
per distinct model before any pane opens. Pi is the thing that will actually do
the authenticating; every hand-rolled version of this check grew a bug that
either waved through a run with no usable credential or refused one that was
perfectly fine. The check also refreshes an expired OAuth token as a side
effect, which is what you want *before* the panes go behind netguard.

**A Claude subscription is refused.** Anthropic does not permit Free, Pro or
Max subscription credentials in a third-party client such as Pi: an
`anthropic/*` seat on an OAuth login in Pi's store (or on
`ANTHROPIC_AUTH_TOKEN` or `ANTHROPIC_OAUTH_TOKEN` where the store holds no key:
Pi takes those before `ANTHROPIC_API_KEY`) is refused at kickoff in every run. Log Pi in to Anthropic with an API key from the Anthropic Console
(`/logout anthropic`, then `/login anthropic`, choosing the key).

**A customer's case takes API keys only.** `--customer-case` refuses every
subscription seat (`openai-codex/*` whatever the store says: its terms are a
consumer plan's, with no processor commitments) and asks whose key each
provider uses (`--key-owner [PROVIDER=]OWNER`: the customer's own, or your
business account's with the customer told). The record and custody keep it
per seat. Codex's subscription stays usable for test and CTF runs, and every
subscription seat is recorded as "consumer plan; not for customer data" (another provider's as "subscription login; not for customer data")
([ADR 0003](adr/0003-the-provider-key-comes-from-pis-own-store.md), "Whose
credential, under which terms").

A subscription needs no API key and no `--key-from-env`. It does need its token
endpoint on the netguard allowlist, because an access token expires mid-run and
a refresh that cannot reach the endpoint fails the swarm rather than the
request:

| Provider | API host | OAuth token endpoint |
| --- | --- | --- |
| `anthropic` | `api.anthropic.com` | `platform.claude.com` |
| `openai-codex` | `chatgpt.com` | `auth.openai.com` |

Both are in `provider_hosts_for_model` and in netguard's own default list.

### Azure OpenAI

Pi's `azure` provider serves the same model ids as OpenAI
(`azure/gpt-5.4`, `gpt-5.4-mini`, `gpt-5.5`, …) against the
customer's own resource. Four settings: the key (`AZURE_OPENAI_API_KEY`), the
endpoint (`AZURE_OPENAI_BASE_URL`, `https://<resource>.openai.azure.com` or
the `.cognitiveservices.azure.com` / `.ai.azure.com` forms; or
`AZURE_OPENAI_RESOURCE_NAME`), and optionally the API version
(`AZURE_OPENAI_API_VERSION`) and the deployment map
(`AZURE_OPENAI_DEPLOYMENT_NAME_MAP=gpt-5.4=<deployment>`). The clean way is
Pi's own store, where the key never touches the shell or `ps`:

```json
{
  "azure": {
    "type": "api_key",
    "key": "<the key>",
    "env": {
      "AZURE_OPENAI_BASE_URL": "https://<resource>.openai.azure.com",
      "AZURE_OPENAI_API_VERSION": "<api version>",
      "AZURE_OPENAI_DEPLOYMENT_NAME_MAP": "gpt-5.4=<deployment>"
    }
  }
}
```

in `~/.pi/agent/auth.json` (mode 0600). `pi auth check --model azure/gpt-5.4 --json`
is the gate, as for every provider. The netguard allowlist needs the
resource's host: `provider_hosts_for_model` reads it from the shell or from
that store entry, and the kickoff warns when it finds neither, in which case
`--allow-host <resource>.openai.azure.com` does it. Azure settings exported in
the kickoff shell are forwarded to the panes; the key itself only with
`--key-from-env`.

### Azure AI Foundry, and any other provider from `models.json`

An Azure AI **Foundry** resource is not the same thing as an Azure OpenAI
resource: it serves third-party models (Grok, DeepSeek, Llama, Mistral) from
your own deployments, on an OpenAI-compatible route
`https://<resource>.services.ai.azure.com/openai/v1`, where the model name is
the **deployment** name. `azure` does not carry those model
ids, so define the provider in Pi's own `~/.pi/agent/models.json` instead:

```json
{
  "providers": {
    "azure-foundry": {
      "name": "Azure AI Foundry",
      "baseUrl": "https://<resource>.services.ai.azure.com/openai/v1",
      "api": "openai-completions",
      "models": [
        { "id": "grok-4.6", "reasoning": true, "input": ["text", "image"],
          "contextWindow": 500000, "maxTokens": 128000,
          "cost": { "input": 2, "output": 6, "cacheRead": 0.5, "cacheWrite": 0,
                    "tiers": [{ "inputTokensAbove": 200000, "input": 4, "output": 12, "cacheRead": 1, "cacheWrite": 0 }] } },
        { "id": "DeepSeek-V4-Pro", "reasoning": true, "input": ["text"],
          "contextWindow": 1000000, "maxTokens": 384000, "maxTokensField": "max_tokens",
          "cost": { "input": 1.74, "output": 3.48, "cacheRead": 0.145, "cacheWrite": 0 } }
      ]
    }
  }
}
```

with the key in `auth.json` under the same provider id. Then
`--models "azure-foundry/grok-4.6=4,azure-foundry/DeepSeek-V4-Pro=3"`.

Two things worth knowing:

- **The costs are yours to state.** Pi bills the swarm from the `cost` block,
  so a provider defined here reports spend at whatever rates you write, and a
  missing block means a run that reports $0 and a spend cap that never fires.
  Take the numbers from the provider, not from the model's own vendor: the
  rates above are Azure's own (retail prices API, Global deployments,
  commercial regions), and DeepSeek V4 Pro costs $1.74 per 1M input tokens
  there against $1.32 at DeepSeek itself. The first run here was configured
  from neither, and under-reported its bill by a third —
  [the case README](use-cases/dfir-c07-sysinternals-azure/README.md) shows
  the arithmetic. Azure's current figures for any model:

  ```bash
  curl -s "https://prices.azure.com/api/retail/prices?\$filter=productName%20eq%20'Azure%20Grok%20Models'" \
    | jq -r '.Items[] | "\(.meterName) \(.retailPrice * 1000) USD/1M \(.armRegionName)"' | sort -u
  ```
- **A rate can depend on the hour.** DeepSeek's own API charges half its list
  price outside 01:00–04:00 and 06:00–10:00 UTC on weekdays
  ([its pricing page](https://api-docs.deepseek.com/quick_start/pricing/):
  V4 Pro at $1.32 input, $3.96 output, $0.044 cached input per 1M at peak).
  A `cost` block holds one number, so Pi bills the peak rate around the
  clock; an off-peak run really costs half of what the console showed. That
  is the safe direction for a cap, and it means the reported figure is an
  upper bound rather than the invoice — the DFIR cases recompute it.
- **The host comes from `baseUrl`.** `provider_hosts_for_model` falls through
  to `models.json` for any provider it does not know, so a Foundry resource, a
  gateway or a local server reaches netguard's allowlist without
  `--allow-host`. Check it with
  `pi auth check --model azure-foundry/<deployment> --json` before the run;
  the kickoff refuses to start on anything but `ready`.

### Local models (Ollama, LM Studio, vLLM, llama.cpp)

A model served from this machine or this network is a `models.json`
provider like any other, with three things Pi's own documentation is explicit
about and the harness now checks for you.

```json
{
  "providers": {
    "ollama": {
      "name": "Ollama (local)",
      "baseUrl": "http://127.0.0.1:11434/v1",
      "api": "openai-completions",
      "apiKey": "ollama",
      "compat": {
        "supportsDeveloperRole": false,
        "supportsReasoningEffort": false,
        "supportsStore": false,
        "maxTokensField": "max_tokens"
      },
      "models": [
        { "id": "qwen3-coder-next:latest", "contextWindow": 131072, "maxTokens": 32768 },
        { "id": "gpt-oss:20b", "reasoning": true, "contextWindow": 131072, "maxTokens": 32768 }
      ]
    }
  }
}
```

- **The `apiKey` is a placeholder, and it is mandatory.** Pi lists a provider
  only when it has *some* credential, even one the server ignores; without it
  `pi auth check` answers `not_ready / credentials_not_configured` and the
  models are absent from `pi --list-models`. Any value will do. There is no
  `pi /login` for this and nothing for `--key-from-env` to forward; the
  kickoff says so, with the snippet to add, when it meets a keyless local
  provider.
- **The `compat` block is required.** Pi autodetects compatibility from the
  URL and has no rule for a local server, so without it Pi sends the
  `developer` role, `reasoning_effort`, `store` and `max_completion_tokens`,
  which Ollama, vLLM and SGLang reject. The kickoff warns when the block is
  missing.
- **`contextWindow` must match the server.** Ollama's OpenAI-compatible
  endpoint ignores `num_ctx` in a request and uses its own default — 4096 on
  current builds — while Pi budgets against whatever you declared, and the
  truncation is silent. Set `OLLAMA_CONTEXT_LENGTH=131072` in Ollama's
  environment (or `PARAMETER num_ctx` in a Modelfile), restart it, and
  declare the same number here. The kickoff reads the effective value back
  from Ollama and warns when the two disagree.

No `cost` block: absent means all zero, which is the truth, and it is how the
harness knows the team is not metered. Pi reports the run's cost as an exact
$0, so **a USD cap cannot stop it**; the kickoff requires `--cap-tokens N`
for such a team and records `metered: false` in `budget.json`. The summary
and the console then speak in tokens rather than saying "$0.00 spent".

```bash
scripts/swarm.sh start --model ollama/qwen3-coder-next:latest --n 3 \
  --cap-tokens 20000000 --wall-clock 30 --local-only \
  --goal-file prompts/goals/hello.md
```

Before any pane opens the kickoff asks the server itself: that it answers on
`baseUrl`, that the model id is in its `/models` list (a BLOCKER naming what
it does serve when not), and, for Ollama, what context it will really give.
The traffic then goes through netguard like every other model call — Pi
tunnels even a plain-HTTP origin as `CONNECT`, and the sidecar runs on the
host, so loopback is reachable — with the literal host from `baseUrl` on the
allowlist, and its other spelling too (`127.0.0.1` ↔ `localhost`), because
neither Pi's proxy matcher nor the proxy resolves names. `--local-only` turns
the allowlist into those endpoints alone.

LM Studio is the same shape on `http://127.0.0.1:1234/v1` (the `/v1` is
required; its model ids may contain `/`). vLLM is the same on `:8000/v1`,
with `"thinkingTokenBudgetField": "thinking_token_budget"` in `compat` if
you want thinking budgets. llama.cpp is better served by Pi's own provider:
run `llama-server` in router mode with `--jinja` (which is what enables tool
calling), export `LLAMA_BASE_URL=http://127.0.0.1:8080` and
`LLAMA_API_KEY=local`, and name the model `llama.cpp/<loaded id>`; only loaded
models are listed, and the harness takes the host from `LLAMA_BASE_URL`.

Two things a local model cannot promise: Pi has no way to tell whether a
model supports tool calls, so one that ignores tool definitions will post
nothing and claim nothing rather than fail loudly; and prompt-cache fields
stay zero, so a local run's token total is not comparable with a cloud run's.
Measure a candidate on `prompts/goals/hello.md` before trusting it with a case.

### Cursor's models, through `cursor-agent`

`extensions/cursor-provider.ts` registers a provider, `cursor`, that serves
the models of a Cursor account to Pi: `pi -e extensions/cursor-provider.ts
--model cursor/grok-4.7-medium`. Pi stays the agent (its loop, its tools, the
swarm's guards and record); the model is reached through Cursor's own CLI,
`cursor-agent`, in its headless mode. Install the CLI and log it in on the
host (`cursor-agent login`, or `CURSOR_API_KEY`); `cursor-agent models` lists
the ids, the reasoning effort part of each (`grok-4.7-high`,
`deepseek-v41-flash-1017-none`, `kimi-k3-low`).

What it is, measured on `cursor-agent` 2026.10.22:

- **The CLI is an agent of its own.** Its ask mode still read `/etc/hostname`
  outside its workspace, and the account's MCP plugins (Gmail among them) are
  listed to its model. Each chat therefore has a workspace of its own whose
  `.cursor/cli.json` denies shell, read, write, web fetch and every MCP tool;
  the CLI refused each such call when tried. One of its tools that ran anyway
  (anything but an empty search of the empty workspace, or a list of tool
  names) stops the turn as an error. A tool the permissions have no name for,
  such as the CLI's web search, is not refused by them, and its request has
  left by the time the turn stops.
- **Pi's tools are offered as `pi__<tool>`**, asked for in text blocks that
  end the model's reply, each on a line of its own, which the extension
  parses. A block quoted anywhere else (an injection the model reports) is
  text; one written after text on its line, or cut off, is never run and
  comes back to the model as an error. A text protocol has one limit: a block
  the model quotes as the very last thing in its reply, on a line of its own,
  cannot be told from a call, and Pi runs it under the same guards as any
  other call. A model told to use "your read tool" took the CLI's own Read when the
  names were the same, and DeepSeek still reached for it with the names apart;
  a model that reaches for the CLI's tools and asks Pi for nothing is told
  so once, in the same chat, which costs a second run. Even so, turn the
  account's MCP plugins off, or use an account without them, for a seat that
  reads evidence.
- **The CLI leaves processes behind** (a node process and a TypeScript
  language server it starts through npx): each call runs in a process group
  of its own, killed when the call ends however it ends, and every live group
  when Pi exits. What a killed Pi's call left running in its workspace is
  killed at the next start (on Linux, which has /proc).
- **A conversation is one Cursor chat**, resumed so that only what is new is
  sent. Cursor keeps a chat's history per workspace, so a chat keeps its
  workspace. A chat is resumed only for the exact history it holds and the
  reply it gave, by one call at a time; a changed history (a compaction, an
  edit) starts a new chat.
  DeepSeek's turns after the first were read mostly from Cursor's cache;
  Grok's and Kimi's were counted whole every turn.
- **Usage is the CLI's token count; the cost is zero.** Cursor publishes no
  per-token price for a plan, so a dollar cap does not hold a Cursor seat: cap
  it by tokens or calls.
- **Whether a plan may be used this way is Cursor's to say.** Read its terms
  before relying on it.

A Cursor seat opens in the swarm like any other: `--models
cursor/grok-4.7-medium=2,cursor/kimi-k3-high=1`. The kickoff loads the
extension into every seat (and the probe) when the team has one, and checks
the CLI instead of `pi auth`: that `cursor-agent` is installed (or named by
`CURSOR_AGENT_BIN`), logged in (or given `CURSOR_API_KEY`), and serves each
id, with the ids it does serve when one is not. A plan login counts as a
subscription: not for `--customer-case`, and a team of Cursor seats only must
name `--cap-tokens`. The network allow-list gets Cursor's hosts, and the
write guard lets the CLI write `~/.cursor` and `~/.config/cursor`, where it
keeps its login and its chats, and `/tmp/cursor-agent-persist-<uid>`, where it
locks a chat it resumes (a fixed path, not taken from `TMPDIR`); those chats
are Cursor's copy of the conversation and sit outside the run's record. The
CLI's own sandbox does not start inside the panes' kernel guard, so under
that guard the CLI runs without it (`PI_CURSOR_SANDBOX=disabled`, said at
kickoff), held by the guard and its deny-all permissions. A seat's context is
the transcript's estimate, not the CLI's count, which adds up every step of a
run: the count goes to the budget, the estimate to the self-compaction. The
CLI also connects to every
MCP server the account has, which the network guard blocks unless their hosts
are allowed. Cursor seats run with `--isolation host` for now: the agents'
image has no `cursor-agent`, so a microVM run (the default) with a Cursor
seat is refused at kickoff.

### What a subscription will not do

A login is not the same as an entitlement. Anthropic answered a third-party
request on a Claude plan with:

> Third-party apps now draw from your extra usage, not your plan limits.

That is a billing decision at the provider, not a harness problem: OAuth worked,
the request reached the API, and the API declined it. On the ChatGPT side only
some models are offered to a ChatGPT account — `gpt-6-astra` ran, `gpt-5.4` and
`gpt-5.3-codex-spark` came back "not supported when using Codex with a ChatGPT
account". The preflight cannot see any of this, because `pi auth check` asks
whether Pi *has a credential*, not whether the account may use a given model.
The first agent turn is where you find out.

### Under `--isolation microvm`

The same gate runs, and then no credential enters a VM:

- Pi on the host resolves each credential at kickoff (`pi auth
  print-api-key`, or for a subscription `pi auth print-bearer-token
  --min-expiry`, refreshed on the host for the length of the run) and msb
  holds it. The guest's Pi gets a placeholder shaped the way Pi reads that
  credential, and msb swaps the value in only on the way to the provider's
  own hosts; a placeholder sent anywhere else is stopped and logged, and
  custody names it.
- Each seat's VM holds only its own model's credential and the summary
  model's (`--compact-model`), never another seat's.
- A provider's `env` block and credential headers in `models.json` cross as
  placeholders too; a header Pi would resolve at request time (`$VAR`,
  `!command`) is refused.
- A subscription (OAuth) needs `--allow-oauth-in-vm`: its token is the
  operator's account at the provider, not an inference key. The guest never
  refreshes it and the refresh endpoint is never bound, so the token Pi mints
  at kickoff must last the wall clock and an hour more, or the kickoff stops.
  The host renews it: at half its validity the idle watchdog mints the
  seats' tokens again from Pi's store and msb rotates each seat VM's secret
  in place (live, no restart; the guest keeps its placeholder), so a run
  stopped only by the operator outlasts its first token
  ([ADR 0015](adr/0015-one-seat-finishes-and-work-is-offered.md)).
- An API key needs no flag, but its placeholder reaches every endpoint on the
  provider's host that the key may use, not only inference.
- `--key-from-env` is refused, and so is an `--env` name that looks like a
  credential: either would put the value into every VM and its snapshot.
- A provider whose host the harness cannot find is refused
  (`--provider-host P=HOST` names it). Bedrock and Vertex sign every request
  with their secret inside the client, so they cannot run in a VM.
- A pack's secrets reach a VM as placeholders too, in the whole VM's
  environment ([packs.md](packs.md) §4).
- A local model on this machine is reached through msb's host gateway: the
  guest's `models.json` names it `host.microsandbox.internal:<port>`. One
  elsewhere on the LAN is reached by its address and port. Pi's built-in
  `llama.cpp` provider, configured by `LLAMA_BASE_URL` in the shell, is not
  carried into a VM; describe the same server as a `models.json` provider.

## What a run may install

A case can turn on a reader this host does not have. `--allow-install` is the
narrow answer: `pypi.org` and `files.pythonhosted.org` join netguard's
allowlist, `PYTHONUSERBASE` points at `work/.toolchain/` inside the sandbox,
and `python3 -m pip install --user <package>` therefore installs into the run
and nowhere else. It is off by default; the contract says the rule when it is
on, and asks the agents to record what they installed in the ledger.

Two things it deliberately does not do. It does not open Homebrew or a system
package manager: those write to `/opt/homebrew` and `/usr`, outside the
sandbox, on a machine the next case also has to trust. And it does not grant
root — there is none here, nothing mounts, and that is the guarantee that
makes `inputs/` read-only mean anything. For reading an encrypted or virtual
volume this costs nothing: libbde, libvhdi, libluksde and pytsk3 all read in
place, and the `crypto` toolbox set names them so a kickoff finds out before
the run instead of at minute forty. For a case that genuinely needs a mount,
the answer is `--isolation microvm`, where root and the mount are the VM's
own (whether FUSE or a loop device is there is in each VM's probe record),
not `sudo` on the host; see [safety](safety.md).

On the host `--allow-install` also sets `PIP_BREAK_SYSTEM_PACKAGES=1`, so
`pip install --user` works on a system whose Python is marked externally
managed (PEP 668). It also means PEP 668 no longer refuses a pip run without
`--user`; the write guard is what keeps that out of the system.

Under `--isolation microvm` the agent is root in its own VM and the rule
changes shape. `pip install` (without `--user`) goes into that VM's own disk,
`/opt/dfir/agent`, which no other VM sees and which is kept in that VM's disk
snapshot at stop; the
package index is `pypi.org` and `files.pythonhosted.org`, and `--no-pypi`
keeps them off the VM's allowlist. There is no Debian mirror on the
allowlist, so apt reaches nothing unless the operator allows the image's
mirror with `--allow-host`. A program a pack requires that the image lacks
is a warning with `--allow-install` rather than a refusal. What each VM holds
that its image did not is listed at stop and named in custody.

## Mixed teams

One swarm does not have to be one model:

```bash
scripts/swarm.sh start \
  --models "openai-codex/gpt-6-astra=2,deepseek/deepseek-v4-pro=2" \
  --cap-usd 10 --goal-file prompts/goals/hello.md
```

N is the sum of the counts. Pass `--n` as well and it is checked against that
sum rather than silently winning. `--model` and `--models` are mutually
exclusive: one is "everybody runs this", the other is "here is the team".

What the harness does with it:

- **Every distinct model is credential-checked** before a pane opens, so a team
  that can only authenticate half of itself fails at kickoff rather than three
  agents in.
- **The allowlist is the union** of every provider's hosts. Allowing only the
  first model's provider leaves the other agents unable to reach theirs, which
  looks exactly like a hung swarm.
- **Each agent's model is in `team.json` and named on the board.** Who is
  running what is the one thing an agent cannot work out for itself, and the
  only basis on which it could sensibly hand a slice to a peer.
- Agents are assigned in spec order: the first model named gets agent `00`.

A four-agent run of the `hello` goal, two Codex agents and two DeepSeek:

```
s85a500 -> openai-codex/gpt-6-astra    $0.332720
s85a501 -> openai-codex/gpt-6-astra    $0.289682
s85a502 -> deepseek/deepseek-v4-pro    $0.028674
s85a503 -> deepseek/deepseek-v4-pro    $0.034981
```

All four ids landed in the artifact, both checks passed, and the sentinel was
written by a DeepSeek agent. The order-of-magnitude difference in the per-agent
column is the argument for mixing in the first place — and a reminder that the
Codex figures are Pi's price-table estimate against a subscription, not money
charged.

## Editing the goal from the web app

`/new` has the goal document as a first-class editor, backed by a library:

- **Goal library** — the markdown files in `prompts/goals/`. Load one into the
  form, or save what you have written back under a name. The CLI launches from
  the same files with `--goal-file`, so there is one copy, not two.
- **Goal tab** on a swarm — the goal document this run was given, and below it
  the rendered `SWARM.md` the agents actually read.

The live contract is **read-only**, deliberately. `SWARM.md` is a protected
path: an `edit`/`write` is blocked and a claim on it refused, because an agent
that could edit its own definition of done could certify itself. A *shell*
write is the gap the harness cannot close — no hook can stop a command
mid-flight — so that one is detected afterwards and announced on the board,
and `await-done.sh` reads the checks from the registry rather than from the
sandbox for exactly this reason. Changing a contract
under a running team would also leave half of them working to a goal the other
half never saw. So the Goal tab offers "edit a copy and relaunch", which opens
the kickoff form prefilled, and "save to library" to keep a contract that
worked.

Saving a goal needs the server token, the same as starting a swarm, and a goal
with no `## Definition of done` is refused on the way in — the same rule the CLI
applies.
