/**
 * The VM manager's decisions, at the resolution where they are cheap to
 * check: what a guest's Pi is given instead of a credential, which files a
 * guest's Pi configuration is made of, the order of a VM's mounts, what a
 * VM's probe must say for the kickoff to go on, and which VMs a reap may
 * touch. No VM is started here (tests/vm-integration.test.ts does that).
 */
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { execFileSync, spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";
import {
  bypassCovers,
  capacityVerdict,
  egressRules,
  hostAvailableMib,
  roomForWorker,
  gatewayPorts,
  imageDataWarnings,
  imageFit,
  interceptPorts,
  packNeeds,
  packSeal,
  parseAllowEntry,
  guestPiConfig,
  resolveSecrets,
  seatProviders,
  hostGatewayUrl,
  mountsFor,
  makeSeatVeils,
  seatVeil,
  placeholderFor,
  probeVerdict,
  registryLabel,
  vmPlatformProblem,
  tlsBypass,
  vmName,
  type ResolvedSecret,
  type VmSpec,
  scrubCompleted,
  scrubMsbDatabase,
  seatTokenFor,
  PROBE_SCRIPT,
  GUEST_HUB_SOCKET,
  seatPlan,
  probeChecks,
} from "../scripts/vm.ts";
import type { GatewayConfig } from "../scripts/model-gateway.ts";

const dirs: string[] = [];
after(async () => {
  for (const d of dirs) await rm(d, { recursive: true, force: true });
});

/** What Pi does with a Codex token before it sends it: the account id out of the JWT payload. */
function piCodexAccountId(token: string): string {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Invalid token");
  const payload = JSON.parse(atob(parts[1]));
  const id = payload?.["https://api.openai.com/auth"]?.chatgpt_account_id;
  if (!id) throw new Error("No account ID in token");
  return id;
}

function spec(over: Partial<VmSpec> = {}): VmSpec {
  return {
    run: "s1a2b",
    sandbox: "/runs/s1a2b",
    image: "dfirswarm-base:dev-arm64",
    hub_dir: "/tmp/dfs-s1a2b.x",
    mounts: [{ host: "/repo/extensions", readonly: true }],
    env: {},
    agents: [{ id: "s1a2b00", model: "openai/gpt-5.4-mini" }],
    allow_hosts: [],
    providers: [],
    records_dir: "/runs/s1a2b/vm",
    ...over,
  };
}

test("a placeholder is shaped the way Pi reads the credential it stands for", () => {
  const anthropic = placeholderFor("anthropic", "oauth");
  assert.match(anthropic, /sk-ant-oat/, "Pi sends a subscription bearer only for a token that says sk-ant-oat");
  const codex = placeholderFor("openai-codex", "oauth", "acct-1234");
  assert.equal(piCodexAccountId(codex), "acct-1234", "Pi reads the account id out of the Codex token's payload");
  const key = placeholderFor("openai", "api_key");
  assert.match(key, /^dfirswarm-secret-openai-[0-9a-f]{24}$/);
  assert.notEqual(placeholderFor("openai", "api_key"), key, "each placeholder is unguessable, not a fixed word");
});

test("a guest's Pi configuration holds placeholders and never a credential", async () => {
  const dir = await mkdtemp(join(tmpdir(), "vm-pi-"));
  dirs.push(dir);
  await writeFile(join(dir, "auth.json"), JSON.stringify({
    anthropic: { type: "oauth", access: "sk-ant-oat01-REAL-ACCESS", refresh: "REAL-REFRESH", expires: 1 },
    "openai-codex": { type: "oauth", access: "REAL.CODEX.TOKEN", refresh: "REAL-REFRESH-2", expires: 1, accountId: "acct-9" },
    openai: { type: "api_key", key: "sk-REAL-OPENAI" },
  }));
  await writeFile(join(dir, "models.json"), JSON.stringify({
    providers: {
      "azure-foundry": { baseUrl: "https://x.services.ai.azure.com/openai/v1", api: "openai-completions", apiKey: "REAL-AZURE-KEY", models: [{ id: "m" }] },
      lmstudio: { baseUrl: "http://127.0.0.1:1234/v1", api: "openai-completions", apiKey: "local", models: [{ id: "q" }] },
      unused: { baseUrl: "https://unused.example/v1", apiKey: "REAL-UNUSED" },
    },
  }));
  await writeFile(join(dir, "settings.json"), JSON.stringify({ defaultThinkingLevel: "medium" }));
  const s = spec({
    pi_agent_dir: dir,
    providers: [
      { provider: "anthropic", kind: "oauth", hosts: ["api.anthropic.com"] },
      { provider: "openai-codex", kind: "oauth", hosts: ["chatgpt.com"] },
      { provider: "openai", kind: "api_key", hosts: ["api.openai.com"] },
      { provider: "azure-foundry", kind: "api_key", hosts: ["x.services.ai.azure.com"] },
      { provider: "lmstudio", kind: "local", hosts: [], port: 1234 },
    ],
  });
  const secrets: ResolvedSecret[] = [
    { provider: "anthropic", kind: "oauth", placeholder: placeholderFor("anthropic", "oauth"), value: "sk-ant-oat01-REAL-ACCESS", hosts: ["api.anthropic.com"] },
    { provider: "openai-codex", kind: "oauth", placeholder: placeholderFor("openai-codex", "oauth", "acct-9"), value: "REAL.CODEX.TOKEN", hosts: ["chatgpt.com"], accountId: "acct-9" },
    { provider: "openai", kind: "api_key", placeholder: placeholderFor("openai", "api_key"), value: "sk-REAL-OPENAI", hosts: ["api.openai.com"] },
    { provider: "azure-foundry", kind: "api_key", placeholder: placeholderFor("azure-foundry", "api_key"), value: "REAL-AZURE-KEY", hosts: ["x.services.ai.azure.com"] },
  ];
  const cfg = guestPiConfig(s, secrets);
  const everything = `${cfg.auth}\n${cfg.models}\n${cfg.settings}`;
  for (const real of ["REAL-ACCESS", "REAL-REFRESH", "REAL.CODEX.TOKEN", "sk-REAL-OPENAI", "REAL-AZURE-KEY", "REAL-UNUSED"]) {
    assert.ok(!everything.includes(real), `the guest's Pi files must not carry ${real}`);
  }
  const auth = JSON.parse(cfg.auth);
  assert.equal(auth.anthropic.access, secrets[0].placeholder);
  assert.ok(auth.anthropic.expires > Date.UTC(2090, 0, 1), "a guest never refreshes: its token does not expire in the run");
  assert.equal(auth["openai-codex"].accountId, "acct-9");
  assert.equal(auth.openai.key, secrets[2].placeholder);
  assert.equal(auth["azure-foundry"], undefined, "a models.json provider carries its placeholder in models.json");
  const models = JSON.parse(cfg.models ?? "{}");
  assert.deepEqual(Object.keys(models.providers).sort(), ["azure-foundry", "lmstudio"], "only the team's providers cross");
  assert.equal(models.providers["azure-foundry"].apiKey, secrets[3].placeholder);
  assert.equal(models.providers.lmstudio.baseUrl, "http://host.microsandbox.internal:1234/v1", "a local server is reached through the host gateway");
  assert.equal(JSON.parse(cfg.settings ?? "{}").defaultThinkingLevel, "medium", "the operator's settings travel");
});

test("a local server's address becomes the host gateway, and nothing else changes", () => {
  assert.equal(hostGatewayUrl("http://localhost:11434"), "http://host.microsandbox.internal:11434");
  assert.equal(hostGatewayUrl("http://127.0.0.1:1234/v1"), "http://host.microsandbox.internal:1234/v1");
  assert.equal(hostGatewayUrl("https://api.example.com/v1"), "https://api.example.com/v1");
  assert.equal(hostGatewayUrl("not a url"), "not a url");
});

test("a copy of the evidence in the spec's mounts comes after the floor with its flags kept: the mount that holds the files is the read-only, no-exec one", () => {
  // As the kickoff's vm_build_spec writes a --inputs-copy run (inputs_mount_dirs).
  const s = spec();
  const S = s.sandbox;
  const copy = [`${S}/inputs`, `${S}/.inputs-pristine`];
  const m = mountsFor({ ...s, mounts: [...s.mounts, ...copy.map((host) => ({ host, readonly: true, noexec: true }))] }, "s1a2b00");
  assert.deepEqual(m[0], { host: S, readonly: true }, "the floor comes first");
  for (const host of copy) {
    const at = m.findIndex((x) => x.host === host);
    assert.ok(at > 0, `${host} is mounted after the floor, over it`);
    assert.deepEqual(m[at], { host, readonly: true, noexec: true }, `${host} keeps read-only and no-exec`);
  }
});

test("a VM's mounts: the run's floor read-only first, then the agent's own writable holes, and nothing shared writable", () => {
  const m = mountsFor(spec(), "s1a2b00");
  assert.deepEqual(m[0], { host: "/runs/s1a2b", readonly: true }, "the floor comes first, read-only");
  const writable = m.filter((x) => !x.readonly).map((x) => x.host);
  assert.deepEqual(writable, [
    "/runs/s1a2b/work/s1a2b00",
    "/runs/s1a2b/work/extracted/s1a2b00",
    "/runs/s1a2b/work/quarantine/s1a2b00",
    "/runs/s1a2b/tool-output/s1a2b00",
    "/runs/s1a2b/.pi-sessions/s1a2b00",
  ]);
  assert.ok(!writable.includes("/runs/s1a2b/work"), "the shared work/ is part of the read-only floor");
  // Listed outright: an `every` over an empty list would pass with no noexec mount at all.
  assert.deepEqual(
    m.filter((x) => x.noexec).map((x) => [x.host, x.readonly === true]),
    [
      ["/runs/s1a2b/work/extracted", true],
      ["/runs/s1a2b/work/quarantine", true],
      ["/runs/s1a2b/work/extracted/s1a2b00", false],
      ["/runs/s1a2b/work/quarantine/s1a2b00", false],
    ],
    "extracted and quarantined material cannot execute here, a peer's (read-only) as well as one's own",
  );
  const order = m.map((x) => x.host);
  assert.ok(order.indexOf("/runs/s1a2b/work/extracted") < order.indexOf("/runs/s1a2b/work/extracted/s1a2b00"), "the shared corner is mounted before the seat's own inside it");
  assert.ok(!writable.some((h) => h.includes("s1a2b01")), "never a peer's directory");
  // The run's traces/, tool-output/ and .pi-sessions/ are each covered by
  // one of the seat's veils, read-only and outside the run; the seat's own
  // hole goes on top where it has one.
  for (const [dir, own] of [["traces", false], ["tool-output", true], [".pi-sessions", true]] as const) {
    const veil = m.findIndex((x) => (x.guest ?? x.host) === `/runs/s1a2b/${dir}`);
    assert.ok(veil > 0, `the floor's ${dir}/ is covered`);
    assert.deepEqual(m[veil], { host: seatVeil(spec(), dir, "s1a2b00"), guest: `/runs/s1a2b/${dir}`, readonly: true });
    assert.ok(!m[veil]!.host.startsWith("/runs/s1a2b/"), `the ${dir} veil is not a directory of the run`);
    const hole = order.indexOf(`/runs/s1a2b/${dir}/s1a2b00`);
    if (own) assert.ok(hole > veil, `the seat's own ${dir}/ hole is mounted on the veil, after it`);
    else assert.equal(hole, -1, `nothing of ${dir}/ is the seat's own`);
    assert.notEqual(seatVeil(spec(), dir, "s1a2b00"), seatVeil(spec(), dir, "s1a2b01"), "each seat has its own veil");
  }
});

test("a seat sees no peer's Pi session or tool output and no trace; the probe says which, and the kickoff refuses a VM that sees one", async () => {
  // Run s306463: a seat grepped its peers' session transcripts through the
  // read-only floor and quoted what it found. The trace carries every seat's
  // calls and reasoning, and a critic re-deriving a finding must not read it.
  const dir = await mkdtemp(join("/tmp", "veil-"));
  after(() => rm(dir, { recursive: true, force: true }));
  const hub = { hub_dir: join(dir, "hub") };
  const mine = await makeSeatVeils(hub, "s1a2b00");
  await makeSeatVeils(hub, "s1a2b01");
  assert.deepEqual(mine, [seatVeil(hub, "traces", "s1a2b00"), seatVeil(hub, "tool-output", "s1a2b00"), seatVeil(hub, ".pi-sessions", "s1a2b00")]);
  assert.deepEqual(await readdir(seatVeil(hub, "traces", "s1a2b00")), [], "the trace's veil is empty");
  assert.deepEqual(await readdir(seatVeil(hub, "tool-output", "s1a2b00")), ["s1a2b00"], "the tool-output veil holds the seat's own mount point and nothing else");
  assert.deepEqual(await readdir(seatVeil(hub, ".pi-sessions", "s1a2b00")), ["s1a2b00"]);
  assert.deepEqual(await readdir(seatVeil(hub, ".pi-sessions", "s1a2b01")), ["s1a2b01"]);
  // The probe's check, as the guest runs it: once over the floor as it is on
  // the host (every seat's directory and the trace made at kickoff), once
  // through the veils.
  const block = PROBE_SCRIPT.match(/# What of the peers' records this seat can see[\s\S]*?out\["trace"\] = [^\n]*\n/);
  assert.ok(block, "the probe's veil check was not found");
  const probe = async (sandbox: string): Promise<Record<string, string>> => {
    const py = `import errno, json, os\nS = ${JSON.stringify(sandbox)}\nA = "s1a2b00"\nout = {}\n${block![0]}print(json.dumps(out))\n`;
    return JSON.parse(execFileSync("python3", ["-c", py], { encoding: "utf8" }).trim()) as Record<string, string>;
  };
  const floor = join(dir, "floor");
  for (const id of ["s1a2b00", "s1a2b01", "s1a2b02"]) {
    await mkdir(join(floor, ".pi-sessions", id), { recursive: true });
    await mkdir(join(floor, "tool-output", id), { recursive: true });
  }
  await mkdir(join(floor, "traces"), { recursive: true });
  await writeFile(join(floor, "traces", "events.jsonl"), "{}\n");
  assert.deepEqual(await probe(floor), {
    peers_sessions: "visible:s1a2b01,s1a2b02",
    peers_tool_output: "visible:s1a2b01,s1a2b02",
    trace: "visible:events.jsonl",
  }, "on the floor alone every peer's record and the trace are there");
  const guest = join(dir, "guest");
  await mkdir(guest, { recursive: true });
  await symlink(seatVeil(hub, ".pi-sessions", "s1a2b00"), join(guest, ".pi-sessions"));
  await symlink(seatVeil(hub, "tool-output", "s1a2b00"), join(guest, "tool-output"));
  await symlink(seatVeil(hub, "traces", "s1a2b00"), join(guest, "traces"));
  assert.deepEqual(await probe(guest), { peers_sessions: "hidden", peers_tool_output: "hidden", trace: "hidden" }, "through the veils only the seat's own");
  const good = { base: "ro", work: "ro", scratch: "rw", extracted: "rw", extracted_exec: "noexec", quarantine_exec: "noexec", tool_output: "rw", session: "rw", inputs: "ro", hub: true, pi: "0.87.0" };
  const veiled = { ...good, peers_sessions: "hidden", peers_tool_output: "hidden", trace: "hidden" };
  assert.deepEqual(probeVerdict(veiled, true), []);
  assert.match(probeVerdict({ ...veiled, peers_sessions: "visible:s1a2b01" }, true).join(), /a peer's Pi session is readable here \(visible:s1a2b01\)/);
  assert.match(probeVerdict({ ...veiled, peers_tool_output: "visible:s1a2b01" }, true).join(), /a peer's tool-output\/ is readable here \(visible:s1a2b01\)/);
  assert.match(probeVerdict({ ...veiled, trace: "visible:events.jsonl" }, true).join(), /the run's trace is readable here \(visible:events\.jsonl\)/);
  assert.deepEqual(probeVerdict(good, true), [], "a probe from before the checks is not refused for lacking them");
  const rows = probeChecks(veiled, true).filter((c) => ["a peer's Pi sessions", "a peer's tool-output/", "the run's trace"].includes(c.check));
  assert.deepEqual(rows.map((c) => [c.check, c.want, c.got, c.ok]), [
    ["a peer's Pi sessions", "hidden", "hidden", true],
    ["a peer's tool-output/", "hidden", "hidden", true],
    ["the run's trace", "hidden", "hidden", true],
  ]);
});

test("the kickoff goes on only when a VM's own probe says what the run needs", () => {
  const good = { base: "ro", work: "ro", scratch: "rw", extracted: "rw", extracted_exec: "noexec", quarantine_exec: "noexec", tool_output: "rw", session: "rw", inputs: "ro", hub: true, pi: "0.87.0" };
  assert.deepEqual(probeVerdict(good, true), []);
  assert.match(probeVerdict({ ...good, work: "rw" }, true).join(), /shared work\/ is rw/, "a writable shared work/ is refused");
  assert.match(probeVerdict({ ...good, scratch: "ro" }, true).join(), /own work\/<id>\/ is ro/);
  assert.match(probeVerdict({ ...good, extracted_exec: "exec" }, true).join(), /extracted\/<id>\/ can execute/);
  assert.match(probeVerdict({ ...good, quarantine_exec: "exec" }, true).join(), /quarantine\/<id>\/ can execute/);
  assert.deepEqual(probeVerdict({ ...good, inputs_files: 4 }, true, 4), [], "the VM sees every name the manifest lists");
  assert.match(probeVerdict({ ...good, peers_extracted_exec: "exec" }, true).join(), /a peer's work\/extracted\/ can execute/);
  assert.match(probeVerdict({ ...good, inputs_exec: "exec" }, true).join(), /the evidence can execute/);
  // A copy's pristine clone, when the probe measured one: never writable, never executable.
  assert.deepEqual(probeVerdict({ ...good, inputs_exec: "noexec", inputs_pristine: "ro", inputs_pristine_exec: "noexec" }, true), []);
  assert.match(probeVerdict({ ...good, inputs_pristine: "rw" }, true).join(), /\.inputs-pristine\/ is rw, not read-only/);
  assert.match(probeVerdict({ ...good, inputs_pristine_exec: "exec" }, true).join(), /the pristine clone can execute in the VM \(exec\)/);
  assert.deepEqual(probeVerdict({ ...good, inputs_pristine: "rw", inputs_pristine_exec: "exec" }, false), [], "no evidence expected, the clone is not judged");
  assert.deepEqual(probeVerdict({ ...good, peers_extracted_exec: "noexec", peers_quarantine_exec: "noexec", inputs_exec: "noexec", reach: [{ target: "api.openai.com:443", ok: true }] }, true), []);
  assert.match(probeVerdict({ ...good, reach: [{ target: "api.openai.com:443", ok: false, error: "getaddrinfo ENOTFOUND" }] }, true).join(), /model's host api\.openai\.com:443 is not reachable from the VM/);
  assert.match(probeVerdict({ ...good, inputs_files: 3 }, true, 4).join(), /sees 3 evidence name\(s\) where the manifest lists 4/);
  assert.deepEqual(probeVerdict({ ...good, inputs: "absent" }, false), [], "no evidence, nothing to check there");
  assert.match(probeVerdict({ ...good, base: "rw" }, true).join(), /floor is rw/);
  assert.match(probeVerdict({ ...good, inputs: "rw" }, true).join(), /inputs\/ is rw/);
  assert.match(probeVerdict({ ...good, hub: false, hub_error: "refused" }, true).join(), /hub is not reachable \(refused\)/);
  assert.match(probeVerdict({ ...good, pi: "error: ENOENT" }, true).join(), /pi does not run/);
  assert.match(probeVerdict({}, true).join(), /floor/);
});

test("a VM's name and its registry label are stable, and two registries never share a label", () => {
  assert.equal(vmName("s1a2b", "s1a2b00"), "dfs-s1a2b-s1a2b00");
  assert.equal(registryLabel("/a/runs/registry.json"), registryLabel("/a/runs/../runs/registry.json"));
  assert.notEqual(registryLabel("/a/runs/registry.json"), registryLabel("/b/runs/registry.json"));
  assert.match(registryLabel("/a/runs/registry.json"), /^[0-9a-f]{16}$/);
});

test("a VM's allowlist reads the host allowlist's syntax (netguard-proxy.mjs): suffixes, ports and addresses become their own rules", () => {
  const hosts = ["api.openai.com", "*.blob.core.windows.net", ".googleapis.com", "mirror.example.org:8443", "10.0.0.5:3128", "PyPI.org"];
  const rules = egressRules(hosts);
  assert.deepEqual(rules, [
    { port: 443, domains: ["api.openai.com", "pypi.org"], suffixes: [".blob.core.windows.net", ".googleapis.com"], ips: [], cidrs: [] },
    { port: 3128, domains: [], suffixes: [], ips: ["10.0.0.5"], cidrs: [] },
    { port: 8443, domains: ["mirror.example.org"], suffixes: [], ips: [], cidrs: [] },
  ]);
  assert.deepEqual(tlsBypass(hosts), ["api.openai.com", "pypi.org", "*.blob.core.windows.net", "*.googleapis.com", "mirror.example.org"]);
});

test("IPv6, CIDR blocks and the host's loopback each become the rule a VM can use; a loopback entry goes through the host gateway", () => {
  const hosts = ["[2001:db8::1]:8443", "2001:db8::2", "10.0.0.0/8:8080", "[fd00::/8]:443", "127.0.0.1:8080", "[::1]:11434", "localhost:1234", "api.x.com"];
  assert.deepEqual(egressRules(hosts), [
    { port: 443, domains: ["api.x.com"], suffixes: [], ips: ["2001:db8::2"], cidrs: ["fd00::/8"] },
    { port: 8080, domains: [], suffixes: [], ips: [], cidrs: ["10.0.0.0/8"] },
    { port: 8443, domains: [], suffixes: [], ips: ["2001:db8::1"], cidrs: [] },
  ], "the VM's own loopback is not the host's, so no loopback entry is a plain rule");
  assert.deepEqual(gatewayPorts(hosts), [1234, 8080, 11434]);
  // A bare IPv6 address is not host:port: 2001:db8::1 is not host 2001:db8: on port 1.
  assert.deepEqual(parseAllowEntry("2001:db8::1"), { kind: "ip", value: "2001:db8::1", port: 443, loopback: false });
});

test("an allowlist entry a VM would read as nothing is refused with the reason", () => {
  for (const [entry, why] of [
    ["https://api.x.com", /not a URL/],
    ["api.x.com/v1", /no path/],
    ["*.com", /top-level domain/],
    ["a*.x.com", /leading \*\./],
    ["x.com:0", /1-65535/],
    ["x.com:70000", /1-65535/],
    ["300.1.1.1", /not an IPv4 address/],
    ["10.0.0.0/33", /not an IPv4 block/],
    ["[zz]:443", /not an IPv6 address/],
    ["user@x.com", /no user/],
  ] as const) {
    assert.throws(() => parseAllowEntry(entry), why, entry);
  }
});

test("TLS is terminated on every port a secret travels on, and no bypass covers a secret's host", () => {
  const allow = ["*.openai.com", "pypi.org", "api.openai.com", "*.azure.com", "*.blob.core.windows.net"];
  const secretHosts = ["api.openai.com", "*.openai.azure.com", "gw.example.com:8443"];
  assert.deepEqual(tlsBypass(allow, secretHosts), ["pypi.org", "*.blob.core.windows.net"], "*.openai.com and *.azure.com would carry a placeholder past the swap");
  assert.deepEqual(interceptPorts(secretHosts), [443, 8443]);
  assert.equal(bypassCovers("*.openai.com", "openai.com"), true, "a suffix covers its apex, as msb matches it");
  assert.equal(bypassCovers("*.openai.com", "notopenai.com"), false);
});

test("a provider's env block crosses with its settings as they are and its credentials as placeholders; host-only settings stay behind", async () => {
  const dir = await mkdtemp(join(tmpdir(), "vm-pi-env-"));
  dirs.push(dir);
  await writeFile(join(dir, "auth.json"), JSON.stringify({
    "azure": {
      type: "api_key",
      key: "REAL-AZURE-KEY",
      env: { AZURE_OPENAI_BASE_URL: "https://res.openai.azure.com", AZURE_OPENAI_API_VERSION: "2025-04-01", AZURE_OPENAI_API_KEY: "REAL-ENV-KEY" },
    },
  }));
  await writeFile(join(dir, "settings.json"), JSON.stringify({ defaultThinkingLevel: "low", httpProxy: "http://proxy.corp:3128", packages: ["/host/only"], shellPath: "/bin/zsh" }));
  const s = spec({ pi_agent_dir: dir, providers: [{ provider: "azure", kind: "api_key", hosts: ["res.openai.azure.com"] }] });
  const key = placeholderFor("azure", "api_key");
  const secrets: ResolvedSecret[] = [
    { provider: "azure", kind: "api_key", placeholder: key, value: "REAL-AZURE-KEY", hosts: ["res.openai.azure.com"] },
    { provider: "azure", kind: "api_key", placeholder: "dfirswarm-secret-envkey-x", value: "REAL-ENV-KEY", hosts: ["res.openai.azure.com"], envKey: "AZURE_OPENAI_API_KEY" },
  ];
  const cfg = guestPiConfig(s, secrets);
  assert.ok(!`${cfg.auth}${cfg.settings}`.includes("REAL-"), "no credential in the guest's files");
  const auth = JSON.parse(cfg.auth)["azure"];
  assert.equal(auth.key, key);
  assert.equal(auth.env.AZURE_OPENAI_BASE_URL, "https://res.openai.azure.com", "the resource travels: Pi needs it to build the URL");
  assert.equal(auth.env.AZURE_OPENAI_API_VERSION, "2025-04-01");
  assert.equal(auth.env.AZURE_OPENAI_API_KEY, "dfirswarm-secret-envkey-x", "a credential in the env block is its placeholder");
  const settings = JSON.parse(cfg.settings ?? "{}");
  assert.equal(settings.defaultThinkingLevel, "low");
  for (const k of ["httpProxy", "packages", "shellPath"]) assert.equal(settings[k], undefined, `${k} names this host and stays behind`);
});

test("resolving secrets: an env-block credential and a header credential get placeholders; a header Pi resolves at request time is refused", async () => {
  const dir = await mkdtemp(join(tmpdir(), "vm-pi-res-"));
  dirs.push(dir);
  // A stand-in for `pi auth print-api-key`: every provider has the key "REAL-KEY".
  const fakePi = join(dir, "pi");
  await writeFile(fakePi, "#!/bin/sh\necho REAL-KEY\n", { mode: 0o755 });
  await writeFile(join(dir, "auth.json"), JSON.stringify({
    gw: { type: "api_key", key: "REAL-KEY", env: { GW_REGION: "eu", GW_TOKEN: "REAL-ENV-TOKEN" } },
  }));
  await writeFile(join(dir, "models.json"), JSON.stringify({
    providers: { gw: { baseUrl: "https://gw.example/v1", api: "openai-completions", apiKey: "REAL-KEY", headers: { "x-api-key": "REAL-HEADER-KEY", "x-trace": "on" }, models: [{ id: "m" }] } },
  }));
  const s = spec({ pi_agent_dir: dir, pi_bin: fakePi, providers: [{ provider: "gw", kind: "api_key", hosts: ["gw.example"] }] });
  const secrets = await resolveSecrets(s);
  assert.deepEqual(secrets.map((x) => x.envKey ?? "key").sort(), ["GW_TOKEN", "header:x-api-key", "key"]);
  assert.ok(secrets.every((x) => x.hosts.length === 1 && x.hosts[0] === "gw.example"), "every one is bound to the provider's host");
  const cfg = guestPiConfig(s, secrets);
  assert.ok(!`${cfg.auth}${cfg.models}`.includes("REAL-"), "nothing real crosses");
  const models = JSON.parse(cfg.models ?? "{}");
  assert.equal(models.providers.gw.headers["x-api-key"], secrets.find((x) => x.envKey === "header:x-api-key")?.placeholder);
  assert.equal(models.providers.gw.headers["x-trace"], "on", "a header that is not a credential travels as it is");
  await writeFile(join(dir, "models.json"), JSON.stringify({
    providers: { gw: { baseUrl: "https://gw.example/v1", api: "openai-completions", apiKey: "REAL-KEY", headers: { Authorization: "!op read secret" }, models: [{ id: "m" }] } },
  }));
  await assert.rejects(resolveSecrets(s), /resolved by Pi at request time/);
});

test("a seat's VM gets the providers of its own model and the summary model, and every local one", () => {
  const s = spec({
    providers: [
      { provider: "openai", kind: "api_key", hosts: ["api.openai.com"] },
      { provider: "deepseek", kind: "api_key", hosts: ["api.deepseek.com"] },
      { provider: "google", kind: "api_key", hosts: ["generativelanguage.googleapis.com"] },
      { provider: "lmstudio", kind: "local", hosts: [], port: 1234 },
    ],
    env: { SWARM_COMPACT_MODEL: "google/gemini" },
    agents: [{ id: "a0", model: "openai/gpt" }, { id: "a1", model: "deepseek/chat" }],
  });
  assert.deepEqual(seatProviders(s, s.agents[0]).map((p) => p.provider), ["openai", "google", "lmstudio"]);
  assert.deepEqual(seatProviders(s, s.agents[1]).map((p) => p.provider), ["deepseek", "google", "lmstudio"]);
});

test("a pack's needs come from its installed directory: its version, its seal and the programs it requires", async () => {
  const dir = await mkdtemp(join(tmpdir(), "vm-packneed-"));
  dirs.push(dir);
  const { mkdir } = await import("node:fs/promises");
  await mkdir(join(dir, "requires"), { recursive: true });
  await writeFile(join(dir, "pack.json"), JSON.stringify({ id: "demo", version: "1.2.3", checksums: { sha256: { "b.md": "22", "a.md": "11" } } }));
  // Another system's program (not_in_image) is asked of no image, even unmarked optional.
  await writeFile(join(dir, "requires", "host.json"), JSON.stringify({ binaries: [{ name: "fls" }, { name: "vol", optional: true }, { name: "fls" }, { name: "log", not_in_image: "Only macOS has it." }] }));
  const [need] = packNeeds([dir]);
  assert.deepEqual({ ...need, seal: undefined }, { id: "demo", version: "1.2.3", seal: undefined, required: ["fls"] });
  // The seal is the sha256 of the sorted checksums, as images/recipe.py computes it.
  const { createHash } = await import("node:crypto");
  assert.equal(need.seal, createHash("sha256").update('{"a.md":"11","b.md":"22"}').digest("hex"));
  assert.equal(packSeal({ checksums: { sha256: { "a.md": "11", "b.md": "22" } } }), need.seal, "key order does not change the seal");
});

test("an image that lacks a pack's required program stops the kickoff, unless the agents may install; another pack version is said", () => {
  const needs = [
    { id: "cfb", version: "1.2.2", seal: "s1", required: ["fls", "icat"] },
    { id: "mem", version: "1.0.1", seal: "s2", required: [] },
  ];
  const probe = { missing_binaries: ["icat"], image: { pack_versions: { cfb: { version: "1.2.1", seal: "old" } } } };
  const closed = imageFit(probe, needs, false);
  assert.equal(closed.blockers.length, 1);
  assert.match(closed.blockers[0], /lacks icat, which pack cfb requires/);
  assert.ok(closed.warnings.some((w) => /built with cfb 1\.2\.1 \(another seal\); this run has 1\.2\.2/.test(w)), closed.warnings.join("\n"));
  assert.ok(closed.warnings.some((w) => /not built with pack mem/.test(w)), closed.warnings.join("\n"));
  const open = imageFit(probe, needs, true);
  assert.deepEqual(open.blockers, []);
  assert.ok(open.warnings.some((w) => /agents may install it/.test(w)));
  // An image from before the record: said once, not a blocker.
  const old = imageFit({ missing_binaries: [], image: { profile: "disk" } }, needs, false);
  assert.deepEqual(old.blockers, []);
  assert.deepEqual(old.warnings, ["the image records no pack versions (built before images recorded them): which version of each pack it was built for is unknown"]);
  assert.deepEqual(imageFit({ image: {} }, [], false), { blockers: [], warnings: [] }, "a run with no packs asks nothing of the image");
  // Agents on the base, the packs' programs in the job images: the base is
  // not held to them, and nobody is told to install them there.
  assert.deepEqual(imageFit({ missing_binaries: ["fls", "icat"], image: { profile: "base", pack_versions: {} } }, needs, true, true), { blockers: [], warnings: [] });
  assert.deepEqual(imageFit({ missing_binaries: ["fls", "icat"], image: { profile: "base", pack_versions: {} } }, needs, false, true).blockers, [], "nor stopped for it");
});

test("an image's record that lacks the data its packs pin, or did not index it, is said at kickoff", () => {
  assert.deepEqual(imageDataWarnings({ profile: "memory", not_installed: { data: [] }, downloads: { "vol-windows-symbols": { kind: "data", warm: "done" } } }), []);
  assert.deepEqual(imageDataWarnings(null), []);
  assert.deepEqual(imageDataWarnings("not a record"), []);
  const lacking = imageDataWarnings({ profile: "memory", not_installed: { data: [{ name: "vol-windows-symbols", pack: "memory-forensics", why: "download failed: timed out" }] } });
  assert.equal(lacking.length, 1);
  assert.match(lacking[0], /the memory image lacks the data vol-windows-symbols that pack memory-forensics pins \(download failed: timed out\)/);
  assert.match(lacking[0], /not an absence in the evidence/);
  const omitted = imageDataWarnings({ profile: "memory", not_installed: { data: [] }, omitted: { data: [{ name: "vol-isf-x", pack: "memory-forensics", why: "--symbol-set none: the curated set is left out" }] } });
  assert.equal(omitted.length, 1);
  assert.match(omitted[0], /built without the data vol-isf-x that pack memory-forensics pins \(--symbol-set none: the curated set is left out\)/);
  const cold = imageDataWarnings({ profile: "memory", downloads: { "vol-windows-symbols": { kind: "data", warm: "failed" }, memprocfs: { kind: "download" } } });
  assert.equal(cold.length, 1);
  assert.match(cold[0], /holds the data vol-windows-symbols but did not index it at build/);
  // The agent VM's own image is read the same way.
  const fit = imageFit({ missing_binaries: [], image: { profile: "memory", pack_versions: {}, not_installed: { data: [{ name: "vol-windows-symbols", pack: "memory-forensics", why: "x" }] } } }, [], false);
  assert.deepEqual(fit.blockers, [], "a missing data file warns, it does not stop the run");
  assert.ok(fit.warnings.some((w) => /lacks the data vol-windows-symbols/.test(w)), fit.warnings.join("\n"));
});

test("a host msb does not run on is refused by name, before msb is asked", () => {
  // null, not undefined: undefined is a left-out argument, and a left-out
  // glibc is read from the host (a Linux CI runner has one).
  assert.equal(vmPlatformProblem("darwin", "arm64", null), null);
  assert.match(vmPlatformProblem("darwin", "x64", null) ?? "", /Apple silicon; this Mac is Intel/);
  assert.equal(vmPlatformProblem("linux", "x64", "2.36"), null);
  assert.match(vmPlatformProblem("linux", "x64", null) ?? "", /not glibc \(musl\?\)/);
  assert.match(vmPlatformProblem("win32", "x64", null) ?? "", /this host is win32/);
  assert.match(vmPlatformProblem("linux", "ppc64", "2.36") ?? "", /x64 or arm64/);
});

test("N VMs of a size are refused past 85% of the host's memory or four times its cores, and warned about past 60% or its cores", () => {
  const host = { mem_mib: 16384, cpus: 8 };
  assert.deepEqual(capacityVerdict(4, 2, 2048, host), { blockers: [], warnings: [] });
  const warm = capacityVerdict(5, 2, 2048, host);
  assert.equal(warm.blockers.length, 0);
  assert.match(warm.warnings.join("\n"), /10240 of this host's 16384 MiB/);
  assert.match(warm.warnings.join("\n"), /10 vCPUs on 8 cores/);
  assert.match(capacityVerdict(30, 1, 1024 * 1024, host).blockers.join("\n"), /need 31457280 MiB, and this host has 16384 MiB/);
  assert.match(capacityVerdict(20, 2, 512, host).blockers.join("\n"), /40 vCPUs on 8 cores/);
});

test("a worker starts only while the host keeps 15% of its memory free beside it; memory that cannot be read does not hold jobs back", () => {
  const host = { mem_mib: 131072, available_mib: 30000 };
  assert.deepEqual(roomForWorker(4096, host), { ok: true, available_mib: 30000, needed_mib: 4096 + 19661 });
  assert.equal(roomForWorker(4096, { ...host, available_mib: 23000 }).ok, false, "three runs on one Mac: no room for a fourth worker");
  assert.equal(roomForWorker(4096, { ...host, available_mib: null }).ok, true);
  // On this host, whatever it is, the figure is a number of MiB or unreadable.
  const now = hostAvailableMib();
  assert.ok(now === null || (Number.isInteger(now) && now >= 0), String(now));
});

test("a seat's probe tries each model host it needs: a local model through the gateway, a named host on its port", async () => {
  const { probeTargets } = await import("../scripts/vm.ts");
  assert.deepEqual(
    probeTargets([
      { provider: "openai", kind: "api_key", hosts: ["api.openai.com"] },
      { provider: "ollama", kind: "local", hosts: [], port: 11434 },
      { provider: "lan", kind: "local", hosts: ["10.0.0.5:8000"], port: 8000 },
      { provider: "v6", kind: "local", hosts: ["[fd00::5]:9000"], port: 9000 },
      { provider: "suffixonly", kind: "api_key", hosts: [".example.com"] },
    ]),
    ["10.0.0.5:8000", "[fd00::5]:9000", "api.openai.com:443", "host.microsandbox.internal:11434"],
  );
});

test("a credential header is found at every depth Pi reads one, and a local model's real key is refused", async () => {
  const { credentialHeaders, isLoopbackIp } = await import("../scripts/vm.ts");
  const config = {
    headers: { "X-Api-Key": "k1", Accept: "json" },
    models: [{ id: "m", headers: { Authorization: "Bearer k2" } }],
    modelOverrides: { big: { headers: { "x-session-token": "k3" } } },
  };
  assert.deepEqual(credentialHeaders(config).map((h) => h.value).sort(), ["Bearer k2", "k1", "k3"]);
  assert.equal(isLoopbackIp("0.0.0.0"), true, "a server bound to every interface is reached on loopback");
  assert.equal(isLoopbackIp("10.0.0.1"), false);
});

test("a finish leaves no byte of a removed VM's secret in msb's database", async (t) => {
  try {
    execFileSync("sh", ["-c", "command -v sqlite3"], { stdio: "ignore" });
  } catch {
    t.skip("no sqlite3 on this host");
    return;
  }
  const home = await mkdtemp(join(tmpdir(), "msb-home-"));
  after(() => rm(home, { recursive: true, force: true }));
  const db = join(home, "db", "msb.db");
  execFileSync("mkdir", ["-p", join(home, "db")]);
  const value = `sk-test-${Date.now().toString(36)}-never-kept`;
  // As msb keeps it: WAL, a live VM's row and a removed one's, and no secure
  // delete (msb's own SQLite has none; a distribution's sqlite3 may).
  execFileSync("sqlite3", [
    db,
    `PRAGMA secure_delete=OFF; PRAGMA journal_mode=WAL; CREATE TABLE sandbox(name TEXT, config TEXT); INSERT INTO sandbox VALUES ('live', '{"env":{}}'); INSERT INTO sandbox VALUES ('gone', '{"secret":"${value}"}'); DELETE FROM sandbox WHERE name='gone';`,
  ]);
  const held = () =>
    ["msb.db", "msb.db-wal"].some((f) => {
      try {
        return readFileSync(join(home, "db", f)).includes(value);
      } catch {
        return false;
      }
    });
  assert.ok(held(), "the removed row's bytes are in the database before the scrub, as measured with msb");
  const before = process.env.MSB_HOME;
  process.env.MSB_HOME = home;
  try {
    assert.equal(await scrubMsbDatabase(), "scrubbed");
  } finally {
    if (before === undefined) delete process.env.MSB_HOME;
    else process.env.MSB_HOME = before;
  }
  assert.ok(!held(), "the removed row's bytes outlived the scrub");
  assert.equal(execFileSync("sqlite3", [db, "SELECT name FROM sandbox"], { encoding: "utf8" }).trim(), "live", "the live row is kept");
  process.env.MSB_HOME = join(home, "nothing-here");
  try {
    assert.equal(await scrubMsbDatabase(), "no database");
  } finally {
    if (before === undefined) delete process.env.MSB_HOME;
    else process.env.MSB_HOME = before;
  }
});

test("a scrub a reader held back is busy, not scrubbed: the removed row's bytes are still there", async (t) => {
  try {
    execFileSync("sh", ["-c", "command -v sqlite3 && command -v python3"], { stdio: "ignore" });
  } catch {
    t.skip("no sqlite3 or python3 on this host");
    return;
  }
  // sqlite3's own answer rows: busy|log|checkpointed, then the free pages.
  assert.equal(scrubCompleted("3000\n0|0|0\n0|0|0\n0\n"), true);
  assert.equal(scrubCompleted("3000\n0|-1|-1\n0|-1|-1\n0\n"), true, "a database not in WAL mode has no log to checkpoint");
  assert.equal(scrubCompleted("3000\n0|4|4\n1|12|3\n0\n"), false, "a checkpoint a reader held back");
  assert.equal(scrubCompleted("3000\n0|4|4\n0|12|3\n0\n"), false, "a log not wholly checkpointed");
  assert.equal(scrubCompleted("3000\n0|0|0\n0|0|0\n2\n"), false, "free pages left");
  assert.equal(scrubCompleted(""), false);
  const home = await mkdtemp(join(tmpdir(), "msb-home-"));
  after(() => rm(home, { recursive: true, force: true }));
  const db = join(home, "db", "msb.db");
  execFileSync("mkdir", ["-p", join(home, "db")]);
  const value = `sk-test-${Date.now().toString(36)}-held`;
  // A live msb's pool can hold a read transaction: here a second connection
  // that keeps one open until told to let go.
  const reader = spawn(
    "python3",
    [
      "-c",
      `import sqlite3, sys
c = sqlite3.connect(sys.argv[1], isolation_level=None)
c.execute("PRAGMA secure_delete=OFF"); c.execute("PRAGMA journal_mode=WAL"); c.execute("PRAGMA wal_autocheckpoint=0")
c.execute("CREATE TABLE sandbox(name TEXT, config TEXT)")
c.execute("INSERT INTO sandbox VALUES ('live', '{}')")
c.execute("INSERT INTO sandbox VALUES ('gone', ?)", (sys.argv[2],))
c.execute("DELETE FROM sandbox WHERE name='gone'")
r = sqlite3.connect(sys.argv[1], isolation_level=None)
r.execute("BEGIN"); r.execute("SELECT count(*) FROM sandbox").fetchall()
print("ready", flush=True)
sys.stdin.read()
r.execute("COMMIT")`,
      db,
      value,
    ],
    { stdio: ["pipe", "pipe", "inherit"] },
  );
  await new Promise<void>((resolve, reject) => {
    reader.stdout.on("data", (d: Buffer) => d.toString().includes("ready") && resolve());
    reader.on("exit", (code) => reject(new Error(`the reader exited ${code} before it held a snapshot`)));
  });
  const before = process.env.MSB_HOME;
  process.env.MSB_HOME = home;
  try {
    assert.equal(await scrubMsbDatabase(), "busy", "a scrub a reader held back said scrubbed");
    reader.stdin.end();
    await new Promise((r) => reader.on("exit", r));
    assert.equal(await scrubMsbDatabase(), "scrubbed", "once the reader let go the scrub completes");
  } finally {
    reader.kill();
    if (before === undefined) delete process.env.MSB_HOME;
    else process.env.MSB_HOME = before;
  }
  for (const f of ["msb.db", "msb.db-wal"]) {
    let bytes = Buffer.alloc(0);
    try {
      bytes = readFileSync(join(home, "db", f));
    } catch {
      // a truncated log may be gone
    }
    assert.ok(!bytes.includes(value), `${f} still holds the removed row after the scrub completed`);
  }
});

test("a seat's hub token comes from the run's seat-tokens file, never the spec, and a seat without a good one is an error", async () => {
  const dir = await mkdtemp(join(tmpdir(), "seat-tokens-"));
  after(() => rm(dir, { recursive: true, force: true }));
  const file = join(dir, "seat-tokens.json");
  await writeFile(file, JSON.stringify({ s1a2b00: "0123456789abcdef0123456789abcdef", s1a2b01: "short" }), { mode: 0o600 });
  assert.equal(seatTokenFor({ seat_tokens_file: file }, "s1a2b00"), "0123456789abcdef0123456789abcdef");
  assert.throws(() => seatTokenFor({ seat_tokens_file: file }, "s1a2b01"), /no hub token for s1a2b01/, "a malformed token is refused");
  assert.throws(() => seatTokenFor({ seat_tokens_file: file }, "s1a2b02"), /no hub token for s1a2b02/, "a seat the file does not name is refused");
  assert.equal(seatTokenFor({}, "s1a2b00"), null, "a run without tokens (an older kickoff) has none");
  // The error names the seat, never a token.
  try {
    seatTokenFor({ seat_tokens_file: file }, "s1a2b01");
  } catch (err) {
    assert.doesNotMatch(String(err), /0123456789abcdef/);
  }
});

test("the VM's probe walks each set held in place through its link, probes each set's own mount, and counts one set as it always did", async () => {
  // The probe's evidence check, as the guest runs it; the write and no-exec
  // probes are stand-ins that say what they were asked about.
  const block = PROBE_SCRIPT.match(/inputs = os\.path\.join\(S, "inputs"\)\n[\s\S]*?\nelse:\n {4}out\["inputs"\] = "absent"\n/);
  assert.ok(block, "the probe's evidence check was not found");
  const dir = await mkdtemp(join(tmpdir(), "probe-sets-"));
  after(() => rm(dir, { recursive: true, force: true }));
  const ev = join(dir, "ev");
  await mkdir(join(ev, "laptop", "users"), { recursive: true });
  await mkdir(join(ev, "phone"), { recursive: true });
  await writeFile(join(ev, "laptop", "users", "ntuser.dat"), "hive");
  await symlink("users/ntuser.dat", join(ev, "laptop", "hive-link"));
  await writeFile(join(ev, "phone", "sms.db"), "sqlite");
  const probe = async (S: string, sets?: string[]): Promise<{ out: { inputs?: string; inputs_files?: number; inputs_exec?: string; inputs_pristine?: string; inputs_pristine_exec?: string }; probed: Array<[string, string]> }> => {
    const py = `import json, os\nS = ${JSON.stringify(S)}\nout = {}\nprobed = []\ndef can_write(path):\n    probed.append(["w", path])\n    return "ro"\ndef mount_noexec(path):\n    probed.append(["x", path])\n    return "noexec"\n${block![0]}print(json.dumps({"out": out, "probed": probed}))\n`;
    const env = { ...process.env, SWARM_INPUT_SETS: sets ? JSON.stringify(sets) : "" };
    return JSON.parse(execFileSync("python3", ["-c", py], { encoding: "utf8", env }));
  };
  // Two sets held in place: inputs/ holds a link per set, each set its own
  // mount, and the kickoff names them to the VM (it does not read inputs.json).
  const two = join(dir, "two");
  await mkdir(join(two, "inputs"), { recursive: true });
  await symlink(join(ev, "laptop"), join(two, "inputs", "laptop"));
  await symlink(join(ev, "phone"), join(two, "inputs", "phone"));
  const got = await probe(two, ["laptop", "phone", "../etc", "gone"]);
  assert.equal(got.out.inputs_files, 3, "a file in each set and a link inside one, and neither set's own link");
  assert.equal(got.out.inputs, "ro");
  assert.equal(got.out.inputs_exec, "noexec");
  const laptop = await realpath(join(ev, "laptop"));
  const phone = await realpath(join(ev, "phone"));
  for (const want of [["w", join(laptop, ".vm-probe")], ["w", join(phone, ".vm-probe")], ["x", join(laptop, ".probe")], ["x", join(phone, ".probe")]]) {
    assert.ok(got.probed.some((p) => p[0] === want[0] && p[1] === want[1]), `the probe did not ask about ${want.join(" ")}: ${JSON.stringify(got.probed)}`);
  }
  // One set held in place: inputs/ is the link, as it always was, and
  // there is no pristine clone to ask about.
  const one = join(dir, "one");
  await mkdir(one, { recursive: true });
  await symlink(join(ev, "laptop"), join(one, "inputs"));
  const single = await probe(one);
  assert.equal(single.out.inputs_files, 2);
  assert.deepEqual(single.probed, [["w", join(laptop, ".vm-probe")], ["x", join(laptop, ".probe")]]);
  assert.ok(!("inputs_pristine" in single.out) && !("inputs_pristine_exec" in single.out), "in place, nothing is measured for a clone that is not there");
  // A copy (--inputs-copy): inputs/ is the run's own directory and
  // .inputs-pristine/ its clone, each its own mount over the floor (run
  // s8760fa: the probe asked about the floor's mount, which is not no-exec,
  // and every seat was refused). The probe asks about the mount that holds
  // each, and about the clone as well.
  const copy = join(dir, "copy");
  await mkdir(join(copy, "inputs", "users"), { recursive: true });
  await mkdir(join(copy, ".inputs-pristine", "users"), { recursive: true });
  for (const d of ["inputs", ".inputs-pristine"]) await writeFile(join(copy, d, "users", "ntuser.dat"), "hive");
  const copied = await probe(copy);
  const copyReal = await realpath(copy);
  assert.equal(copied.out.inputs_files, 1, "the clone is not counted among the evidence's names");
  assert.equal(copied.out.inputs, "ro");
  assert.equal(copied.out.inputs_exec, "noexec");
  assert.deepEqual(copied.probed, [
    ["w", join(copyReal, "inputs", ".vm-probe")],
    ["x", join(copyReal, "inputs", ".probe")],
    ["w", join(copyReal, ".inputs-pristine", ".vm-probe")],
    ["x", join(copyReal, ".inputs-pristine", ".probe")],
  ], "the copy's own mount and the clone's are the ones asked about, not the floor's");
  assert.equal(copied.out.inputs_pristine, "ro");
  assert.equal(copied.out.inputs_pristine_exec, "noexec");
});

test("the VM's probe shows its seat's token before anything else on the hub socket, and nothing when the run has none", async () => {
  // The probe's hub check, as the guest runs it, against a socket here.
  const block = PROBE_SCRIPT.match(/out\["hub"\] = False\nfor attempt in range\(\d+\):[\s\S]*?out\["hub_attempts"\] = attempt \+ 1\n/);
  assert.ok(block, "the probe's hub check was not found");
  const dir = await mkdtemp(join("/tmp", "probe-auth-"));
  after(() => rm(dir, { recursive: true, force: true }));
  const sock = join(dir, "hub.sock");
  const net = await import("node:net");
  const run = async (token: string | undefined): Promise<{ lines: string[]; out: { hub?: boolean } }> => {
    const lines: string[] = [];
    const server = net.createServer((c) => {
      let buf = "";
      c.on("data", (d) => {
        buf += d.toString();
        let i;
        while ((i = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, i);
          buf = buf.slice(i + 1);
          lines.push(line);
          if (JSON.parse(line).t === "rpc") c.end('{"ok":true,"result":false}\n');
        }
      });
    });
    await new Promise<void>((r) => server.listen(sock, r));
    const py = `import json, os, socket, time\nout = {}\n${block![0].replaceAll(GUEST_HUB_SOCKET, sock)}print(json.dumps(out))\n`;
    const out = await new Promise<string>((resolve, reject) => {
      const child = spawn("python3", ["-c", py], { env: { ...process.env, SWARM_SEAT_TOKEN: token ?? "" } });
      let text = "";
      child.stdout.on("data", (d) => (text += d));
      child.on("error", reject);
      child.on("close", () => resolve(text));
    });
    await new Promise<void>((r) => server.close(() => r()));
    return { lines, out: JSON.parse(out.trim().split("\n").pop() ?? "{}") };
  };
  const withToken = await run("0123456789abcdef0123456789abcdef");
  assert.deepEqual(JSON.parse(withToken.lines[0]), { t: "auth", token: "0123456789abcdef0123456789abcdef" }, "the auth line is first");
  assert.equal(JSON.parse(withToken.lines[1]).t, "rpc");
  assert.equal(withToken.out.hub, true);
  const without = await run(undefined);
  assert.equal(JSON.parse(without.lines[0]).t, "rpc", "no auth line when the run has no tokens");
  assert.equal(without.lines.length, 1);
});


test("the VM's probe asks the hub again when a connection closes with no answer, and says so when it never answers", async () => {
  // Sixth CTF round: with eighteen VMs running and a third run coming up, two
  // seats of eight had their first connection close with nothing said, twice,
  // and the kickoff stopped with "no answer" and nothing more.
  const block = PROBE_SCRIPT.match(/out\["hub"\] = False\nfor attempt in range\(\d+\):[\s\S]*?out\["hub_attempts"\] = attempt \+ 1\n/);
  assert.ok(block, "the probe's hub check was not found");
  const dir = await mkdtemp(join("/tmp", "probe-retry-"));
  after(() => rm(dir, { recursive: true, force: true }));
  const sock = join(dir, "hub.sock");
  const net = await import("node:net");
  const probe = async (silentFor: number): Promise<{ hub?: boolean; hub_error?: string; hub_attempts?: number }> => {
    let seen = 0;
    const server = net.createServer((c) => {
      seen += 1;
      if (seen <= silentFor) {
        c.destroy();
        return;
      }
      c.on("data", (d) => {
        if (d.toString().includes('"rpc"')) c.end('{"ok":true,"result":false}\n');
      });
    });
    await new Promise<void>((r) => server.listen(sock, r));
    const py = `import json, os, socket, time\nout = {}\n${block![0].replaceAll(GUEST_HUB_SOCKET, sock).replace(/time\.sleep\(\d+\)/, "time.sleep(0)")}print(json.dumps(out))\n`;
    const out = await new Promise<string>((resolve, reject) => {
      const child = spawn("python3", ["-c", py], { env: { ...process.env, SWARM_SEAT_TOKEN: "" } });
      let text = "";
      child.stdout.on("data", (d) => (text += d));
      child.on("error", reject);
      child.on("close", () => resolve(text));
    });
    await new Promise<void>((r) => server.close(() => r()));
    return JSON.parse(out.trim().split("\n").pop() ?? "{}");
  };
  const second = await probe(1);
  assert.equal(second.hub, true, "a hub that answers the second connection is reachable");
  assert.equal(second.hub_attempts, 2);
  assert.equal(second.hub_error, undefined, "a hub reached in the end leaves no error behind");
  const never = await probe(99);
  assert.equal(never.hub, false);
  assert.equal(never.hub_attempts, 5);
  // A close with nothing said reads as a clean close on macOS, and on Linux
  // as a reset or, when the close beats the send, a broken pipe: all three
  // are said the same way, with the error kept beside it.
  assert.match(String(never.hub_error), /^the connection closed with no answer( \(.*(Connection reset by peer|Broken pipe)\))?$/, "a hub that never answers is said to have said nothing");
});

test("without --model-gateway a seat's VM plan is today's; with it a fronted provider is reached through the gateway and nothing of its credential is in the VM", async () => {
  const dir = await mkdtemp(join(tmpdir(), "gw-plan-"));
  after(() => rm(dir, { recursive: true, force: true }));
  // The operator's Pi: a custom entry for openai with a credential header
  // (whose value the VM must not get) and a setting it may.
  await writeFile(join(dir, "models.json"), JSON.stringify({ providers: { openai: { headers: { "X-Org-Token": "real-header-value", "X-Team": "forensics" } } } }));
  await writeFile(join(dir, "auth.json"), JSON.stringify({ openai: { type: "api_key", key: "sk-real-openai" }, openrouter: { type: "api_key", key: "sk-real-openrouter" } }));
  const base = spec({
    pi_agent_dir: dir,
    agents: [
      { id: "s1a2b00", model: "openai/gpt-5.4-mini" },
      { id: "s1a2b01", model: "openrouter/some-model" },
    ],
    providers: [
      { provider: "openai", kind: "api_key", hosts: ["api.openai.com"] },
      { provider: "openrouter", kind: "api_key", hosts: ["openrouter.ai"] },
    ],
  });
  const secrets: ResolvedSecret[] = [
    { provider: "openai", kind: "api_key", placeholder: "dfirswarm-secret-openai-aaaaaaaaaaaaaaaaaaaaaaaa", value: "sk-real-openai", hosts: ["api.openai.com"] },
    { provider: "openai", kind: "api_key", placeholder: "dfirswarm-secret-openaihdr-bbbbbbbbbbbbbbbbbbbbbbbb", value: "real-header-value", hosts: ["api.openai.com"], envKey: "header:X-Org-Token" },
    { provider: "openrouter", kind: "api_key", placeholder: "dfirswarm-secret-openrouter-cccccccccccccccccccccccc", value: "sk-real-openrouter", hosts: ["openrouter.ai"] },
  ];
  // Off: the plan is exactly what createOne worked out before the gateway.
  const off = seatPlan(base, base.agents[0], secrets, null);
  assert.deepEqual(off.fronted, []);
  assert.deepEqual(off.secrets.map((x) => x.placeholder).sort(), secrets.filter((x) => x.provider === "openai").map((x) => x.placeholder).sort());
  assert.deepEqual(off.allowHosts, ["api.openai.com"]);
  assert.deepEqual(off.hostPorts, []);
  assert.deepEqual(off.piConfig, guestPiConfig({ ...base, providers: [base.providers[0]] }, secrets.filter((x) => x.provider === "openai")));
  // On: the gateway fronts openai (not openrouter).
  const gateway: GatewayConfig = {
    v: 1,
    run: "s1a2b",
    sandbox: base.sandbox,
    seats: {
      s1a2b00: { token: "seat-token-00", model: "openai/gpt-5.4-mini", providers: ["openai"] },
      s1a2b01: { token: "seat-token-01", model: "openrouter/some-model", providers: [] },
    },
    providers: { openai: { upstream: "https://api.openai.com", base_path: "/v1", api: "openai-responses", auth_header: "authorization", key: { source: "pi", provider: "openai" } } },
  };
  const gw = { ...base, model_gateway: { port: 47123, config: "/hub/model-gateway.json", declined: [{ provider: "openrouter", reason: "not fronted" }] } };
  const on = seatPlan(gw, gw.agents[0], secrets, gateway);
  assert.deepEqual(on.fronted, ["openai"]);
  assert.deepEqual(on.secrets, [], "no msb secret for a fronted provider");
  assert.ok(!on.allowHosts.includes("api.openai.com"), "the VM does not reach the provider's host");
  assert.deepEqual(on.hostPorts, [47123], "it reaches the gateway's port through msb's host gateway");
  assert.deepEqual(on.probeTargets, ["host.microsandbox.internal:47123"]);
  const models = JSON.parse(on.piConfig.models ?? "{}");
  assert.equal(models.providers.openai.baseUrl, "http://host.microsandbox.internal:47123/p/openai/api.openai.com/v1");
  assert.equal(models.providers.openai.apiKey, "seat-token-00", "the key Pi sends is the seat's gateway token");
  assert.deepEqual(models.providers.openai.headers, { "X-Team": "forensics" }, "the credential header goes, the setting stays");
  assert.equal(JSON.parse(on.piConfig.auth).openai, undefined, "no stored credential for a fronted provider (it would win over models.json)");
  const all = JSON.stringify(on);
  for (const real of ["sk-real-openai", "real-header-value", "dfirswarm-secret-openai"]) assert.ok(!all.includes(real), `${real} reached the VM's plan`);
  // A provider the gateway does not front keeps the placeholder path.
  const other = seatPlan(gw, gw.agents[1], secrets, gateway);
  assert.deepEqual(other.fronted, []);
  assert.deepEqual(other.secrets.map((x) => x.provider), ["openrouter"]);
  assert.deepEqual(other.allowHosts, ["openrouter.ai"]);
  assert.deepEqual(other.hostPorts, []);
  assert.equal(JSON.parse(other.piConfig.auth).openrouter.key, "dfirswarm-secret-openrouter-cccccccccccccccccccccccc");
});

test("each probe check has a name, what it wants, what was found, whether it holds and what that means; the kickoff's verdict is the failed ones' meanings", () => {
  const good = {
    hub: true, base: "ro", work: "ro", scratch: "rw", extracted: "rw", extracted_exec: "noexec", quarantine_exec: "noexec",
    peers_extracted_exec: "noexec", peers_quarantine_exec: "noexec", tool_output: "rw", session: "rw", inputs: "ro", inputs_exec: "noexec",
    inputs_files: 2, pi: "0.87.0", reach: [{ target: "api.openai.com:443", ok: true }],
  };
  const rows = probeChecks(good, true, 2);
  assert.ok(rows.length >= 15);
  for (const r of rows) {
    assert.ok(r.check && r.want && r.got && r.meaning, `a row lacks a field: ${JSON.stringify(r)}`);
    assert.equal(r.ok, true, `${r.check} fails on a good probe`);
  }
  assert.deepEqual(probeVerdict(good, true, 2), []);
  const bad = { ...good, work: "rw", inputs_exec: "exec", hub: false, hub_error: "no socket" };
  const failed = probeChecks(bad, true, 2).filter((r) => !r.ok);
  assert.deepEqual(failed.map((r) => r.check), ["the shared work/", "the evidence executes", "the hub"]);
  assert.deepEqual(probeVerdict(bad, true, 2), failed.map((r) => r.meaning));
  assert.equal(failed[0].meaning, "the shared work/ is rw, not read-only");
  // Not measured is said, not taken for a value.
  assert.equal(probeChecks({ hub: true }, false).find((r) => r.check === "the sandbox floor")?.got, "not measured");
});
