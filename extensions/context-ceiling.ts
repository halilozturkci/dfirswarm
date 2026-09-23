/**
 * The context ceiling and the self-compaction thresholds.
 *
 * Pure module: no Pi imports, so it runs under Pi's loader, under
 * `node --test`, and in the console's build if it ever needs the same numbers.
 *
 * Two facts drive it, both measured on real runs (docs/self-compaction-plan.md):
 *
 * - **Pi's declared window is not the real one.** `openai/gpt-5.4-mini` is
 *   declared at 400k and the provider refused a 215k-token request on the
 *   Linux run s3096; `grok-4.6` on Azure doubles its price above 200k input
 *   tokens; `gpt-5.4` and `gpt-5.5` double theirs above 272k, which is also
 *   what Pi declares for them. So the thresholds are fractions of an
 *   *effective ceiling* the harness owns, never of the declared window alone.
 * - **The wall must stay out of reach of one tool result.** On s3096 a single
 *   `wait` result was 64k tokens. The hard line therefore never sits above
 *   `declared - reserveTokens - HEADROOM_TOKENS`, whatever the operator asks.
 *
 * Defaults, as a fraction of the ceiling: notice 40%, warning 50%, compact
 * 60% (where the agent must hand off and the context is summarized).
 */

export type TokenSpec =
  | { kind: "tokens"; value: number; raw: string }
  | { kind: "percent"; value: number; raw: string };

export type ThresholdSpecs = {
  /** Awareness only: a transient heads-up with the live numbers. */
  noticeAt: string;
  /** Time to finish the current step, write the note and hand off. */
  warnAt: string;
  /** Every tool but the hand-off is blocked; compaction runs at the hand-off. */
  compactAt: string;
};

export const DEFAULT_SPECS: ThresholdSpecs = { noticeAt: "40%", warnAt: "50%", compactAt: "60%" };

/** Pi's own `compaction.reserveTokens` default, written to every sandbox's `.pi/settings.json`. */
export const RESERVE_TOKENS = 16_384;
/** Pi's own `compaction.keepRecentTokens` default: the newest history a compaction leaves untouched. */
export const KEEP_RECENT_TOKENS = 20_000;
/**
 * Room above the hard line for the tool result that lands after it and for
 * the hand-off call itself. Half of the largest single jump ever measured;
 * the page bound on `wait`/`inbox` (whole posts, 40,000 characters of post
 * text per delivery) keeps a real jump well under it.
 */
export const HEADROOM_TOKENS = 32_000;
/**
 * Where a million-token model is held for the sake of quality rather than
 * cost: nothing in the archive ever went past 262k, and the reference build
 * puts its own hard line at 30% of 1M.
 */
export const ROT_CEILING_TOKENS = 300_000;
/** What to assume when Pi does not know the window at all. */
export const FALLBACK_WINDOW_TOKENS = 128_000;

export const SPEC_HELP = "Use whole tokens (150000), k/m suffixes (150k, 0.5m), or a percentage of the ceiling (60%).";

const SPEC_RE = /^(\d+(?:\.\d+)?)\s*(k|m|%)?$/i;

export function parseTokenSpec(raw: string | undefined, label: string): TokenSpec {
  const text = (raw ?? "").trim();
  if (!text) throw new Error(`${label}: value is blank. ${SPEC_HELP}`);
  const match = SPEC_RE.exec(text);
  if (!match) throw new Error(`${label}: "${text}" is not a token count or a percentage. ${SPEC_HELP}`);
  const n = Number(match[1]);
  const suffix = (match[2] ?? "").toLowerCase();
  if (!Number.isFinite(n) || n < 0) throw new Error(`${label}: "${text}" must be a non-negative number. ${SPEC_HELP}`);
  if (suffix === "%") {
    if (n > 100) throw new Error(`${label}: "${text}" is above 100%.`);
    return { kind: "percent", value: n, raw: text };
  }
  if (suffix === "k") return { kind: "tokens", value: Math.round(n * 1_000), raw: text };
  if (suffix === "m") return { kind: "tokens", value: Math.round(n * 1_000_000), raw: text };
  if (!Number.isInteger(n)) throw new Error(`${label}: "${text}" must be a whole token count. ${SPEC_HELP}`);
  return { kind: "tokens", value: n, raw: text };
}

/** Load-time validation, before the model window is known. Throws on the first bad value. */
export function validateSpecs(specs: ThresholdSpecs): { notice: TokenSpec; warn: TokenSpec; compact: TokenSpec } {
  const notice = parseTokenSpec(specs.noticeAt, "compact notice threshold");
  const warn = parseTokenSpec(specs.warnAt, "compact warning threshold");
  const compact = parseTokenSpec(specs.compactAt, "compact threshold");
  const sameUnit = (a: TokenSpec, b: TokenSpec) => a.kind === b.kind;
  if (sameUnit(notice, warn) && notice.value > warn.value) {
    throw new Error(`the notice threshold (${notice.raw}) must not exceed the warning threshold (${warn.raw}).`);
  }
  if (sameUnit(warn, compact) && warn.value > compact.value) {
    throw new Error(`the warning threshold (${warn.raw}) must not exceed the compact threshold (${compact.raw}).`);
  }
  return { notice, warn, compact };
}

export type Ceiling = {
  /** The declared window Pi reports for the model, or the fallback when it reports none. */
  declared: number;
  /** What the thresholds are fractions of. */
  ceiling: number;
  /** Why the ceiling is what it is, in one clause for the trace and the console. */
  reason: string;
};

/**
 * The harness's own table. Matched on the model id alone, so the same model
 * behind Azure, OpenRouter or a gateway gets the same ceiling; the provider
 * is only in the reason.
 */
const CEILING_TABLE: Array<{ test: RegExp; ceiling: number; reason: string }> = [
  { test: /gpt-5\.4-mini/i, ceiling: 272_000, reason: "declared 400k, but the provider refused at ~215k plus one result on s3096; 272k measured" },
  { test: /gpt-5\.[45]/i, ceiling: 272_000, reason: "price doubles above 272k input tokens" },
  { test: /grok-4\.6/i, ceiling: 200_000, reason: "price doubles above 200k input tokens" },
  { test: /deepseek-v4/i, ceiling: ROT_CEILING_TOKENS, reason: "1M declared; held at the rot ceiling" },
];

export function effectiveCeiling(model: string | undefined, declaredWindow: number | undefined): Ceiling {
  const declared = Number.isFinite(declaredWindow) && (declaredWindow ?? 0) > 0 ? Math.floor(declaredWindow as number) : FALLBACK_WINDOW_TOKENS;
  const id = (model ?? "").trim();
  for (const row of CEILING_TABLE) {
    if (row.test.test(id)) {
      const ceiling = Math.min(declared, row.ceiling);
      return { declared, ceiling, reason: ceiling < row.ceiling ? `declared window ${declared.toLocaleString("en-US")} is below the table's ${row.ceiling.toLocaleString("en-US")}` : row.reason };
    }
  }
  if (declared > ROT_CEILING_TOKENS) return { declared, ceiling: ROT_CEILING_TOKENS, reason: `declared ${declared.toLocaleString("en-US")}; held at the rot ceiling` };
  return { declared, ceiling: declared, reason: declaredWindow ? "the declared window" : `Pi reported no window; assumed ${FALLBACK_WINDOW_TOKENS.toLocaleString("en-US")}` };
}

export type ResolvedThresholds = {
  declared: number;
  ceiling: number;
  ceilingReason: string;
  /** The most the hard line may be: `declared - reserve - headroom`, and never above the ceiling. */
  capTokens: number;
  noticeTokens: number;
  warnTokens: number;
  compactTokens: number;
  noticePct: number;
  warnPct: number;
  compactPct: number;
  /** True when a value was moved to fit; `notes` says which. */
  clamped: boolean;
  notes: string[];
};

export type ResolveResult = { ok: true; thresholds: ResolvedThresholds } | { ok: false; error: string };

function toTokens(spec: TokenSpec, ceiling: number): number {
  return spec.kind === "percent" ? Math.floor((spec.value / 100) * ceiling) : spec.value;
}

export function pctOf(tokens: number, ceiling: number): number {
  return ceiling > 0 ? (tokens / ceiling) * 100 : 0;
}

/**
 * Resolve the three specs against a model. Defaults that do not fit are
 * clamped and noted; explicit values that do not fit are refused, so an
 * operator who asked for something impossible hears about it rather than
 * getting something else.
 *
 * Explicitness is per line: `explicit` names the lines the operator set,
 * and a line it leaves out is a default that may be clamped to fit the
 * others. Without it, every line is explicit unless `fromDefaults` is set.
 */
export function resolveThresholds(
  specs: ThresholdSpecs,
  model: string | undefined,
  declaredWindow: number | undefined,
  options: { fromDefaults?: boolean; explicit?: Partial<Record<keyof ThresholdSpecs, boolean>>; reserveTokens?: number } = {},
): ResolveResult {
  const isSet = (key: keyof ThresholdSpecs) => !options.fromDefaults && (options.explicit ? options.explicit[key] === true : true);
  const set = { notice: isSet("noticeAt"), warn: isSet("warnAt"), compact: isSet("compactAt") };
  let parsed: ReturnType<typeof validateSpecs>;
  try {
    // The order check at load time is for lines the operator wrote; a
    // default out of order with them is clamped below, once in tokens.
    parsed = {
      notice: parseTokenSpec(specs.noticeAt, "compact notice threshold"),
      warn: parseTokenSpec(specs.warnAt, "compact warning threshold"),
      compact: parseTokenSpec(specs.compactAt, "compact threshold"),
    };
    if (set.notice && set.warn && parsed.notice.kind === parsed.warn.kind && parsed.notice.value > parsed.warn.value) {
      throw new Error(`the notice threshold (${parsed.notice.raw}) must not exceed the warning threshold (${parsed.warn.raw}).`);
    }
    if (set.warn && set.compact && parsed.warn.kind === parsed.compact.kind && parsed.warn.value > parsed.compact.value) {
      throw new Error(`the warning threshold (${parsed.warn.raw}) must not exceed the compact threshold (${parsed.compact.raw}).`);
    }
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
  const { declared, ceiling, reason } = effectiveCeiling(model, declaredWindow);
  const reserve = options.reserveTokens ?? RESERVE_TOKENS;
  const capTokens = Math.max(KEEP_RECENT_TOKENS + 1, Math.min(ceiling, declared - reserve - HEADROOM_TOKENS));
  const notes: string[] = [];
  let clamped = false;
  let compactTokens = toTokens(parsed.compact, ceiling);
  let warnTokens = toTokens(parsed.warn, ceiling);
  let noticeTokens = toTokens(parsed.notice, ceiling);
  const fmt = (n: number) => n.toLocaleString("en-US");

  if (compactTokens > capTokens) {
    if (!set.compact) {
      notes.push(`the default compact threshold (${parsed.compact.raw} = ${fmt(compactTokens)}) is above what this ${fmt(declared)}-token window can hold; clamped to ${fmt(capTokens)}`);
      compactTokens = capTokens;
      clamped = true;
    } else {
      return { ok: false, error: `the compact threshold ${parsed.compact.raw} (${fmt(compactTokens)} tokens) is above the ${fmt(capTokens)} this ${fmt(declared)}-token window can hold once ${fmt(reserve)} reserve and ${fmt(HEADROOM_TOKENS)} headroom are kept.` };
    }
  }
  if (compactTokens <= KEEP_RECENT_TOKENS) {
    return { ok: false, error: `the compact threshold ${parsed.compact.raw} (${fmt(compactTokens)} tokens) is not above Pi's retained history of ${fmt(KEEP_RECENT_TOKENS)} tokens: a compaction there would have nothing to cut.` };
  }
  if (warnTokens > compactTokens) {
    if (!set.warn) {
      notes.push(`the default warning threshold exceeds the compact threshold; clamped to ${fmt(compactTokens)}`);
      warnTokens = compactTokens;
      clamped = true;
    } else {
      return { ok: false, error: `the warning threshold ${parsed.warn.raw} (${fmt(warnTokens)} tokens) is above the compact threshold ${parsed.compact.raw} (${fmt(compactTokens)} tokens).` };
    }
  }
  if (noticeTokens > warnTokens) {
    if (!set.notice) {
      notes.push(`the default notice threshold exceeds the warning threshold; clamped to ${fmt(warnTokens)}`);
      noticeTokens = warnTokens;
      clamped = true;
    } else {
      return { ok: false, error: `the notice threshold ${parsed.notice.raw} (${fmt(noticeTokens)} tokens) is above the warning threshold ${parsed.warn.raw} (${fmt(warnTokens)} tokens).` };
    }
  }
  return {
    ok: true,
    thresholds: {
      declared,
      ceiling,
      ceilingReason: reason,
      capTokens,
      noticeTokens,
      warnTokens,
      compactTokens,
      noticePct: pctOf(noticeTokens, ceiling),
      warnPct: pctOf(warnTokens, ceiling),
      compactPct: pctOf(compactTokens, ceiling),
      clamped,
      notes,
    },
  };
}

export type UsageLevel = "unknown" | "idle" | "notice" | "warning" | "forced";

export const LEVEL_ORDER: Record<UsageLevel, number> = { unknown: -1, idle: 0, notice: 1, warning: 2, forced: 3 };

export function levelFor(tokens: number | null | undefined, t: ResolvedThresholds | undefined): UsageLevel {
  if (!t || tokens === null || tokens === undefined || !Number.isFinite(tokens)) return "unknown";
  if (tokens >= t.compactTokens) return "forced";
  if (tokens >= t.warnTokens) return "warning";
  if (tokens >= t.noticeTokens) return "notice";
  return "idle";
}

/**
 * One line as the operator writes it: a value for every seat, then
 * per-model overrides, comma-separated: `60%,openai/gpt-5.4-mini=55%,grok-4.6=70%`.
 * A key with a slash matches provider/id exactly; one without matches the
 * model id under any provider. The last matching entry wins. A list with
 * no seat value leaves the seats it does not name on the default.
 */
export type SpecList = { value: string; byModel: Array<{ key: string; value: string }> };

export const SPEC_LIST_HELP = `${SPEC_HELP} Per-model overrides follow, comma-separated, as model=value: 60%,openai/gpt-5.4-mini=55%,grok-4.6=70%.`;

/** What the kickoff, the console and the extension all accept for one line: the shape only, the order is checked against the window. */
export const SPEC_LIST_RE = /^(?:[A-Za-z0-9][A-Za-z0-9._:-]*(?:\/[A-Za-z0-9][A-Za-z0-9._:-]*)?=)?\d+(?:\.\d+)?[kKmM%]?(?:\s*,\s*(?:[A-Za-z0-9][A-Za-z0-9._:-]*(?:\/[A-Za-z0-9][A-Za-z0-9._:-]*)?=)?\d+(?:\.\d+)?[kKmM%]?)*$/;

const MODEL_KEY_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]*(?:\/[A-Za-z0-9][A-Za-z0-9._:-]*)?$/;

export function parseSpecList(raw: string | undefined, label: string): SpecList {
  const text = (raw ?? "").trim();
  if (!text) throw new Error(`${label}: value is blank. ${SPEC_LIST_HELP}`);
  const list: SpecList = { value: "", byModel: [] };
  for (const part of text.split(",").map((s) => s.trim()).filter(Boolean)) {
    const eq = part.lastIndexOf("=");
    if (eq === -1) {
      if (list.value) throw new Error(`${label}: "${text}" gives two values for every seat (${list.value} and ${part}); a per-model entry is model=value.`);
      parseTokenSpec(part, label);
      list.value = part;
      continue;
    }
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (!MODEL_KEY_RE.test(key)) throw new Error(`${label}: "${key}" is not a model (provider/id, or the id alone).`);
    parseTokenSpec(value, `${label} for ${key}`);
    list.byModel.push({ key, value });
  }
  return list;
}

/** The value one seat gets from a list: its model's override when one matches, else the seat value, else the default. */
export function specForModel(list: SpecList, fallback: string, model: string | undefined): { value: string; explicit: boolean; matched?: string } {
  const id = (model ?? "").trim().toLowerCase();
  const bare = id.includes("/") ? id.slice(id.indexOf("/") + 1) : id;
  let hit: { key: string; value: string } | undefined;
  for (const entry of list.byModel) {
    const key = entry.key.toLowerCase();
    if (key.includes("/") ? key === id : key === bare) hit = entry;
  }
  if (hit) return { value: hit.value, explicit: true, matched: hit.key };
  return list.value ? { value: list.value, explicit: true } : { value: fallback, explicit: false };
}

export type SpecLists = { noticeAt: SpecList; warnAt: SpecList; compactAt: SpecList };

/** The three lines as the kickoff hands them to a pane (`SWARM_COMPACT_*`), parsed; a blank line is an empty list. */
export function specsFromEnv(env: Record<string, string | undefined> = process.env): { specs: SpecLists; fromDefaults: boolean } {
  const parse = (raw: string | undefined, label: string): SpecList => (raw?.trim() ? parseSpecList(raw, label) : { value: "", byModel: [] });
  const specs: SpecLists = {
    noticeAt: parse(env.SWARM_COMPACT_NOTICE_AT, "compact notice threshold"),
    warnAt: parse(env.SWARM_COMPACT_WARN_AT, "compact warning threshold"),
    compactAt: parse(env.SWARM_COMPACT_AT, "compact threshold"),
  };
  const blank = (l: SpecList) => !l.value && l.byModel.length === 0;
  return { specs, fromDefaults: blank(specs.noticeAt) && blank(specs.warnAt) && blank(specs.compactAt) };
}

/** The three lines one seat runs under, with which entries applied and whether any of them was set by the operator. */
export function specsForModel(lists: SpecLists, model: string | undefined): {
  specs: ThresholdSpecs;
  fromDefaults: boolean;
  /** Which lines the operator set for this seat; the others are defaults that may be clamped to fit them. */
  explicit: Record<keyof ThresholdSpecs, boolean>;
  matched: Partial<Record<keyof ThresholdSpecs, string>>;
} {
  const notice = specForModel(lists.noticeAt, DEFAULT_SPECS.noticeAt, model);
  const warn = specForModel(lists.warnAt, DEFAULT_SPECS.warnAt, model);
  const compact = specForModel(lists.compactAt, DEFAULT_SPECS.compactAt, model);
  const matched: Partial<Record<keyof ThresholdSpecs, string>> = {};
  if (notice.matched) matched.noticeAt = notice.matched;
  if (warn.matched) matched.warnAt = warn.matched;
  if (compact.matched) matched.compactAt = compact.matched;
  return {
    specs: { noticeAt: notice.value, warnAt: warn.value, compactAt: compact.value },
    fromDefaults: !notice.explicit && !warn.explicit && !compact.explicit,
    explicit: { noticeAt: notice.explicit, warnAt: warn.explicit, compactAt: compact.explicit },
    matched,
  };
}
