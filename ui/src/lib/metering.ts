/**
 * The console's words for a team that bills nothing per token. The kickoff
 * writes why next to `metered: false` in the budget record: `local` (every
 * model is served from this machine or network) or `subscription` (an OAuth
 * login whose dollars Pi only estimates). A record without the reason (a run
 * from before it was written) is "unmetered (reason not recorded)", never
 * "free": nothing says it is free. One pure function, so every label site of
 * the console says the same thing.
 */
export type UnmeteredWhy = "local" | "subscription";
export type MeteringRecord = { metered?: boolean; unmetered_why?: UnmeteredWhy | string | null };

export type MeteringWords = {
  /** Whether the team is metered (billed per token, its dollars exact). */
  metered: boolean;
  /** The short word where a dollar figure would stand. */
  label: string;
  /** The line beside it: why there is no dollar figure. */
  note: string;
  /** Pi's dollars for this team are an estimate (a subscription): marked wherever they are shown. */
  dollars_estimate: boolean;
  /** One sentence for the budget panel's footnote. */
  sentence: string;
};

export function meteringWords(record: MeteringRecord | null | undefined): MeteringWords {
  if (!record || record.metered !== false) return { metered: true, label: "", note: "", dollars_estimate: false, sentence: "" };
  if (record.unmetered_why === "subscription") {
    return {
      metered: false,
      label: "subscription",
      note: "subscription · not billed per token",
      dollars_estimate: true,
      sentence: "Not billed per token: this team runs on a subscription, so the dollars Pi computes are an estimate and brake nothing.",
    };
  }
  if (record.unmetered_why === "local") {
    return {
      metered: false,
      label: "free",
      note: "no metered cost · local models",
      dollars_estimate: false,
      sentence: "No metered cost: every model on this team is served from this machine or network, so Pi computes $0 for every call.",
    };
  }
  return {
    metered: false,
    label: "unmetered",
    note: "unmetered (reason not recorded)",
    dollars_estimate: false,
    sentence: "Unmetered: no spend is billed per token, and this run's record does not say why (a run from before the reason was written).",
  };
}
