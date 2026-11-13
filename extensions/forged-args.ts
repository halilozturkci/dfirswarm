/**
 * The arguments of a forged tool, brought to the types its manifest declares.
 *
 * A seat's tool declares `candidates: array` and is called with
 * "[1, 2, 3]" or "1,2,3"; it declares `offset: integer` and gets "4096".
 * The script then adds a string to a number and dies: all seven calls of two
 * forged tools in the run sf4406b, all seven of one in s5d814f, across three
 * seats, none repaired. What a value plainly is under its declared type is
 * taken as that; anything else is left as it came, and what was changed is
 * said, so the caller learns the form.
 */
export type ParamDecl = { type?: string };

export function coerceArgs(params: Record<string, ParamDecl> | undefined, args: Record<string, unknown>): { args: Record<string, unknown>; coerced: string[] } {
  const out: Record<string, unknown> = { ...args };
  const coerced: string[] = [];
  for (const [key, decl] of Object.entries(params ?? {})) {
    const v = out[key];
    if (typeof v !== "string") continue;
    const t = v.trim();
    const took = (value: unknown, as: string) => {
      out[key] = value;
      coerced.push(`${key} (a string) was taken as ${as}`);
    };
    switch (decl?.type) {
      case "integer":
      case "number": {
        if (t !== "" && /^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$/.test(t) && Number.isFinite(Number(t)) && (decl.type === "number" || Number.isInteger(Number(t)))) took(Number(t), `the ${decl.type} ${Number(t)}`);
        else if (decl.type === "integer" && /^0x[0-9a-f]+$/i.test(t)) took(Number.parseInt(t, 16), `the integer ${Number.parseInt(t, 16)}`);
        break;
      }
      case "boolean":
        if (/^(true|false)$/i.test(t)) took(t.toLowerCase() === "true", `the boolean ${t.toLowerCase()}`);
        break;
      case "array": {
        let parsed: unknown;
        try { parsed = JSON.parse(t); } catch { parsed = undefined; }
        if (Array.isArray(parsed)) took(parsed, `an array of ${parsed.length}`);
        else if (t !== "" && !/^[[{]/.test(t)) {
          const items = t.split(/\s*,\s*/).filter((x) => x !== "").map((x) => (/^[+-]?\d+(\.\d+)?$/.test(x) ? Number(x) : x));
          took(items, `an array of ${items.length} (split at the commas)`);
        }
        break;
      }
      case "object": {
        let parsed: unknown;
        try { parsed = JSON.parse(t); } catch { parsed = undefined; }
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) took(parsed, "an object");
        break;
      }
      default:
        break;
    }
  }
  return { args: out, coerced };
}
