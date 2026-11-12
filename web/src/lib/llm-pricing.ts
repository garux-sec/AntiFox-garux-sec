// Built-in LLM price table — USD per 1,000,000 tokens.
//
// Used only to turn the token counters on the dashboard into a rough dollar
// estimate; it is NOT billed anywhere and does not need to be exact. Rates are
// matched to a profile's model id by LONGEST-PREFIX (so "gpt-5-mini" wins over
// "gpt-5"). A model with no match prices as null → the UI shows "—" instead of
// a wrong number.
//
// Sources (public list prices, 2026):
//   OpenAI    — https://openai.com/api/pricing/  (GPT-5 $1.25/$10, mini $0.25/$2)
//   Anthropic — https://docs.claude.com/en/docs/about-claude/pricing
//               (Opus $5/$25, Sonnet $3/$15, Haiku $1/$5; cache read = 0.1× input,
//                5-minute cache write = 1.25× input)
// Update these if a provider changes its prices.

export interface ModelPrice {
  input: number; // per 1M fresh (cache-miss) input tokens
  output: number; // per 1M output tokens
  cacheRead: number; // per 1M cached-read input tokens
  cacheWrite: number; // per 1M cache-creation tokens
}

export interface TokenBucket {
  input: number; // NOTE: dashboard convention — input INCLUDES cacheRead
  output: number;
  cacheRead: number;
  cacheWrite: number;
}

// Longest-prefix wins, so order here does not matter.
const TABLE: Array<[string, ModelPrice]> = [
  // ── OpenAI ──────────────────────────────────────────────────────────────
  ["gpt-5-nano", { input: 0.05, output: 0.4, cacheRead: 0.005, cacheWrite: 0.05 }],
  ["gpt-5-mini", { input: 0.25, output: 2.0, cacheRead: 0.025, cacheWrite: 0.25 }],
  ["gpt-5", { input: 1.25, output: 10.0, cacheRead: 0.125, cacheWrite: 1.25 }],
  ["gpt-4.1-nano", { input: 0.1, output: 0.4, cacheRead: 0.025, cacheWrite: 0.1 }],
  ["gpt-4.1-mini", { input: 0.4, output: 1.6, cacheRead: 0.1, cacheWrite: 0.4 }],
  ["gpt-4.1", { input: 2.0, output: 8.0, cacheRead: 0.5, cacheWrite: 2.0 }],
  ["gpt-4o-mini", { input: 0.15, output: 0.6, cacheRead: 0.075, cacheWrite: 0.15 }],
  ["gpt-4o", { input: 2.5, output: 10.0, cacheRead: 1.25, cacheWrite: 2.5 }],
  ["o4-mini", { input: 1.1, output: 4.4, cacheRead: 0.275, cacheWrite: 1.1 }],
  ["o3-mini", { input: 1.1, output: 4.4, cacheRead: 0.55, cacheWrite: 1.1 }],
  ["o3", { input: 2.0, output: 8.0, cacheRead: 0.5, cacheWrite: 2.0 }],
  ["o1-mini", { input: 1.1, output: 4.4, cacheRead: 0.55, cacheWrite: 1.1 }],
  ["o1", { input: 15.0, output: 60.0, cacheRead: 7.5, cacheWrite: 15.0 }],
  // ── Anthropic (cache read = 0.1× input, cache write = 1.25× input) ───────
  ["claude-haiku", { input: 1.0, output: 5.0, cacheRead: 0.1, cacheWrite: 1.25 }],
  ["claude-sonnet", { input: 3.0, output: 15.0, cacheRead: 0.3, cacheWrite: 3.75 }],
  ["claude-opus", { input: 5.0, output: 25.0, cacheRead: 0.5, cacheWrite: 6.25 }],
  // older naming (claude-3-opus / claude-3-5-sonnet …) still catches via these:
  ["claude-3-opus", { input: 15.0, output: 75.0, cacheRead: 1.5, cacheWrite: 18.75 }],
];

/** priceFor returns the price row whose key is the longest prefix of `model`. */
export function priceFor(model: string | undefined | null): ModelPrice | null {
  const m = (model ?? "").toLowerCase().trim();
  if (!m) return null;
  let best: ModelPrice | null = null;
  let bestLen = -1;
  for (const [key, price] of TABLE) {
    if (m.startsWith(key) && key.length > bestLen) {
      best = price;
      bestLen = key.length;
    }
  }
  return best;
}

/**
 * costUSD estimates the dollar cost of a token bucket for `model`, or null when
 * the model is not in the table. Follows the dashboard convention that `input`
 * already includes cached reads, so fresh input is billed as (input − cacheRead).
 */
export function costUSD(model: string | undefined | null, t: TokenBucket): number | null {
  const p = priceFor(model);
  if (!p) return null;
  // canonical input INCLUDES both cacheRead and cacheWrite → fresh = input − both.
  const freshInput = Math.max(0, t.input - t.cacheRead - t.cacheWrite);
  return (
    (freshInput * p.input +
      t.cacheRead * p.cacheRead +
      t.output * p.output +
      t.cacheWrite * p.cacheWrite) /
    1_000_000
  );
}

/** fmtUSD renders a dollar amount with precision that scales to small values. */
export function fmtUSD(v: number): string {
  if (v >= 100) return "$" + v.toFixed(0);
  if (v >= 1) return "$" + v.toFixed(2);
  if (v >= 0.01) return "$" + v.toFixed(3);
  if (v > 0) return "$" + v.toFixed(4);
  return "$0.00";
}
