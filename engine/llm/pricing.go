package llm

import "strings"

// Price is a model's list price in USD per 1,000,000 tokens, split by token
// class. Mirrors the frontend table in web/src/lib/llm-pricing.ts — keep the two
// in sync when a provider changes prices.
type Price struct {
	Input      float64 // per 1M fresh (uncached) input tokens
	Output     float64 // per 1M output tokens
	CacheRead  float64 // per 1M cached-read input tokens
	CacheWrite float64 // per 1M cache-creation tokens
}

// priceTable is matched by LONGEST-PREFIX against a model id, so "gpt-5-mini"
// wins over "gpt-5". Sources: OpenAI & Anthropic public pricing (2026). Anthropic
// cache read = 0.1× input, 5-minute cache write = 1.25× input.
var priceTable = []struct {
	prefix string
	p      Price
}{
	// ── OpenAI ──────────────────────────────────────────────────────────────
	{"gpt-5-nano", Price{0.05, 0.40, 0.005, 0.05}},
	{"gpt-5-mini", Price{0.25, 2.00, 0.025, 0.25}},
	{"gpt-5", Price{1.25, 10.0, 0.125, 1.25}},
	{"gpt-4.1-nano", Price{0.10, 0.40, 0.025, 0.10}},
	{"gpt-4.1-mini", Price{0.40, 1.60, 0.10, 0.40}},
	{"gpt-4.1", Price{2.00, 8.00, 0.50, 2.00}},
	{"gpt-4o-mini", Price{0.15, 0.60, 0.075, 0.15}},
	{"gpt-4o", Price{2.50, 10.0, 1.25, 2.50}},
	{"o4-mini", Price{1.10, 4.40, 0.275, 1.10}},
	{"o3-mini", Price{1.10, 4.40, 0.55, 1.10}},
	{"o3", Price{2.00, 8.00, 0.50, 2.00}},
	{"o1-mini", Price{1.10, 4.40, 0.55, 1.10}},
	{"o1", Price{15.0, 60.0, 7.50, 15.0}},
	// ── Anthropic ────────────────────────────────────────────────────────────
	{"claude-haiku", Price{1.00, 5.00, 0.10, 1.25}},
	{"claude-sonnet", Price{3.00, 15.0, 0.30, 3.75}},
	{"claude-opus", Price{5.00, 25.0, 0.50, 6.25}},
	{"claude-3-opus", Price{15.0, 75.0, 1.50, 18.75}},
}

// PriceFor returns the price row whose key is the longest prefix of model, and
// false when the model is not in the table.
func PriceFor(model string) (Price, bool) {
	m := strings.ToLower(strings.TrimSpace(model))
	if m == "" {
		return Price{}, false
	}
	var best Price
	bestLen := -1
	for _, e := range priceTable {
		if strings.HasPrefix(m, e.prefix) && len(e.prefix) > bestLen {
			best, bestLen = e.p, len(e.prefix)
		}
	}
	if bestLen < 0 {
		return Price{}, false
	}
	return best, true
}

// CostUSD estimates the dollar cost of a set of token counters for model, or 0
// when the model has no known price. The canonical Usage.InputTokens INCLUDES
// both cached-read and cache-write tokens (see anthropic.go norm / openai.go), so
// fresh input is input − cacheRead − cacheWrite.
func CostUSD(model string, input, output, cacheRead, cacheWrite int) float64 {
	p, ok := PriceFor(model)
	if !ok {
		return 0
	}
	fresh := input - cacheRead - cacheWrite
	if fresh < 0 {
		fresh = 0
	}
	return (float64(fresh)*p.Input +
		float64(cacheRead)*p.CacheRead +
		float64(cacheWrite)*p.CacheWrite +
		float64(output)*p.Output) / 1_000_000
}

// CostUSD estimates the dollar cost of this usage for model (0 if unknown model).
func (u Usage) CostUSD(model string) float64 {
	return CostUSD(model, u.InputTokens, u.OutputTokens, u.CacheReadTokens, u.CacheWriteTokens)
}
