package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"antifox/engine/agentcore"
	"antifox/engine/llm"
	"antifox/engine/permission"
	actool "antifox/engine/tool"
	"antifox/engine/transcript"
	"antifox/db"
)

// Planner is the event-driven LLM planner (docs §4.3): each time the asset or
// exploration graph changes (debounced), it reads the exploration route, queries
// assets, judges whether the task goal is met, and emits 0..N exploration intents
// into the frontier. It is the sole intent generator.
type Planner struct {
	prov        llm.Provider
	model       string
	tx          *transcript.Store                      // raw LLM conversation persistence (nil = off)
	window      int                                    // context window in tokens (for compaction)
	maxTurns    int                                    // max agent turns per run (0 = unlimited)
	killWork    func(intentID int64) error             // engine callback to terminate a running work (nil = off)
	steerWork   func(intentID int64, msg string) error // engine callback to steer a running work mid-run (nil = off)
	proxyAddr   string                                 // recording proxy for WebFetch (empty = direct)
	proxyCACert string                                 // recording proxy's CA cert path (HTTPS verify)
	webSearch   WebSearchOpts                          // web_search tool backend selection (off by default)
	workDir     string                                 // shared work dir (surfaced in prompt as artifact-output target)

	// todos keeps ONE plan-scratchpad per task (keyed by exploration id) so the
	// planner's multi-step plan survives across wake-ups — each Plan() is a fresh
	// session, but the shared store lets it record a serial exploit chain once and
	// dispatch it step-by-step over rounds instead of front-loading it in parallel.
	todoMu sync.Mutex
	todos  map[int64]*actool.TodoStore
}

func NewPlanner(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *Planner {
	return &Planner{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, todos: map[int64]*actool.TodoStore{}}
}

// SetProxy points the planner's WebFetch at the recording proxy plus the CA cert
// it trusts to verify HTTPS through it (empty addr = direct).
func (p *Planner) SetProxy(addr, caCert string) { p.proxyAddr, p.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for the planner (off by default).
func (p *Planner) SetWebSearch(o WebSearchOpts) { p.webSearch = o }

// todoFor returns the task's persistent planning todo store, creating it on first
// use. Shared across all of this task's planner wake-ups.
func (p *Planner) todoFor(expID int64) *actool.TodoStore {
	p.todoMu.Lock()
	defer p.todoMu.Unlock()
	s := p.todos[expID]
	if s == nil {
		s = actool.NewTodoStore()
		p.todos[expID] = s
	}
	return s
}

// SetKillWork wires the engine's per-work terminate callback so the planner's
// kill_work tool can stop a single running worker.
func (p *Planner) SetKillWork(fn func(intentID int64) error) { p.killWork = fn }

// SetSteerWork wires the engine's per-work steering callback so the planner's
// steer_work tool can inject a mid-run course-correction into a running worker.
func (p *Planner) SetSteerWork(fn func(intentID int64, msg string) error) { p.steerWork = fn }

// renderPlannerTodos formats the persistent planning todo for injection into the
// wake-up prompt (empty when there are no todos yet — first wake-up).
func renderPlannerTodos(items []actool.Todo) string {
	if len(items) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n[Your planning TODO (persisted across wake-ups, written by you last round)]:\n")
	for _, it := range items {
		mark := map[actool.TodoStatus]string{actool.TodoPending: "☐", actool.TodoInProgress: "▶", actool.TodoCompleted: "✔"}[it.Status]
		if mark == "" {
			mark = "☐"
		}
		b.WriteString(fmt.Sprintf("  %s %s\n", mark, it.Content))
	}
	b.WriteString("Proceed accordingly: only dispatch an intent for the next step whose [prerequisite steps are complete / the facts it depends on already exist]; use TodoWrite to update the list (mark steps already satisfied by a fact as completed). Do not re-dispatch steps already pending/in_progress in the list.")
	return b.String()
}

// renderDoneIntents surfaces the intent(s) whose completion triggered this round
// so the planner looks first at their fresh yields (in the态势 below) before
// deciding whether a new direction opened up. Empty for non-completion wakes.
func renderDoneIntents(ids []int64) string {
	if len(ids) == 0 {
		return ""
	}
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("#%d", id)
	}
	return "\n\n[The just-completed intent(s) that triggered this round]: " + strings.Join(parts, ", ")
}

// renderGraphOverview folds the pre-computed graph_overview snapshot into the
// wake-up prompt so the planner starts each round with the full situation in
// hand — saving the round-trip it would otherwise spend calling the tool. It is
// the exact same JSON graph_overview would return; deeper detail is still one
// tool call away (node_detail / list_facts / …).
func renderGraphOverview(data map[string]any) string {
	b, err := json.Marshal(data)
	if err != nil {
		return "" // fall back to the model calling graph_overview itself
	}
	return "\n\n[Current situation (graph_overview prefetched, equivalent to what calling that tool would return; call node_detail/list_facts etc. on demand when you need more detail)]:\n" + string(b)
}

// plannerDefaultTmpl is the built-in EDITABLE body (段 [A]) of the planner prompt,
// seeded into agent_prompts. Goal is a {{.Goal}} template var; the 中间产物输出规约
// tail is code-owned (artifactSpec) and appended by plannerSystem after rendering.
const plannerDefaultTmpl = `You are the "Planner" of an authorized penetration-testing system. You are woken frequently (woken whenever the graph changes). Your responsibilities: read the situation, judge the goals, and **only add exploration intents when there genuinely is a new direction not yet covered**.

Task goal: {{.Goal}}

⚠️ **Producing 0 intents is a legitimate, normal outcome, but it must have a [specific, valid reason] — it is not a "fewer intents is safer" default stance.** Only produce 0 intents in the following cases:
- **Already covered**: every direction you can think of is already covered by an open / running / recent_done intent — regenerating an existing intent, verbatim or reworded, is a serious error; or
- **Waiting on a dependency**: the next step depends on the output of [work that is currently running], and that output is not yet available — in this case you should [wait for that work to finish and the graph to update, then plan on the next wake]; forcing an intent out now would leave the downstream worker without a prerequisite that does not yet exist, spinning idly.
Conversely: if there genuinely is a new direction [not covered by any intent and not dependent on running work], or [the goal is not yet met and there is still untested surface in scope], then [do not] hold back just because "0 intents is common" — when a direction deserves dispatching, dispatch it. Do not treat 0 intents as a lazy default.

Decision process (every wake):
1. **The full situation is attached directly below this prompt (it is the return of graph_overview — no need to call it again)**: task (**the original task title + goal**, i.e. the root node), asset counts, goals and their status, open/running/recent_done intents, sites_without_endpoints, findings (**count of confirmed vulnerabilities**), facts (**count of exploration facts/conclusions — a separate category from vulnerabilities**), recent_facts (the {id, summary, confidence?} of recent facts, including **negative conclusions** such as "port closed / not injectable" — use these to avoid generating intents for dead ends already explored; but a negative conclusion with confidence=inferred is only an [inference] with weak evidence, so do not take it as settled — if that direction is critical to the goal, it is worth dispatching one re-check intent). **The exploration nodes here (goals/intents/facts/findings) belong to this task only** (they never contain another task's goals); **the asset graph, however, is globally shared** (one shared copy across tasks; the asset counts are global in-scope data, not unique to this task). Only when you need deeper detail should you call on demand: list_facts to list all facts, list_findings to list all vulnerabilities, **node_detail(id)** to fetch the full evidence/detail of a single item (the lists / recent_facts give only summaries).
   - open_intents / running_intents / recent_done_intents — "which directions already have an intent covering them / have already been attempted". Each intent also carries **parents (upstream: which facts/intents it was derived from) and yields (downstream: which facts/findings it produced)** — this is the **lineage** of the exploration graph; use it to understand "which facts came from which direction, and whether they can be synthesized into a new direction". Each fact in recent_facts carries **from_intent** (which intent produced it).
   - sites_without_endpoints / findings — "which directions [may] need exploration".
   - Only when you need the detail of a particular slice should you call **on demand**: list_assets (pull mode: search with the q keyword, stack type/company_id/task_id filters, paginate with limit/offset; or fetch directly by id/ids), asset_neighbors, list_findings. The asset graph is globally shared — do not pull everything by default. The assets may include assets not involved in this task, so when assets unrelated to this task appear, ignore them.
2. Judge the goals (core responsibility): the goals field of graph_overview already contains the goals and their status; for an unmet goal that has been proven by some finding/fact, call prove_goal(goal_id,evidence_id,reason) to mark it met. **When the one you mark with prove_goal happens to be the last remaining unfinished goal, the system automatically judges the whole task complete — you need not call goal_met again** — closing out should be driven by proving goals one by one with prove_goal.
   ⚠️ **Quantitative acceptance check (never stamp it done early)**: if a goal contains [quantifiable acceptance conditions] (such as "obtain N flags / N vulnerabilities", "gain a certain privilege / certain sensitive data", "reach a conclusion on a given batch of assets/endpoints"), then before prove_goal (and before closing out in any form) you **[must] check the measured situation in the graph_overview above this prompt** (the findings count, the related facts, whether all the corresponding assets have yielded conclusions, etc.): if the measured result [falls short], you are [forbidden] to mark that goal met — instead dispatch intents to close the gap. **You [must not] mark it met early on the grounds that "the main part is done / mostly achieved / the core goal is already secured", nor use goal_met to bypass this check.** Example: the goal requires "obtain 3 flags" but the graph proves only 1 — then the goal is [unmet]; keep dispatching follow-up test intents and do not mark it complete.
2.5. **(Optional, opening only, extremely lightweight) probing to understand**: you have execution capabilities such as Bash. Their **only legitimate use** is this — when **there are almost no facts in the graph yet** (recent_facts is essentially empty, the task has just begun) and the situation alone does not let you describe the initial intents concretely, run a **very small, read-only** probe of the target (such as 1–2 curls to look at the homepage / fingerprint) to produce more precise **initial intents**.
   ⚠️ **Keep your role boundary firmly in mind: you are the "Planner", not the "Executor". Everything you do here is solely to [generate / clarify intents], never to [do the work inside the plan].** The **only legitimate product of a probe is a more precise intent description** — never the discovery, verification, or exploitation of a vulnerability, nor the enumerated result of endpoints/directories/parameters. Any thought of "I'll just test/confirm this too while I'm at it" is out of bounds: that is the worker's job during the work phase; you only need to **write it up as an intent and dispatch it**.
   **Three hard boundaries — hold the line**:
   - **As soon as the graph contains a worker-produced fact (facts>0 / recent_facts non-empty), you are [forbidden] to probe yourself again.** From then on every judgment is based on existing facts, and your output this round can only be "dispatch new intents" or "end this round". When you see a lead you want to dig into, **the correct response is to dispatch an intent for a worker to investigate — never to curl it yourself**.
   - Even at the opening, **probe at most a few times (≤3) and then stop**, only to clarify the initial intents; **never** slide into: enumerating endpoints/directories one by one, trying ids one by one, base64-decoding chains, re-probing the same endpoint repeatedly, or any injection/privilege-escalation/vulnerability testing or verification — those are **all the worker's heavy lifting**, the content of the intents you are to generate, not something you should do yourself. The moment you notice you are "deeply verifying" rather than "quickly fixing a direction", stop at once and write the rest up as intents.
   - Probing only helps you "think it through"; **it does not itself produce intents**. If you can judge from existing facts/situation, **do not probe at all**.
3. **Decide whether to add exploration directions (be disciplined)**: an intent is an [open exploration direction], not a fixed type/menu — combining **known facts, assets, and the task goal**, judge for yourself "to close in on the goal, what valuable directions not yet covered remain for the next step". Compare each such direction one by one against open_intents + running_intents + recent_done_intents:
   - The direction is already covered by an open or running intent → **do not generate it again** (it is already being handled).
   - The direction was already attempted in recent_done_intents (even if it produced nothing) → **do not retry it as-is**. Treat it as a [blocked route]: re-dispatch only when a [material new mechanism] appears — a new fact, a new asset, a new parameter, or a clearly different approach/construction — and the summary of the new intent must spell out "how this differs from last time". **Merely rewording it, or "let's try once more, maybe it works", does not count as a new mechanism — retrying is forbidden.** Conversely, if a negative conclusion is weak evidence with confidence=inferred and that direction is critical to the goal, using [one re-check intent] to confirm or overturn it is legitimate (this counts as a new reason).
   - Generate only for [a wholly new direction that currently has no intent coverage at all].
   - All known directions are already covered by existing intents → **generate no intents and end this round directly.**
   - **Keep routes diverse, do not converge too early onto a single one**: while the goal is unmet, if the existing intents are all crowded onto [the same attack route / the same class of entry point] and there still exists a [fundamentally different] uncovered direction (such as another entry surface, another class of asset, another exploitation chain), prefer to add one such divergent direction rather than piling synonymous intents onto the same line. The ideal is to keep 2–3 mutually independent, mechanistically different routes alive at once (such as "attack via the upload chain" and "attack via auth bypass"); only once a route has delivered evidence of [closing in on the goal] is it worth concentrating resources there. Judge diversity by substantive differences in direction, not by wording. (This does not conflict with "0 intents is normal": add only when a fundamentally different, uncovered direction truly exists; if the blank route is already covered by existing intents, it is still 0 intents.)
3.5. **Serial exploitation chains: dispatch step by step, do not split into parallel at once.** Many exploits are a **strongly dependent serial chain** (e.g. ①→ ② → ③) where each later step depends on the **actual output** of the previous one. In this case:
   - **Do not** dispatch ①②③ at once as multiple parallel intents (the downstream worker cannot obtain a prerequisite output that does not yet exist, and will only duplicate / spin idly);
   - **Record the whole chain as a to-do list with TodoWrite** (one item per step), then **this round dispatch only the step whose prerequisite is already satisfied** (usually the first);
   - Once that step produces a fact, dispatch the next step on the following wake (the prompt will carry your to-do list), and mark the satisfied step completed;
   - Do not split "the same thing" into two items (e.g. "confirm the trigger point" and "fire the trigger point" are the same step). Use multiple parallel intents only for **parallel dimensions of exploration** (such as enumerating several unrelated endpoints at the same time).
4. Use [one] add_intent call to batch-submit the new directions filtered in step 3 (the intents array, at most the 4 highest-value ones; do not call it repeatedly one at a time):
   - summary: a free one-sentence description of the direction (what + why), in natural language, **do not apply a fixed taxonomy**. The direction must be spelled out clearly in the summary, since deduplication relies mainly on comparing it against existing intents.
   - asset_ids: the **id(s) of the target asset(s) this direction will test/attack** (**pass them whenever possible**, 0/1/many; these are the asset ids from list_assets). Whenever a direction centers on specific assets (a given site/endpoint/parameter/host), **be sure to include them** — this marks "which targets this exploration hits", used for coverage dedup and to link the intent into the asset chain; if it spans several assets, include them all. Leave it empty only for pure global reconnaissance with genuinely no specific target asset.
   - parent_ids: which [upstream nodes] this direction was synthesized from (optional, 0/1/many). **When several facts combine to produce a new intent, include all those fact ids**; if it derives from an upstream intent/finding, include that id too; leave empty for a top-level, wholly new direction.


Better to generate nothing than to duplicate or pad. Be concise, disciplined, efficient.`

func plannerSystem(goal, workDir string) string {
	body := renderSystem("planner", plannerDefaultTmpl, PlannerVars{Goal: goal, Now: time.Now().Format("2006-01-02 15:04:05 MST")})
	return body + artifactSpec(workDir)
}

// Plan runs one planning round. emit, if non-nil, receives the planner's execution
// steps (so users can see how it reads the situation and judges goals — the
// planner is the intent generator and was previously a black box). Returns whether
// the planner judged the goal met.
// doneIntents carries the ids of the intent(s) whose completion triggered this
// round (may be several — the engine debounces a burst; empty for non-completion
// wakes). They are surfaced in the prompt so the planner focuses on the fresh
// yields of what just finished.
func (p *Planner) Plan(ctx context.Context, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, goal string, doneIntents []int64, emit func(db.Activity)) (met bool, reason string, err error) {
	tsx := NewToolSet(ts, "planner")
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(taskID)
	tsx.killWork = p.killWork   // enable kill_work tool (nil = unavailable)
	tsx.steerWork = p.steerWork // enable steer_work tool (nil = unavailable)
	if origin, _ := ts.OriginFactID(); origin > 0 {
		tsx.SetOwnerNode(origin) // planner-side anchors default to the task root (origin fact)
	}
	// 领域工具 + 基础默认工具集（Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash）
	base := append(tsx.PlannerTools(), actool.DefaultTools()...)
	tools, def, cleanup := AugmentTools(ctx, "planner", base)
	defer cleanup()
	// 关键态势（刚完成的意图 + 预取的完整图）放进 system prompt，而不是 user 输入：
	// system 段永不被 compaction 压缩，长回合里也保证这份态势始终在场；轮内固定，还能吃到
	// system 缓存。它落在指令之后、deferred 工具块之前（deferredSystem 保证块在最后）。
	situational := renderDoneIntents(doneIntents) + renderGraphOverview(tsx.graphOverviewData())
	// 任务级 deadline / 终局模式(经 ctx 注入,见 taskclock.go)。终局那一轮把任务超时
	// planner 收尾词作为【本轮操作指令】直接注入 system,让它只做最后目标判定、不产新意图。
	tc := taskClockFrom(ctx)
	if tc.Final {
		situational += "\n\n[Task endgame wrap-up (special instruction for this round, overriding the regular planning flow above)]: " + resolveTaskTimeoutWrapup("planner")
	}
	system, boundary := deferredSystem(plannerSystem(goal, p.workDir)+situational, def)
	// planner 无自身墙钟预算;有 deadline 时把 MaxDuration 夹逼到剩余,让在跑的规划轮在
	// 任务到点时进收尾(因超时→任务超时词,因步数→per-run 词)。
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, 0)
	settle := wrapupSettlement("planner", nil)
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("planner", nil, clamped)
	}
	opts := agentcore.Options{
		Provider:        p.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  true, // 走记录代理留痕；载入代理 CA 验证 MITM 重签的 HTTPS 证书
		WebFetchProxy:   p.proxyAddr,
		WebFetchCACert:  p.proxyCACert,
		// 联网搜索(可选)。ddgs 无需 key；brave-free 需 BraveKey；tavily 需 TavilyKey。
		// WebSearchProxy 是独立出口代理(http/https/socks5)，与记录流量的 MITM 代理无关；空则直连。
		EnableWebSearch:    p.webSearch.Enabled,
		WebSearchBackend:   p.webSearch.Backend,
		BraveSearchAPIKey:  p.webSearch.BraveKey,
		TavilySearchAPIKey: p.webSearch.TavilyKey,
		SearxngURL:         p.webSearch.SearxngURL,
		WebSearchProxy:     p.webSearch.Proxy,
		BashEnv:           proxyEnv(p.proxyAddr, p.proxyCACert), // Bash 子命令默认走代理+信任 CA
		MaxTurns:          p.maxTurns,                           // 0 = unlimited (configurable in agent management)
		MaxDuration:       maxDur,                               // 0=不限;有 deadline 时=距 deadline 剩余
		Compaction:        compactionConfig(p.window),
		// 跨唤醒共享的规划待办：让串行链在多轮之间保留（session 是新的，store 不是）。
		Todos: p.todoFor(ts.ID()),
		// 命中【本轮】步数预算→ SDK 跑收尾:把本轮已想清楚的结论落地(该派的 add_intent、
		// 能证的 prove_goal、串行链记 TodoWrite),而非停止规划——planner 之后仍会被反复唤醒。
		// clamped(被任务 deadline 夹逼)时改用 PromptByReason(见 wrapupSettlementForTask)。
		Settlement: settle,
	}
	if p.tx != nil { // persist raw LLM conversation; one accumulating file per task's planner
		opts.Transcript = p.tx
		opts.SessionID = fmt.Sprintf("exp%d-planner", ts.ID())
	}
	// 态势（刚完成的意图 + 完整图）已在上面拼进 system prompt（抗压缩、轮内常驻）。这里
	// 的 user 输入只留指令 + 跨唤醒待办（todo 是模型自己的规划便签，可再生，放 user 即可）。
	input := "The graph has changed; plan the next step: read the situation in the system prompt above and judge the goals. **If there is no uncovered new direction this round, just end directly (producing 0 intents is normal and common, especially right after dispatching intents while waiting for worker output). Never call goal_met just to \"end this round\" — goal_met will [immediately end the entire task]; only call it once you have confirmed the goal is [genuinely met] (the target outcome has been obtained / the target vulnerability confirmed); if it is not met, mark goals one by one with prove_goal, or simply end without calling anything.**" +
		renderPlannerTodos(opts.Todos.List())
	// 有 deadline 夹逼时加硬 ctx 兜底(软预算 + grace),防单轮卡死绕过轮边界软超时。
	runCtx := ctx
	if maxDur > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, maxDur+settleHardGrace)
		defer cancel()
	}
	_, _, err = captureRun(runCtx, opts, input,
		func(r db.Activity) {
			if emit != nil {
				r.Worker = "planner" // planner activity has no intent_id (it generates them)
				emit(r)
			}
		})
	return tsx.GoalMet, tsx.Reason, err
}
