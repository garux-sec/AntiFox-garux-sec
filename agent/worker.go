package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"antifox/db"
	"antifox/engine/agentcore"
	"antifox/engine/harness"
	"antifox/engine/llm"
	"antifox/engine/memory"
	"antifox/engine/permission"
	actool "antifox/engine/tool"
	"antifox/engine/transcript"
)

// Worker is an LLM work agent (docs §4.4): it claims ONE intent, completes it
// with real tools (Bash: kali tooling through the recording proxy), writes the
// FACTS it found back into the graph, and stops. It does NOT generate new
// directions (that is the planner's job) and does NOT keep exploring toward the
// goal on its own. Multiple workers run concurrently as goroutines.
// WebSearchOpts is the web-search backend selection the server pushes into each
// agent (planner/worker/main). Enabled=false leaves the web_search tool off.
// Backend is "ddgs" (no key), "brave-free" (BraveKey required), or "tavily"
// (TavilyKey required). It maps directly onto agentcore.Options.
// Proxy is a dedicated egress proxy for the search request (http/https/socks5),
// independent of the traffic-recording MITM proxy — set it when the search endpoint
// is only reachable via a VPN/SOCKS proxy. Empty = direct.
type WebSearchOpts struct {
	Enabled   bool
	Backend   string
	BraveKey  string
	TavilyKey string
	Proxy     string
}

type Worker struct {
	prov        llm.Provider
	model       string
	workDir     string
	proxyAddr   string
	proxyCACert string            // recording proxy's CA cert path (for WebFetch HTTPS verify)
	webSearch   WebSearchOpts     // web_search tool backend selection (off by default)
	mem         *memory.Store     // cross-engagement tradecraft memory (G4)
	tx          *transcript.Store // raw LLM conversation persistence (nil = off)
	window      int               // context window in tokens (for compaction)
	maxTurns    int               // max agent turns per run (0 = unlimited)
	// runTimeout is the wall-clock budget for the main exploration of one intent
	// (0 = unlimited). When it fires, the run is cut and a settlement round is
	// forced so already-identified facts get written back instead of being lost.
	runTimeout time.Duration
	// extraTools are host-provided tools (e.g. traffic query, oast) appended to
	// the worker's graph write-back tools.
	extraTools []actool.CoreTool
	// trafficResolver, if set, resolves a finding's reproduction steps to real
	// recorded traffic exchange ids at record time (host callback). nil = no linkage.
	trafficResolver func(taskID int64, repro json.RawMessage) json.RawMessage
}

// SetRunTimeout configures the per-intent wall-clock budget for the main
// exploration (0 = unlimited). When it fires, the SDK settlement phase still runs
// so facts are never lost to a timeout. Safe to call before Execute.
func (w *Worker) SetRunTimeout(run time.Duration) {
	w.runTimeout = run
}

// settleHardGrace is how far past the soft wall-clock budget (runTimeout) the hard
// ctx deadline sits — a backstop for a hung turn; the soft budget handles the
// normal case at the turn boundary.
const settleHardGrace = 90 * time.Second

// settleWrapUpPrompt is injected by the SDK settlement phase when a worker hits its
// turn/time budget: stop probing, write back what was found, then end with a
// plain-text one-liner (which becomes this run's displayed result).
const settleWrapUpPrompt = "你即将因预算耗尽被终止。不要再运行任何命令/探测。请依次：(1) 把你上面已识别但还没写回的内容逐条写回——新资产用 insert_assets、探索结论/事实用 record_fact、确认漏洞用 report_finding；(2) **最后单独用一句话纯文本**总结你做了什么、得到哪些关键结论（这句会作为本次运行的结果展示，务必输出）。"

// SetMemory enables cross-engagement tradecraft memory (RecallMemory/RecordMemory
// tools + auto-injection of relevant memories, docs §8 G4).
func (w *Worker) SetMemory(m *memory.Store) { w.mem = m }

func NewWorker(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int, extra ...actool.CoreTool) *Worker {
	return &Worker{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, extraTools: extra}
}

// SetProxy configures the recording proxy address that workers route target
// traffic through, plus the CA cert path WebFetch trusts to verify HTTPS through
// that MITM proxy. Empty addr disables the hint.
func (w *Worker) SetProxy(addr, caCert string) { w.proxyAddr, w.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for this worker (off by default).
func (w *Worker) SetWebSearch(o WebSearchOpts) { w.webSearch = o }

// SetTrafficResolver wires the record-time traffic linkage callback (host-provided).
func (w *Worker) SetTrafficResolver(fn func(taskID int64, repro json.RawMessage) json.RawMessage) {
	w.trafficResolver = fn
}

// proxyEnv builds the Bash-subprocess env that routes child-command HTTP through
// the recording proxy and makes the common toolchain trust its MITM CA — so tools
// need no manual -x/--proxy/-k. Each ecosystem reads a different CA var (verified
// empirically): SSL_CERT_FILE→curl/urllib/Go/openssl, REQUESTS_CA_BUNDLE→python
// requests (it ignores SSL_CERT_FILE), CURL_CA_BUNDLE→curl, GIT_SSL_CAINFO→git,
// NODE_EXTRA_CA_CERTS→node; NODE_USE_ENV_PROXY makes Node 24+ honor the proxy vars.
// Empty proxyAddr → nil (direct, unchanged env).
func proxyEnv(proxyAddr, caCert string) []string {
	if proxyAddr == "" {
		return nil
	}
	env := []string{
		"HTTP_PROXY=" + proxyAddr, "HTTPS_PROXY=" + proxyAddr,
		"http_proxy=" + proxyAddr, "https_proxy=" + proxyAddr,
		"NODE_USE_ENV_PROXY=1", // Node 24+: honor HTTP(S)_PROXY in built-in fetch/http
	}
	if caCert != "" {
		env = append(env,
			"SSL_CERT_FILE="+caCert,
			"CURL_CA_BUNDLE="+caCert,
			"REQUESTS_CA_BUNDLE="+caCert,
			"GIT_SSL_CAINFO="+caCert,
			"NODE_EXTRA_CA_CERTS="+caCert,
		)
	}
	return env
}

// workerDefaultTmpl is the built-in EDITABLE body (段 [A]) of the worker system
// prompt, seeded into agent_prompts. The trafficTool block and the 中间产物输出规约
// are NOT here — they are code-owned and appended by workerSystem after rendering
// (段 [B]/[C]), so editing the DB body can never drop them.
const workerDefaultTmpl = `You are the "executor" (work agent) of an authorized penetration-testing system. You are assigned [one intent] (a one-sentence exploration direction), and your sole responsibility is: **complete this one intent, write the facts you discover back into the knowledge graph, then stop and return.**

Iron rules (must be followed):
1. **Do only this one intent.** The intent's boundary is your red line. A fingerprinting intent means doing fingerprint identification only — do not casually go enumerate endpoints, brute-force directories, scrape JS for APIs, or test for vulnerabilities; those belong to [other intents] and are dispatched to other workers by the planner.
2. **You are not responsible for the "exploration direction".** If you find a new lead worth pursuing further, do not keep attacking it yourself; just write it back into the graph, and the planner will read it and generate new intents on its own. Generating exploration directions is the planner's job, not yours.
3. **Return only after exhausting the options, and don't give up at the first obstacle.** The standard for judging "intent accomplished" is [you have truly explored this direction thoroughly]: a first attempt being blocked (a payload filtered, an endpoint returning 404, an injection point with no echo) does not mean the path is dead — first switch encoding / switch method / switch parameter / switch path to run through the reasonable techniques for this intent, then draw a conclusion. **But the boundary does not change**: what you exhaust is only the techniques [within this one intent], never casually doing other intents (enumerating other endpoints, testing other vulnerabilities); those are still work the planner dispatches to other workers. Once you have truly explored it thoroughly, or confirmed the path is dead, write back and return immediately — don't keep going just because "the overall task goal hasn't been met yet", and don't spin idly on an already-exhausted direction just to pad out steps.
4. **Write back as you discover, and write to the right place.** Write back the moment you reach a result (don't save it all for the end, or you lose everything when steps run out). A result only counts once it is written into the graph; one living in your head or in your text does not count. **Keep the two graphs straight**:
   - **Discovered a new asset/resource** → use insert_assets to write to the [asset graph] (register the asset itself: endpoint / parameter / tech fingerprint / service / credential / subdomain, etc.). An asset's structured attributes go on the asset itself: put a site's/endpoint's status code / title / body length / content_type in props.http, and register a technology as a type=tech node. Register multiple assets in one batch via insert_assets's assets array.
   - **Reached an exploration conclusion/fact** (including positive conclusions such as fingerprints/enumeration, and negative conclusions such as "port closed", "this parameter is not injectable", "no login entry found") → use record_fact to write to the [exploration graph] (pass intent_id). **Aggregate multiple observations from one exploration into [a single] fact**: write a summarizing one-liner in summary, and the relevant details in detail (stuff the tech stack, status codes, response characteristics, etc. all into this one fact's detail) — **do not make one fact per attribute**; one intent usually produces just one fact, and splitting too finely makes the graph balloon without limit. Only use the facts array to write several at once when there really are multiple [mutually distinct] conclusions. [New] **Write only the increment**: before writing back, first glance at recent_facts in the [Global Exploration Situation] above — write only the conclusions you [newly obtained] this time, and don't re-record a fact already in the graph with different wording (duplicate facts make the graph balloon and mislead the planner into thinking there is new progress). If your observation merely confirms an existing fact and adds nothing, there is no need to record another one.
   - **Confirmed a vulnerability** → use report_finding to write to the [exploration graph] (include PoC, pass intent_id).
   - **Exposure/information disclosure is also a finding, not just an asset**: sensitive surfaces reachable without authorization — admin/debug interfaces, Swagger/API docs, config or backup/source files, sensitive-data-leaking endpoints, etc. — **as long as you actually reached it and obtained a response proving its exposure**, that is itself a [confirmed] finding (reachable + a response = triggered, not speculation) → record it with report_finding (severity by sensitivity: ordinary information disclosure = low, unauthorized-reachable sensitive/admin interface = medium, direct takeover or obtaining credentials/keys = high). **The distinction**: merely "this interface exists" is an asset (insert_assets); "it can be reached without authorization and exposes content that should not be exposed" is a finding (report_finding) — do not write the latter only into assets/facts. When exploitation of a hard target does not break through, this kind of proven exposure is exactly the finding you should hand in; don't leave even one unrecorded.

Available tools:
- insert_assets: register new assets (asset graph). **You pass only the raw information; keys and parent-child relationships are computed by the code**: a new endpoint → pass the full url+method (the code auto-builds domain→site→endpoint, auto-extracts the query parameters from the URL, and body/header parameters go in params); a fingerprint → type=tech, name=technology name, on_url=site address, props filled with {version,category}. Put multiple assets in the assets array to register them in one batch. Attributes go on the asset's own props; do not write exploration conclusions here.
- record_fact: write an exploration [fact/conclusion] into the exploration graph and link it to the intent (pass intent_id). Use it for positive/negative conclusions, observations, and judgments; **aggregate multiple observations from one exploration into a single fact** (summary one-liner + detail for the details), not one per attribute. Only use the facts array when there really are multiple distinct conclusions. **Write only what you actually saw**: give evidence (one line of key evidence: command + key output, concise, don't paste large blocks — details go in detail), and mark confidence (observed = directly seen / inferred = deduced); **evidence bar for negative conclusions** (conclusions such as not-injectable / port-closed / no-login-entry that [may make the planner abandon an entire direction]): before concluding, first confirm you have [exhausted the reasonable techniques within this intent] (switch encoding / switch parameter / switch path / switch method); if the techniques are not run through, or the evidence is only "looks like / most likely so", always mark confidence=inferred. **Better to mark inferred and let the planner re-check than to weld an entire route shut with a hasty observed negative** — especially early in the task, a wrong observed negative can derail the whole task and be very hard to reverse later.
- report_finding: confirmed vulnerability → record it (include PoC, pass intent_id = the id of the intent you were assigned). **Use it only when you actually triggered the vulnerability during this run and obtained reproducible evidence (request/response or command output).** It is strictly forbidden to report the following as confirmed vulnerabilities: matching a CVE purely by version number/fingerprint, "the parameter looks injectable" alone, or inference purely from an external vulnerability database / changelog / code diff. **Do not substitute checking a CVE database or "comparing patch versions" for actually triggering it.** If you cannot trigger it but there is a genuine suspicion, use record_fact to record a confidence=inferred fact (describe the suspected point + why it could not be triggered), hand it to the planner to dispatch follow-up intents, and don't force it into a finding.
  **[Be sure to fill in the reproduction structured reproduction process]** (you have just finished the attack and know every step best; afterward no one can accurately reconstruct it for you): entry_point (the key interface that triggers the vulnerability, method+URL) · prerequisites (reproduction prerequisites: the accounts/roles/prior steps needed; if a test account is required, spell out [how to register] — the interface + key request points, so anyone can reproduce from scratch) · steps (ordered steps; for each step, request = the verbatim original request you actually sent [verbatim, don't rewrite / don't fabricate], response = that step's verbatim original response [status code + key headers + key body fragments, taken verbatim from the real return; if too long, keep the key fragment that proves the problem], expected = a one-line expectation/conclusion for that step, proves = what it proves) · provenance (the source/dependency of this vulnerability's attack chain). Give the verbatim originals of both requests and responses as much as possible — this reproduction process directly determines whether the report can be manually reproduced step by step, so please fill it in carefully.
- list_assets (query assets, not exploration nodes) / asset_neighbors / list_facts (exploration facts) / list_findings (vulnerabilities) / node_detail (exploration node id, not asset id): look up context as needed.
- [Used only when necessary; most context is already in this session] search_all_worker_traces / list_worker_traces / get_worker_trace: **reuse information across work runs** (things that appeared during another work run's execution but were never written into a fact). You cannot see the exploration graph, but you can: search_all_worker_traces(q) to search all work runs' processes by keyword (returns with intent_id); list_worker_traces to see which work runs have run; get_worker_trace(intent_id) to see a work run's step summary, and get_worker_trace(intent_id, step_ids=[…]) to retrieve the full content of those steps (≤5 at a time). **Only for reusing others' observations and avoiding duplicated effort — it does not change your task boundary (you still do only this one intent).**

Operate only within the authorized scope. After completing this intent, summarize in one sentence what you did and which facts you wrote back. Be pragmatic, restrained, and focused on this one intent.`

// workerTrafficBlock is 段 [B]: the traffic-tool note, code-injected only when
// traffic capture is on (proxyAddr set). Not stored, not editable.
func workerTrafficBlock(proxyAddr string) string {
	if proxyAddr == "" {
		return ""
	}
	return "\n\n**流量工具**：\n- traffic_search / traffic_get：目标流量已被记录代理全量落库（本地文件树 data/traffic/<host>/<访问路径>/）。回看响应、找已访问过的资源，**先查流量、不要重复 curl 同一 URL**。traffic_search **必须指定 host**、默认只回 3 条极轻量索引(id/method/url/status/resp_len，无响应内容)，需要更多显式调大 limit；要看某条原文用 traffic_get(id)。"
}

// artifactSpec is 段 [C]: the code-owned, non-editable tail appended to every
// pentest agent's prompt — intermediate artifacts must land in the shared work
// dir, never /tmp. Guaranteed present regardless of how the DB body is edited.
func artifactSpec(workDir string) string {
	return "\n\n**中间产物输出规约**：脚本、payload、抓到的响应体、临时数据等一切中间产物，**一律写到共享工作目录 " + workDir + "**（这是所有 agent 共用的 CWD，相对路径即写在这里，也可用该绝对路径）——**不要写 /tmp、不要用其它绝对路径**。"
}

// workerArtifactSubdir is the worker-only addendum to artifactSpec: put a run's
// artifacts under an i<intentID>/ subdir to avoid concurrent name collisions.
const workerArtifactSubdir = "为避免与其他 work 撞名，把本次产物放到子目录 i<意图id>/ 下（如 i123/exploit.py）。"

func workerSystem(proxyAddr, workDir string) string {
	body := renderSystem("worker", workerDefaultTmpl, WorkerVars{ProxyAddr: proxyAddr})
	return body + workerTrafficBlock(proxyAddr) + artifactSpec(workDir) + workerArtifactSubdir
}

// renderIntentTask formats the claimed intent for the worker's SYSTEM prompt: the
// intent is the worker's whole job, so — like the planner's situational block — it
// belongs in system, where compaction can never drop it during a long run.
func renderIntentTask(intent *db.Node) string {
	return fmt.Sprintf("\n\n【你领到的意图（本次唯一任务：只做这一条、只产生事实、做完即停）】：\n%s\n意图 id: %d（写回 record_fact / report_finding 时传它）", string(intent.Payload), intent.ID)
}

// renderWorkerGraphOverview folds the global situational snapshot into the worker's
// SYSTEM prompt for AWARENESS ONLY. The framing is deliberately strong: the overview
// must NOT widen the worker's job — it still does only its assigned intent. Its sole
// purpose is letting the worker read context (existing facts/assets/hints)
// so it avoids redundant work and doesn't re-derive what others already found.
func renderWorkerGraphOverview(data map[string]any) string {
	b, err := json.Marshal(data)
	if err != nil {
		return "" // fall back silently: the worker just won't have the global context
	}
	return "\n\n【全局探索态势（仅供你了解大局，不是你的任务清单）】：\n" +
		"下面是整个任务当前的探索概况。给你的**唯一目的**是让你了解全局动态、复用已有结论、避免重复别人已做过的事。\n" +
		"**它绝不扩大你的职责边界**：你仍然只做上面领到的那一条意图。看到这里有别的 open 意图 / 未覆盖的点 / 其它可打方向，也**绝不要自己去动手**——那些是别的 worker 的事，由规划者调度。你若发现相关新线索，最多写进 fact 让规划者知道，不要自己追。\n" +
		string(b)
}

// Execute runs one intent. hooks (the per-task Guard) gates every tool call; may
// be nil. emit, if non-nil, receives one ActivityRecord per execution step.
// Returns the terminal reason (so the engine can distinguish completed vs
// max_turns) and a per-kind breakdown of what was written back (so an intent that
// explored but persisted nothing isn't mistaken for done, and the engine can log
// facts/assets/findings separately instead of lumping them under "facts").
func (w *Worker) Execute(ctx context.Context, name string, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, intent *db.Node, hooks harness.HookRunner, emit func(db.Activity), enr EnrichTrigger) (harness.TerminalReason, WriteCounts, error) {
	tsx := NewToolSet(ts, name)
	tsx.SetTaskID(taskID)
	tsx.SetTrafficResolver(w.trafficResolver)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetOwnerNode(intent.ID) // assets this worker discovers anchor to its intent → visible to the task
	tsx.SetEnrich(enr)          // async DNS/HTTP auto-completion for assets this worker writes
	// base = built-in worker tools ∪ host tools (traffic) ∪ default tools (incl. Bash);
	// then augment with the agent's visible skills/MCP. During the SDK settlement
	// phase, Bash is hidden via Settlement.DisabledTools (no local gating needed).
	base := append(tsx.WorkerTools(), w.extraTools...)
	base = append(base, actool.DefaultTools()...)
	tools, def, cleanup := AugmentTools(ctx, "worker", base)
	defer cleanup()

	// 意图是 worker 的全部任务，放进 system prompt（抗 compaction、整轮常驻），而不是
	// user 输入——与 planner 把关键态势放 system 一致。落在指令之后、deferred 块之前。
	// 全局态势(graphOverviewData)也带上，但仅供了解大局；意图放在最后、最醒目的位置。
	overview := renderWorkerGraphOverview(tsx.graphOverviewData())
	system, boundary := deferredSystem(workerSystem(w.proxyAddr, w.workDir)+overview+renderIntentTask(intent), def)
	// 任务级 deadline(经 ctx 注入)夹逼本 run 的墙钟预算 + 决定收尾词(见 taskclock.go)。
	tc := taskClockFrom(ctx)
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, w.runTimeout)
	settle := wrapupSettlement("worker", []string{"Bash"})
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("worker", []string{"Bash"}, clamped)
	}
	opts := agentcore.Options{
		Provider:        w.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		// WebFetch 走记录代理，其 HTTP 与 curl 一样被留痕；载入代理 CA 让经 MITM
		// 重签的 HTTPS 证书能【正常校验通过】（而非关掉校验）。proxy 空则直连。
		EnableWebFetch: true,
		WebFetchProxy:  w.proxyAddr,
		WebFetchCACert: w.proxyCACert,
		// 联网搜索(可选)。ddgs 无需 key；brave-free 需 BraveKey；tavily 需 TavilyKey。
		// WebSearchProxy 是独立的出口代理(http/https/socks5)，与记录流量的 MITM 代理无关；空则直连。
		EnableWebSearch:    w.webSearch.Enabled,
		WebSearchBackend:   w.webSearch.Backend,
		BraveSearchAPIKey:  w.webSearch.BraveKey,
		TavilySearchAPIKey: w.webSearch.TavilyKey,
		WebSearchProxy:     w.webSearch.Proxy,
		// Bash 子命令的 HTTP 默认走记录代理 + 信任其 CA（工具无需 -x/-k）。
		BashEnv:    proxyEnv(w.proxyAddr, w.proxyCACert),
		WorkingDir: w.workDir,
		MaxTurns:   w.maxTurns, // 0 = unlimited (configurable in agent management)
		// 墙钟预算,轮边界判,不打断半路;0 = 不限。有任务级 deadline 时夹逼到 min(自身预算,
		// 距 deadline 剩余),让本 run 在任务到点时自然进收尾(见 taskclock.go)。
		MaxDuration: maxDur,
		// 命中预算(轮次 OR 时长)→ SDK 跑一轮收尾(隐藏 Bash),把已识别的写回,避免烂尾。
		// clamped(被任务 deadline 夹逼)时用 PromptByReason:因超时=任务到点→任务超时词,
		// 因步数=夹逼窗口内步数先耗尽→回落 per-run 词。非 clamped 维持纯 per-run。
		Settlement: settle,
		// large tool output spills to cmd-output/ with a head + pointer (SDK tool.Capture);
		// full output preserved on disk. 截断上限用 SDK 默认(30000 字符)。
		ToolOutputDir: filepath.Join(w.workDir, "cmd-output"),
		Compaction:    compactionConfig(w.window), // long tool-heavy runs stay within the window
		Todos:         actool.NewTodoStore(),      // 会话级临时待办（TodoWrite），纯规划用，退出即丢
	}
	if hooks != nil { // typed-nil guard: only set when concrete (avoids harness panic)
		opts.Hooks = hooks
	}
	if w.mem != nil {
		opts.Memory = &agentcore.MemoryOptions{Store: w.mem, AutoInject: true, MaxInject: 3}
	}
	if w.tx != nil { // persist raw LLM conversation; one file per worked intent
		opts.Transcript = w.tx
		opts.SessionID = fmt.Sprintf("exp%d-worker-i%d", ts.ID(), intent.ID)
	}
	intentID := intent.ID
	emitWrap := func(r db.Activity) {
		if emit != nil {
			r.NodeID, r.Worker = &intentID, name
			emit(r)
		}
	}
	// 意图已在 system 里。user 输入只放启动指令。
	input := "开始执行 system 提示里的这条意图：只做它、只产生事实、做完即停。"

	s := agentcore.NewSession(opts)
	defer s.Close() // release the session's background-task manager (temp dir + processes)

	// Budgets + settlement are owned by the SDK (MaxTurns/MaxDuration + Settlement):
	// on hit it runs a wrap-up turn and finishes with ReasonMaxTurns/ReasonTimeout.
	// We only add a HARD ctx backstop past the soft wall-clock budget, for the rare
	// case a single turn hangs so the turn-boundary check never runs — the soft
	// budget handles the normal case gracefully (no mid-stream abort). pause /
	// planner kill cancel ctx; the engine distinguishes those and re-queues/stops.
	// backstop uses the EFFECTIVE (deadline-clamped) budget, not the raw runTimeout,
	// so a task-timeout run's hard deadline sits just past its clamped soft budget.
	runCtx := ctx
	if maxDur > 0 {
		var runCancel context.CancelFunc
		runCtx, runCancel = context.WithTimeout(ctx, maxDur+settleHardGrace)
		defer runCancel()
	}
	_, reason, err := captureRunSession(runCtx, s, input, emitWrap)
	return reason, tsx.Writes(), err
}
