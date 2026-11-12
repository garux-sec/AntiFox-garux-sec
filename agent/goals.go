package agent

import (
	"context"
	"encoding/json"
	"strings"

	"antifox/engine/agentcore"
	acperm "antifox/engine/permission"
	actool "antifox/engine/tool"
	"antifox/db"
)

// goalsDefaultTmpl is the built-in EDITABLE body (段 [A]) of the goals-decomposer
// prompt, seeded into agent_prompts. No template vars are used today.
const goalsDefaultTmpl = `You are a penetration-testing objective decomposer. Your job is to identify, from the user's input, the **final results to be achieved**, not to plan the attack steps.

**Objective = the final deliverable / verifiable result**

**Things that are NOT objectives (must not be listed as sub-objectives)**:
- Information gathering, reconnaissance, endpoint scanning
- Vulnerability analysis and verification processes
- Attack steps, exploitation techniques
- Result-verification steps

**Decomposition principles**:
- The user describes only one final objective → output a single one
- There are multiple **mutually independent** final deliverables → list them separately
- For objectives that map to a clear vulnerability class, annotate vulnclass; leave it empty for information-gathering / business-logic objectives
- Never invent objectives the user did not mention

Call set_goals to submit the results.`

// GoalSpec is one decomposed objective.
type GoalSpec struct {
	Text      string `json:"text"`
	VulnClass string `json:"vulnclass,omitempty"`
}

// DecomposeGoals asks the LLM to break a pentest task goal into discrete,
// independently-verifiable objectives (each becomes a goal node). Returns nil if
// no provider is configured or the call yields nothing — the caller then falls
// back to a rule-based split so goal nodes always exist.
//
// desc is the task's free-text description (背景：靶标范围/flag 数量/交战说明等).
// It is fed alongside the goal so the decomposer no longer splits blind — the
// prompt still forbids inventing anything the two texts don't state.
//
// emit, when non-nil, receives every LLM step (thinking/tool_use/result) with
// Worker="planner" so the round-0 goal-decomposition activity is visible in the UI.
func DecomposeGoals(ctx context.Context, c Config, goalText, desc string, emit func(db.Activity)) []GoalSpec {
	prov, err := c.NewProvider()
	if err != nil {
		return nil
	}
	var out struct {
		Goals []GoalSpec `json:"goals"`
	}
	captured := false
	submitTool := actool.Build(actool.Spec{
		Name:        "set_goals",
		Description: "提交拆分后的目标列表。",
		Schema: map[string]any{"type": "object", "properties": map[string]any{
			"goals": map[string]any{"type": "array", "items": map[string]any{
				"type": "object", "properties": map[string]any{
					"text":      map[string]any{"type": "string", "description": "一个独立可验证的目标"},
					"vulnclass": map[string]any{"type": "string", "description": "对应漏洞类(若明确)，如 SQLi/IDOR；业务逻辑目标可留空"},
				}, "required": []string{"text"},
			}},
		}, "required": []string{"goals"}},
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			_ = json.Unmarshal(in, &out)
			captured = true
			return actool.Text("ok"), nil
		},
	})
	// Description rides in the user message (same channel as the goal), NOT via the
	// {{.EngagementDescription}} template var — else a prompt that references the var
	// would inject the description twice. System prompt stays pure static instructions.
	sys := renderSystem("goals", goalsDefaultTmpl, GoalsVars{})
	userMsg := "任务目标：\n" + goalText
	if d := strings.TrimSpace(desc); d != "" {
		userMsg += "\n\n任务描述（背景信息，可能含靶标范围/flag 数量/交战说明；仅供参考，不要臆造其中未提及的内容）：\n" + d
	}
	// Use captureRun so every LLM step is emitted as an activity record (visible in
	// the plan tab under the round-0 marker). Falls back gracefully when emit is nil.
	captureEmit := func(r db.Activity) {
		if emit != nil {
			r.Worker = "planner"
			emit(r)
		}
	}
	captureRun(ctx, agentcore.Options{
		Provider:               prov,
		SystemPrompt:           []string{sys},
		Tools:                  []actool.CoreTool{submitTool},
		PermissionMode:         acperm.ModeBypass,
		DisableBackgroundTasks: true,
		MaxTurns:               4,
	}, userMsg, captureEmit)
	if !captured {
		return nil
	}
	return out.Goals
}
