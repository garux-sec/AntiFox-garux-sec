package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"antifox/db"
)

// AI-Report ("AI Kill Chain") push integration.
//
// When a task reaches the "done" terminal state, AntiFox's confirmed findings
// are pushed into the AI-Report system as a brand-new report + vulnerabilities,
// so the autonomous pentest results land in the team's official (Thai-PDF)
// reporting system automatically — no copy/paste.
//
// Only AntiFox is touched: it speaks AI-Report's EXISTING REST API
//   POST /api/reports                         -> create report, returns {_id}
//   PUT  /api/reports/:id {vulnerabilities:[]} -> attach the mapped findings
// with the X-API-Key header. Nothing is pushed unless both the base URL and the
// API key are configured in settings (AIReportURL / AIReportKey).

const (
	aiReportMaxEvidence    = 12               // cap screenshots per finding in the push
	aiReportMaxEvidenceB   = 3 << 20          // skip any single screenshot larger than 3 MiB
	aiReportTotalEvidenceB = 24 << 20         // overall screenshot budget for one push
	aiReportHTTPTimeout    = 90 * time.Second // create + bulk PUT can carry many data-URL images
)

// owaspRe pulls an "A0X:20YY" OWASP code out of a finding's class/description so
// the AI-Report row is pre-categorized when the agent already named it.
var owaspRe = regexp.MustCompile(`A\d{1,2}:20\d{2}`)

type aiReportFile struct {
	URL         string `json:"url"` // data: URL (base64 screenshot) or empty
	Description string `json:"description,omitempty"`
	Command     string `json:"command,omitempty"`
}

type aiReportVuln struct {
	Title      string         `json:"title"`
	Severity   string         `json:"severity"` // Critical|High|Medium|Low|Informational
	Detail     string         `json:"detail"`
	OWASP      string         `json:"owasp,omitempty"`
	CVSSScore  float64        `json:"cvssScore,omitempty"`
	CVSSVector string         `json:"cvssVector,omitempty"`
	Fix        string         `json:"fix,omitempty"`
	Affected   string         `json:"affected,omitempty"`
	PoC        string         `json:"poc,omitempty"`
	Files      []aiReportFile `json:"files,omitempty"`
}

// aiReportSeverity maps AntiFox severities (high|medium|low|critical|info) to the
// AI-Report enum (Title-case; anything unknown -> Informational).
func aiReportSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium", "moderate", "med":
		return "Medium"
	case "low":
		return "Low"
	default:
		return "Informational"
	}
}

// AIReportConfigured reports whether a push can be attempted (URL + key both set).
func (m *Manager) AIReportConfigured() bool {
	return m.AIReportURL() != "" && m.AIReportKey() != ""
}

// pushTaskToAIReport harvests the task's confirmed findings, maps them to the
// AI-Report schema (attaching evidence screenshots as data URLs), creates a new
// report and bulk-attaches the vulnerabilities. Returns the new report id and
// the number of findings pushed. Safe to call in a goroutine.
func (s *Server) pushTaskToAIReport(t *Task, projectID string) (string, int, error) {
	base := strings.TrimRight(s.m.AIReportURL(), "/")
	key := s.m.AIReportKey()
	if base == "" || key == "" {
		return "", 0, fmt.Errorf("AI-Report not configured (set the base URL and API key in Settings)")
	}

	vulns := s.harvestAIReportVulns(t)
	if len(vulns) == 0 {
		return "", 0, fmt.Errorf("task has no confirmed findings to push")
	}

	// 1) Create the report shell.
	systemName := strings.TrimSpace(t.Name)
	if systemName == "" {
		systemName = "AntiFox Pentest #" + t.ID
	}
	if len([]rune(systemName)) > 120 { // a pasted target-list in the name would blow up the cover
		systemName = "AntiFox Pentest #" + t.ID
	}
	format := "Blackbox"
	if ctx := strings.ToLower(t.Goal + " " + t.Description); strings.Contains(ctx, "white box") ||
		strings.Contains(ctx, "whitebox") || strings.Contains(ctx, "source code") || strings.Contains(ctx, "sast") {
		format = "Whitebox"
	}
	createPayload := map[string]any{
		"systemName": systemName,
		"format":     format,
		"scope":      strings.TrimSpace(t.Description),
		"executiveSummary": fmt.Sprintf(
			"Imported from AntiFox autonomous pentest task #%s on %s. %d finding(s). Review and refine before delivery.",
			t.ID, time.Now().Format("2006-01-02"), len(vulns)),
	}
	if u := dominantTarget(vulns); u != "" {
		createPayload["url"] = u
	}
	if projectID = strings.TrimSpace(projectID); projectID != "" {
		createPayload["project"] = projectID // link the report to the chosen AI-Report project
	}

	var created struct {
		ID  string `json:"_id"`
		Alt string `json:"id"`
	}
	if err := s.aiReportCall(base, key, http.MethodPost, "/api/reports", createPayload, &created); err != nil {
		return "", 0, fmt.Errorf("create report: %w", err)
	}
	reportID := created.ID
	if reportID == "" {
		reportID = created.Alt
	}
	if reportID == "" {
		return "", 0, fmt.Errorf("create report: AI-Report returned no report id")
	}

	// 2) Attach all vulnerabilities in one PUT (fresh report, so no merge needed).
	if err := s.aiReportCall(base, key, http.MethodPut, "/api/reports/"+reportID,
		map[string]any{"vulnerabilities": vulns}, nil); err != nil {
		return reportID, 0, fmt.Errorf("attach vulnerabilities: %w", err)
	}
	return reportID, len(vulns), nil
}

// harvestAIReportVulns flattens the task's KindFinding nodes into AI-Report vulns,
// reusing persisted enrichment (the human-reviewed "AI 分析") when present and
// attaching evidence screenshots as data URLs.
func (s *Server) harvestAIReportVulns(t *Task) []aiReportVuln {
	if t == nil || t.Store == nil {
		return nil
	}
	nodes, _ := t.Store.ListByKind(db.KindFinding, 500)
	out := make([]aiReportVuln, 0, len(nodes))
	totalEvidence := 0
	for _, n := range nodes {
		var p struct {
			VulnClass string `json:"vulnclass"`
			Severity  string `json:"severity"`
			Summary   string `json:"summary"`
			Evidence  struct {
				PoC string `json:"poc"`
			} `json:"evidence"`
		}
		_ = json.Unmarshal(n.Payload, &p)

		v := aiReportVuln{
			Title:    strings.TrimSpace(firstNonEmpty(p.VulnClass, p.Summary, "Finding")),
			Severity: aiReportSeverity(p.Severity),
			Detail:   strings.TrimSpace(p.Summary),
			PoC:      strings.TrimSpace(p.Evidence.PoC),
		}

		// Reuse persisted enrichment for richer, review-consistent content.
		if enr, _ := s.m.pg.GetFindingEnrichment(n.ID); enr != nil {
			if sv := strings.TrimSpace(enr.Severity); sv != "" {
				v.Severity = aiReportSeverity(sv)
			}
			re := reportEnrichmentFromDB(enr)
			if re != nil {
				if strings.TrimSpace(re.Title) != "" {
					v.Title = strings.TrimSpace(re.Title)
				}
				if d := joinLines(re.Description); d != "" {
					v.Detail = d
				}
				if f := joinLines(re.Remediation); f != "" {
					v.Fix = f
				}
				if re.CVSSScore > 0 {
					v.CVSSScore = re.CVSSScore
				}
				if strings.TrimSpace(re.CVSSVector) != "" {
					v.CVSSVector = re.CVSSVector
				}
				if strings.TrimSpace(re.Target) != "" {
					v.Affected = strings.TrimSpace(re.Target)
				}
			}
		}
		if v.OWASP == "" {
			v.OWASP = owaspRe.FindString(p.VulnClass + " " + v.Detail + " " + v.Title)
		}

		// Attach evidence screenshots (budgeted) as data URLs.
		if totalEvidence < aiReportTotalEvidenceB {
			evs, _ := s.m.pg.ListFindingEvidence(n.ID)
			for i, ev := range evs {
				if i >= aiReportMaxEvidence || totalEvidence >= aiReportTotalEvidenceB {
					break
				}
				url, size := s.evidenceDataURL(n.ID, ev.Filename)
				if url == "" {
					continue
				}
				totalEvidence += size
				v.Files = append(v.Files, aiReportFile{URL: url, Description: strings.TrimSpace(ev.Caption)})
			}
		}
		out = append(out, v)
	}
	return out
}

// evidenceDataURL reads an evidence image off disk and returns a base64 data URL
// plus its encoded size. Empty URL = skip (missing/too large/unreadable).
func (s *Server) evidenceDataURL(nodeID int64, filename string) (string, int) {
	path := filepath.Join(s.evidenceDir(nodeID), filepath.Base(filename))
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() || fi.Size() > aiReportMaxEvidenceB {
		return "", 0
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", 0
	}
	ct := mime.TypeByExtension(strings.ToLower(filepath.Ext(filename)))
	if ct == "" || !strings.HasPrefix(ct, "image/") {
		ct = "image/png"
	}
	enc := base64.StdEncoding.EncodeToString(b)
	return "data:" + ct + ";base64," + enc, len(enc)
}

// aiReportCall performs one JSON request against the AI-Report API with the
// X-API-Key header, decoding the response into out (nil to ignore the body).
func (s *Server) aiReportCall(base, key, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(s.ctx, aiReportHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, base+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Generous cap: AI-Report list responses can be large (projects embed base64
	// logos), so a small limit would truncate the JSON and break parsing.
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(data))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return fmt.Errorf("AI-Report %s %s -> %d: %s", method, path, resp.StatusCode, msg)
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// dominantTarget returns the most common non-empty Affected value across the
// findings, used to pre-fill the report's URL field.
func dominantTarget(vulns []aiReportVuln) string {
	count := map[string]int{}
	for _, v := range vulns {
		if a := strings.TrimSpace(v.Affected); a != "" {
			count[a]++
		}
	}
	type kv struct {
		k string
		n int
	}
	var all []kv
	for k, n := range count {
		all = append(all, kv{k, n})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].n > all[j].n })
	if len(all) > 0 {
		return all[0].k
	}
	return ""
}

// joinLines joins an enrichment string slice into one block of text.
func joinLines(ss []string) string {
	var b []string
	for _, s := range ss {
		if t := strings.TrimSpace(s); t != "" {
			b = append(b, t)
		}
	}
	return strings.Join(b, "\n")
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// syncAIReportMCP mirrors the AI-Report Settings (base URL + API key) into the
// 'ai-report' HTTP MCP row, so the agents' MCP tools (create_report,
// add_vulnerability, …) use the same config as the auto-push. The MCP endpoint is
// <base>/mcp and the X-API-Key env doubles as the request header. The row is
// enabled once both are present. Best-effort; called when the Settings change.
func (s *Server) syncAIReportMCP() {
	if s.m.pg == nil {
		return
	}
	m, err := s.findMCPByName("ai-report")
	if err != nil {
		return
	}
	if m == nil {
		m = &db.MCPServer{Name: "ai-report", Transport: "http", Env: json.RawMessage(`{"X-API-Key":""}`)}
	}
	if base := strings.TrimRight(s.m.AIReportURL(), "/"); base != "" {
		m.URL = base + "/mcp"
	}
	if key := s.m.AIReportKey(); key != "" {
		env, _ := json.Marshal(map[string]string{"X-API-Key": key})
		m.Env = env
	}
	m.Enabled = m.URL != "" && envHasValue(m.Env)
	if _, err := s.m.pg.SaveMCP(m); err != nil {
		log.Printf("[aireport] sync MCP row failed: %v", err)
	}
}

// pushAIReport handles POST /api/tasks/{id}/push-aireport — manual (re)send of a
// task's findings to AI-Report, optionally into a chosen project. Returns the
// created report id + count.
func (s *Server) pushAIReport(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok || t == nil {
		writeErr(w, 404, "task not found")
		return
	}
	var body struct {
		ProjectID string `json:"project_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body) // empty body = no project
	id, n, err := s.pushTaskToAIReport(t, body.ProjectID)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"report_id": id, "findings": n})
}

// listAIReportProjects handles GET /api/aireport/projects — proxies AI-Report's
// project list so the UI can offer a target project when sending findings.
func (s *Server) listAIReportProjects(w http.ResponseWriter, r *http.Request) {
	base := strings.TrimRight(s.m.AIReportURL(), "/")
	key := s.m.AIReportKey()
	if base == "" || key == "" {
		writeErr(w, 400, "AI-Report not configured (set the base URL and API key in Settings)")
		return
	}
	var raw []struct {
		ID         string `json:"_id"`
		Name       string `json:"name"`
		ClientName string `json:"clientName"`
	}
	if err := s.aiReportCall(base, key, http.MethodGet, "/api/projects", nil, &raw); err != nil {
		log.Printf("[aireport] list projects failed (base=%s): %v", base, err)
		writeErr(w, 400, err.Error())
		return
	}
	out := make([]map[string]string, 0, len(raw))
	for _, p := range raw {
		out = append(out, map[string]string{"id": p.ID, "name": p.Name, "client_name": p.ClientName})
	}
	log.Printf("[aireport] list projects: %d project(s) from %s", len(out), base)
	writeJSON(w, 200, out)
}

// testAIReport handles POST /api/aireport/test — verify connectivity + key by
// listing reports. Uses the posted url/key when given, else the stored config.
func (s *Server) testAIReport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
		Key string `json:"key"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	base := strings.TrimRight(strings.TrimSpace(firstNonEmpty(req.URL, s.m.AIReportURL())), "/")
	key := strings.TrimSpace(firstNonEmpty(req.Key, s.m.AIReportKey()))
	if base == "" || key == "" {
		writeErr(w, 400, "AI-Report base URL and API key are required")
		return
	}
	var reports []any
	if err := s.aiReportCall(base, key, http.MethodGet, "/api/reports", nil, &reports); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "reports": len(reports)})
}

// autoPushToAIReport is the task-completion hook: when AI-Report is configured
// and auto-push is on, push the finished task's findings in the background and
// log the outcome (best-effort; never blocks the engine).
func (s *Server) autoPushToAIReport(t *Task) {
	if t == nil || !s.m.AIReportConfigured() || !s.m.AIReportAutoPush() {
		return
	}
	go func() {
		id, n, err := s.pushTaskToAIReport(t, "") // auto-push has no project selection
		if err != nil {
			log.Printf("[aireport] auto-push task %s failed: %v", t.ID, err)
			return
		}
		log.Printf("[aireport] auto-push task %s -> report %s (%d findings)", t.ID, id, n)
	}()
}
