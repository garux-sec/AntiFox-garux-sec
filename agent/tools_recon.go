package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	actool "antifox/engine/tool"
)

// =====================================================================
// ASM / OSINT passive-recon collector tools
// =====================================================================
//
// These are READ-ONLY external lookups the agent runs during attack-surface
// mapping: certificate transparency, DNS, RDAP/WHOIS, Shodan and GitHub code
// search. Each returns JSON to the model, which then persists what matters via
// insert_assets. Collectors never exploit a target — they query public sources
// (and your own API keys), so they stay within passive/safe-active recon.

// ReconKeys provides the API keys the recon collectors need, read lazily at call
// time so a key saved in Settings takes effect without rebuilding tools. The
// server wires these to the Manager's accessors at startup; nil = no key.
var ReconKeys struct {
	Shodan func() string // Shodan API key provider
	Github func() string // GitHub token provider
}

func reconKey(fn func() string) string {
	if fn == nil {
		return ""
	}
	return strings.TrimSpace(fn())
}

// reconClient is the shared HTTP client for recon fetches: a bounded timeout so a
// slow source can't hang an agent turn.
var reconClient = &http.Client{Timeout: 25 * time.Second}

// reconGet performs a GET and returns the status code + body (capped), with the
// given headers applied. Used by every HTTP-based collector.
func reconGet(ctx context.Context, rawURL string, headers map[string]string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "AntiFox-ASM/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := reconClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2 MiB cap
	return resp.StatusCode, body, nil
}

// ReconTools returns the ASM/OSINT recon collector tools.
func (t *ToolSet) ReconTools() []actool.CoreTool {
	return []actool.CoreTool{
		t.crtSh(),
		t.dnsLookup(),
		t.rdapWhois(),
		t.shodanHost(),
		t.githubCodeSearch(),
	}
}

// ─── crt.sh — certificate transparency → subdomains ──────────────────────────
func (t *ToolSet) crtSh() actool.CoreTool {
	return readTool(
		"crt_sh",
		"Passive subdomain discovery via crt.sh certificate transparency logs. Given a root domain, returns the unique subdomains seen in issued TLS certificates. No API key needed. Use insert_assets to persist the ones in scope.",
		obj(map[string]any{
			"domain": str("Root domain to enumerate, e.g. example.com"),
		}, "domain"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Domain string `json:"domain"`
			}
			_ = json.Unmarshal(in, &a)
			dom := strings.TrimSpace(strings.ToLower(a.Domain))
			if dom == "" {
				return actool.Errorf("domain is required"), nil
			}
			code, body, err := reconGet(ctx, "https://crt.sh/?q=%25."+url.QueryEscape(dom)+"&output=json", nil)
			if err != nil {
				return actool.Errorf("crt.sh request failed: " + err.Error()), nil
			}
			if code != http.StatusOK {
				return actool.Errorf(fmt.Sprintf("crt.sh returned HTTP %d", code)), nil
			}
			var rows []struct {
				NameValue string `json:"name_value"`
			}
			if err := json.Unmarshal(body, &rows); err != nil {
				return actool.Errorf("could not parse crt.sh response: " + err.Error()), nil
			}
			set := map[string]struct{}{}
			for _, r := range rows {
				for _, name := range strings.Split(r.NameValue, "\n") {
					name = strings.TrimSpace(strings.ToLower(strings.TrimPrefix(name, "*.")))
					if name == "" || strings.ContainsAny(name, " ") {
						continue
					}
					if name == dom || strings.HasSuffix(name, "."+dom) {
						set[name] = struct{}{}
					}
				}
			}
			subs := make([]string, 0, len(set))
			for s := range set {
				subs = append(subs, s)
			}
			sort.Strings(subs)
			return jsonResult(map[string]any{"domain": dom, "count": len(subs), "subdomains": subs})
		},
	)
}

// ─── DNS lookup ──────────────────────────────────────────────────────────────
func (t *ToolSet) dnsLookup() actool.CoreTool {
	return readTool(
		"dns_lookup",
		"Resolve DNS records for a host. type is one of A, AAAA, CNAME, MX, NS, TXT (default A). Returns the record values. Passive, no key.",
		obj(map[string]any{
			"name": str("Hostname to resolve, e.g. www.example.com"),
			"type": str("Record type: A|AAAA|CNAME|MX|NS|TXT (default A)"),
		}, "name"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Name string `json:"name"`
				Type string `json:"type"`
			}
			_ = json.Unmarshal(in, &a)
			name := strings.TrimSpace(a.Name)
			if name == "" {
				return actool.Errorf("name is required"), nil
			}
			rt := strings.ToUpper(strings.TrimSpace(a.Type))
			if rt == "" {
				rt = "A"
			}
			res := net.DefaultResolver
			var values []string
			var err error
			switch rt {
			case "A", "AAAA":
				var ips []net.IP
				ips, err = res.LookupIP(ctx, map[string]string{"A": "ip4", "AAAA": "ip6"}[rt], name)
				for _, ip := range ips {
					values = append(values, ip.String())
				}
			case "CNAME":
				var c string
				c, err = res.LookupCNAME(ctx, name)
				if c != "" {
					values = append(values, strings.TrimSuffix(c, "."))
				}
			case "MX":
				var mx []*net.MX
				mx, err = res.LookupMX(ctx, name)
				for _, m := range mx {
					values = append(values, fmt.Sprintf("%d %s", m.Pref, strings.TrimSuffix(m.Host, ".")))
				}
			case "NS":
				var ns []*net.NS
				ns, err = res.LookupNS(ctx, name)
				for _, n := range ns {
					values = append(values, strings.TrimSuffix(n.Host, "."))
				}
			case "TXT":
				values, err = res.LookupTXT(ctx, name)
			default:
				return actool.Errorf("unsupported type (use A|AAAA|CNAME|MX|NS|TXT)"), nil
			}
			if err != nil {
				return jsonResult(map[string]any{"name": name, "type": rt, "values": []string{}, "error": err.Error()})
			}
			return jsonResult(map[string]any{"name": name, "type": rt, "count": len(values), "values": values})
		},
	)
}

// ─── RDAP / WHOIS ────────────────────────────────────────────────────────────
func (t *ToolSet) rdapWhois() actool.CoreTool {
	return readTool(
		"rdap_whois",
		"WHOIS/RDAP lookup for a domain or IP via rdap.org. Returns registrar/org, nameservers, status and key dates. Passive, no key.",
		obj(map[string]any{
			"query": str("A domain (example.com) or IP address to look up"),
		}, "query"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Query string `json:"query"`
			}
			_ = json.Unmarshal(in, &a)
			q := strings.TrimSpace(a.Query)
			if q == "" {
				return actool.Errorf("query is required"), nil
			}
			kind := "domain"
			if net.ParseIP(q) != nil {
				kind = "ip"
			}
			code, body, err := reconGet(ctx, "https://rdap.org/"+kind+"/"+url.PathEscape(q), map[string]string{"Accept": "application/rdap+json"})
			if err != nil {
				return actool.Errorf("rdap request failed: " + err.Error()), nil
			}
			if code != http.StatusOK {
				return actool.Errorf(fmt.Sprintf("rdap returned HTTP %d for %s", code, q)), nil
			}
			var raw struct {
				LDHName     string `json:"ldhName"`
				Handle      string `json:"handle"`
				Status      []string `json:"status"`
				Nameservers []struct {
					LDHName string `json:"ldhName"`
				} `json:"nameservers"`
				Events []struct {
					Action string `json:"eventAction"`
					Date   string `json:"eventDate"`
				} `json:"events"`
				Entities []struct {
					Roles  []string        `json:"roles"`
					Handle string          `json:"handle"`
					VCard  json.RawMessage `json:"vcardArray"`
				} `json:"entities"`
			}
			if err := json.Unmarshal(body, &raw); err != nil {
				return actool.Errorf("could not parse rdap response: " + err.Error()), nil
			}
			ns := make([]string, 0, len(raw.Nameservers))
			for _, n := range raw.Nameservers {
				ns = append(ns, strings.ToLower(n.LDHName))
			}
			events := map[string]string{}
			for _, e := range raw.Events {
				events[e.Action] = e.Date
			}
			roles := make([]map[string]any, 0, len(raw.Entities))
			for _, e := range raw.Entities {
				roles = append(roles, map[string]any{"handle": e.Handle, "roles": e.Roles})
			}
			return jsonResult(map[string]any{
				"query": q, "kind": kind, "name": raw.LDHName, "handle": raw.Handle,
				"status": raw.Status, "nameservers": ns, "events": events, "entities": roles,
			})
		},
	)
}

// ─── Shodan ──────────────────────────────────────────────────────────────────
func (t *ToolSet) shodanHost() actool.CoreTool {
	return readTool(
		"shodan_host",
		"Shodan lookup of a host's exposed services, open ports, product banners and known CVEs. Provide ip for a single host, or query (Shodan search syntax, e.g. hostname:example.com or org:\"Example\") for a search — query needs a Shodan API key. With no key, an ip falls back to the free Shodan InternetDB. Passive.",
		obj(map[string]any{
			"ip":    str("IP address to look up (optional)"),
			"query": str("Shodan search query (optional; requires an API key), e.g. hostname:example.com"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				IP    string `json:"ip"`
				Query string `json:"query"`
			}
			_ = json.Unmarshal(in, &a)
			ip := strings.TrimSpace(a.IP)
			query := strings.TrimSpace(a.Query)
			key := reconKey(ReconKeys.Shodan)

			if ip != "" && key == "" {
				// Free InternetDB (no key): ports, cpes, hostnames, tags, vulns.
				code, body, err := reconGet(ctx, "https://internetdb.shodan.io/"+url.PathEscape(ip), nil)
				if err != nil {
					return actool.Errorf("shodan internetdb request failed: " + err.Error()), nil
				}
				if code == http.StatusNotFound {
					return jsonResult(map[string]any{"ip": ip, "source": "internetdb", "found": false})
				}
				if code != http.StatusOK {
					return actool.Errorf(fmt.Sprintf("shodan internetdb returned HTTP %d", code)), nil
				}
				var m map[string]any
				_ = json.Unmarshal(body, &m)
				return jsonResult(map[string]any{"ip": ip, "source": "internetdb", "found": true, "data": m, "note": "set a Shodan API key in Settings for full host details and search"})
			}
			if key == "" {
				return actool.Errorf("shodan requires an API key for search (set it in Settings), or pass an ip to use the free InternetDB"), nil
			}
			var endpoint string
			switch {
			case ip != "":
				endpoint = "https://api.shodan.io/shodan/host/" + url.PathEscape(ip) + "?key=" + url.QueryEscape(key)
			case query != "":
				endpoint = "https://api.shodan.io/shodan/host/search?key=" + url.QueryEscape(key) + "&query=" + url.QueryEscape(query)
			default:
				return actool.Errorf("provide an ip or a query"), nil
			}
			code, body, err := reconGet(ctx, endpoint, nil)
			if err != nil {
				return actool.Errorf("shodan request failed: " + err.Error()), nil
			}
			if code != http.StatusOK {
				msg := strings.TrimSpace(string(body))
				if len(msg) > 200 {
					msg = msg[:200]
				}
				return actool.Errorf(fmt.Sprintf("shodan returned HTTP %d: %s", code, msg)), nil
			}
			var m map[string]any
			if err := json.Unmarshal(body, &m); err != nil {
				return actool.Errorf("could not parse shodan response: " + err.Error()), nil
			}
			return jsonResult(map[string]any{"source": "shodan-api", "data": m})
		},
	)
}

// ─── GitHub code search ──────────────────────────────────────────────────────
func (t *ToolSet) githubCodeSearch() actool.CoreTool {
	return readTool(
		"github_code_search",
		"Search public GitHub code for a keyword to find leaked secrets, configs or references to a target (e.g. a domain, internal hostname or API key prefix). Requires a GitHub token (set in Settings). Returns matching repos + file paths; review them for exposed credentials. Passive.",
		obj(map[string]any{
			"query": str("GitHub code-search query, e.g. \"example.com\" password, or org:example filename:.env"),
		}, "query"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Query string `json:"query"`
			}
			_ = json.Unmarshal(in, &a)
			q := strings.TrimSpace(a.Query)
			if q == "" {
				return actool.Errorf("query is required"), nil
			}
			token := reconKey(ReconKeys.Github)
			if token == "" {
				return actool.Errorf("github_code_search requires a GitHub token (set it in Settings)"), nil
			}
			code, body, err := reconGet(ctx, "https://api.github.com/search/code?per_page=20&q="+url.QueryEscape(q), map[string]string{
				"Authorization": "Bearer " + token,
				"Accept":        "application/vnd.github+json",
			})
			if err != nil {
				return actool.Errorf("github request failed: " + err.Error()), nil
			}
			if code != http.StatusOK {
				msg := strings.TrimSpace(string(body))
				if len(msg) > 200 {
					msg = msg[:200]
				}
				return actool.Errorf(fmt.Sprintf("github returned HTTP %d: %s", code, msg)), nil
			}
			var raw struct {
				TotalCount int `json:"total_count"`
				Items      []struct {
					Name       string `json:"name"`
					Path       string `json:"path"`
					HTMLURL    string `json:"html_url"`
					Repository struct {
						FullName string `json:"full_name"`
						HTMLURL  string `json:"html_url"`
					} `json:"repository"`
				} `json:"items"`
			}
			if err := json.Unmarshal(body, &raw); err != nil {
				return actool.Errorf("could not parse github response: " + err.Error()), nil
			}
			items := make([]map[string]any, 0, len(raw.Items))
			for _, it := range raw.Items {
				items = append(items, map[string]any{
					"repo": it.Repository.FullName, "path": it.Path, "url": it.HTMLURL,
				})
			}
			return jsonResult(map[string]any{"query": q, "total_count": raw.TotalCount, "items": items})
		},
	)
}
