---
name: report-generation
description: Editable content for penetration test report generation—AI rewrite prompts plus a fixed skeleton (methodology / test checklist / tools / reference standards / testers), split into per-language files. The report engine reads from disk on every generation, so edits take effect immediately.
---

# Report Generation (Editable Content)

This skill holds the **editable content of penetration test reports**, read by the "Report Management" generation pipeline. Changes **take effect on the next generation**—no restart or recompilation needed; if any file is missing or corrupt, it automatically falls back to the built-in default.

## Structure

- `prompts/report-level.tmpl` — AI prompt for report-level narrative (background / service results / remediation conclusion / matched test items).
- `prompts/vuln-narrative.tmpl` — AI prompt for rewriting a single vulnerability (description / reproduction steps / risk / remediation / CVSS).
- `skeleton/<language>/methodology.json` — 2.2 Test process: `{intro, phases:[{name,desc}]}`.
- `skeleton/<language>/checklist.json` — 2.3 Test checklist: `[{category,name,desc}]`. Items the AI judges as matched are rendered as "Failed".
- `skeleton/<language>/tools.json` — 2.4 Test tools: `[{name,desc}]`.
- `skeleton/<language>/standards.json` — 2.5 Reference standards: `["..."]`.
- `skeleton/<language>/personnel.json` — 2.1 Default testers: `[{name,role,contact}]` (overridden by whatever the user enters in report settings).

Language directories: `zh-CN` (Simplified) / `zh-TW` (Traditional) / `en-US` (English).

## Prompt Template Variables

The prompts are Go `text/template`, with `===USER===` separating the system and user sections:

- Report level: `{{.Company}}` `{{.Project}}` `{{.Client}}` `{{.FindingsList}}` `{{.LangDirective}}`
- Vulnerability level: `{{.Company}}` `{{.VulnClass}}` `{{.Severity}}` `{{.Summary}}` `{{.PoC}}` `{{.LangDirective}}`

`{{.LangDirective}}` injects the target-language directive (Simplified / Traditional / English), so the prompt itself is language-agnostic and a single copy is shared across all three languages.
