package report

import (
	"encoding/json"
	"time"

	"github.com/owogametools/k2f-purge/internal/model"
)

const schemaVersion = 1

type envelope struct {
	SchemaVersion int              `json:"schema_version"`
	GeneratedAt   string           `json:"generated_at"`
	App           jsonApp          `json:"app"`
	Scan          jsonScan         `json:"scan"`
	Block         *jsonBlock       `json:"block"`
	BlockVerify   *jsonBlockVerify `json:"block_verify"`
	Clean         *jsonClean       `json:"clean"`
	Exposure      *jsonExposure    `json:"exposure"`
	Actions       []jsonAction     `json:"actions"`
}

type jsonApp struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	OS             string `json:"os"`
	Arch           string `json:"arch"`
	User           string `json:"user"`
	Elevated       bool   `json:"elevated"`
	ElevationMode  string `json:"elevation_mode"`
	CanBlock       bool   `json:"can_block"`
	CanClean       bool   `json:"can_clean"`
	RulesetVersion string `json:"ruleset_version"`
}

type jsonScan struct {
	ID          string        `json:"id"`
	Verdict     string        `json:"verdict"`
	RulesetVer  string        `json:"ruleset_ver"`
	StartedAt   string        `json:"started_at"`
	FinishedAt  string        `json:"finished_at"`
	Limitations []string      `json:"limitations"`
	Targets     []jsonTarget  `json:"targets"`
	Findings    []jsonFinding `json:"findings"`
}

type jsonTarget struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	Note   string `json:"note"`
}

type jsonFinding struct {
	RuleID     string `json:"rule_id"`
	Title      string `json:"title"`
	Detail     string `json:"detail"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Path       string `json:"path"`
	Offset     int64  `json:"offset"`
	Snippet    string `json:"snippet"`
	SHA256     string `json:"sha256"`
	MTime      string `json:"mtime"`
}

type jsonBlock struct {
	HostsApplied bool         `json:"hosts_applied"`
	HostsPath    string       `json:"hosts_path"`
	Rules        []jsonFWRule `json:"rules"`
	Persisted    bool         `json:"persisted"`
	Verified     bool         `json:"verified"`
	Failures     []string     `json:"failures"`
	Warnings     []string     `json:"warnings"`
}

type jsonFWRule struct {
	Name      string `json:"name"`
	Detail    string `json:"detail"`
	Installed bool   `json:"installed"`
}

type jsonBlockVerify struct {
	HostsOK       bool     `json:"hosts_ok"`
	HostsDetail   string   `json:"hosts_detail"`
	FirewallOK    bool     `json:"firewall_ok"`
	FirewallNotes []string `json:"firewall_notes"`
	AllOK         bool     `json:"all_ok"`
}

type jsonClean struct {
	Quarantined     int          `json:"quarantined"`
	Deleted         int          `json:"deleted"`
	Skipped         int          `json:"skipped"`
	Failures        []string     `json:"failures"`
	RequiresRestart bool         `json:"requires_restart"`
	QuarantineDir   string       `json:"quarantine_dir"`
	Actions         []jsonAction `json:"actions"`
}

type jsonExposure struct {
	StartedAt   string             `json:"started_at"`
	FinishedAt  string             `json:"finished_at"`
	Limitations []string           `json:"limitations"`
	Categories  []jsonCategory     `json:"categories"`
	Items       []jsonExposureItem `json:"items"`
}

type jsonCategory struct {
	Name    string `json:"name"`
	Total   int    `json:"total"`
	Present int    `json:"present"`
}

type jsonExposureItem struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Label    string `json:"label"`
	Path     string `json:"path"`
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Action   string `json:"action"`
	Exists   bool   `json:"exists"`
	Size     int64  `json:"size"`
	MTime    string `json:"mtime"`
	Note     string `json:"note"`
}

type jsonAction struct {
	At     string `json:"at"`
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// JSON encodes the report as a stable snake_case envelope.
func JSON(r model.ReportData) ([]byte, error) {
	env := envelope{
		SchemaVersion: schemaVersion,
		GeneratedAt:   ts(r.GeneratedAt),
		App: jsonApp{
			Name:           r.App.Name,
			Version:        r.App.Version,
			OS:             r.App.OS,
			Arch:           r.App.Arch,
			User:           r.App.User,
			Elevated:       r.App.Elevated,
			ElevationMode:  r.App.ElevationMode,
			CanBlock:       r.App.CanBlock,
			CanClean:       r.App.CanClean,
			RulesetVersion: r.App.RulesetVersion,
		},
		Scan: jsonScan{
			ID:          r.Scan.ID,
			Verdict:     r.Scan.Verdict,
			RulesetVer:  r.Scan.RulesetVer,
			StartedAt:   ts(r.Scan.StartedAt),
			FinishedAt:  ts(r.Scan.FinishedAt),
			Limitations: nonNil(r.Scan.Limitations),
			Targets:     make([]jsonTarget, 0, len(r.Scan.Targets)),
			Findings:    make([]jsonFinding, 0, len(r.Scan.Findings)),
		},
		Actions: make([]jsonAction, 0, len(r.Actions)),
	}
	for _, t := range r.Scan.Targets {
		env.Scan.Targets = append(env.Scan.Targets, jsonTarget{
			ID: t.ID, Kind: t.Kind, Path: t.Path, Exists: t.Exists, Note: t.Note,
		})
	}
	for _, f := range r.Scan.Findings {
		env.Scan.Findings = append(env.Scan.Findings, jsonFinding{
			RuleID:     f.RuleID,
			Title:      f.Title,
			Detail:     f.Detail,
			Severity:   f.Severity,
			Confidence: f.Confidence,
			Path:       f.Path,
			Offset:     f.Offset,
			Snippet:    f.Snippet,
			SHA256:     f.SHA256,
			MTime:      ts(f.MTime),
		})
	}
	if r.Block != nil {
		jb := &jsonBlock{
			HostsApplied: r.Block.HostsApplied,
			HostsPath:    r.Block.HostsPath,
			Rules:        make([]jsonFWRule, 0, len(r.Block.Rules)),
			Persisted:    r.Block.Persisted,
			Verified:     r.Block.Verified,
			Failures:     nonNil(r.Block.Failures),
			Warnings:     nonNil(r.Block.Warnings),
		}
		for _, rule := range r.Block.Rules {
			jb.Rules = append(jb.Rules, jsonFWRule{Name: rule.Name, Detail: rule.Detail, Installed: rule.Installed})
		}
		env.Block = jb
	}
	if r.BlockVerify != nil {
		env.BlockVerify = &jsonBlockVerify{
			HostsOK:       r.BlockVerify.HostsOK,
			HostsDetail:   r.BlockVerify.HostsDetail,
			FirewallOK:    r.BlockVerify.FirewallOK,
			FirewallNotes: nonNil(r.BlockVerify.FirewallNotes),
			AllOK:         r.BlockVerify.AllOK,
		}
	}
	if r.Clean != nil {
		jc := &jsonClean{
			Quarantined:     r.Clean.Quarantined,
			Deleted:         r.Clean.Deleted,
			Skipped:         r.Clean.Skipped,
			Failures:        nonNil(r.Clean.Failures),
			RequiresRestart: r.Clean.RequiresRestart,
			QuarantineDir:   r.Clean.QuarantineDir,
			Actions:         make([]jsonAction, 0, len(r.Clean.Actions)),
		}
		for _, a := range r.Clean.Actions {
			jc.Actions = append(jc.Actions, jsonAction{At: ts(a.At), Kind: a.Kind, Detail: a.Detail})
		}
		env.Clean = jc
	}
	if r.Exposure != nil {
		je := &jsonExposure{
			StartedAt:   ts(r.Exposure.StartedAt),
			FinishedAt:  ts(r.Exposure.FinishedAt),
			Limitations: nonNil(r.Exposure.Limitations),
			Categories:  make([]jsonCategory, 0, len(r.Exposure.Categories)),
			Items:       make([]jsonExposureItem, 0, len(r.Exposure.Items)),
		}
		for _, c := range r.Exposure.Categories {
			je.Categories = append(je.Categories, jsonCategory{Name: c.Name, Total: c.Total, Present: c.Present})
		}
		for _, it := range r.Exposure.Items {
			je.Items = append(je.Items, jsonExposureItem{
				ID: it.ID, Category: it.Category, Label: it.Label, Path: it.Path,
				Kind: it.Kind, Severity: it.Severity, Action: it.Action,
				Exists: it.Exists, Size: it.Size, MTime: ts(it.MTime), Note: it.Note,
			})
		}
		env.Exposure = je
	}
	for _, a := range r.Actions {
		env.Actions = append(env.Actions, jsonAction{At: ts(a.At), Kind: a.Kind, Detail: a.Detail})
	}
	return json.MarshalIndent(env, "", "  ")
}

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
