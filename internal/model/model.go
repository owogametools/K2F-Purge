// Package model holds the data types shared by the scanner, the system
// actions and the interface. It is the only cross-layer contract: no other
// package defines a second copy of these shapes.
package model

import "time"

// AppInfo describes the running app and what it may do on this machine.
type AppInfo struct {
	Name           string
	Version        string
	OS             string
	Arch           string
	User           string
	Elevated       bool
	ElevationMode  string // "elevated" | "limited" | "per-op"
	CanBlock       bool
	CanClean       bool
	RulesetVersion string
}

// ScanOptions narrows or widens a scan.
type ScanOptions struct {
	ExtraLauncherDirs []string
	ExtraPrefixes     []string
	IncludeDNSCache   bool
	MaxFileMB         int
}

// Target kinds.
const (
	TargetLauncherData    = "launcher-data"
	TargetLauncherInstall = "launcher-install"
	TargetChromeProfile   = "chrome-profile"
	TargetWinePrefix      = "wine-prefix"
	TargetTemp            = "temp"
	TargetChromeHelper    = "chrome-helper"
)

// ScanTarget is a place the engine looked, and whether it exists.
type ScanTarget struct {
	ID     string
	Kind   string
	Path   string
	Exists bool
	Note   string
}

// Severity and confidence of a finding.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityInfo     = "info"

	ConfidenceConfirmed = "confirmed"
	ConfidenceLikely    = "likely"
	ConfidenceInfo      = "info"
)

// Finding is one piece of evidence.
type Finding struct {
	RuleID string
	Title  string
	Detail string
	// TitleZH, DetailZH, TitleJA and DetailJA are the Traditional
	// Chinese and Japanese copy from the ruleset. They are empty
	// for an overlay that omits them, and the interface falls back
	// to the English text.
	TitleZH    string
	DetailZH   string
	TitleJA    string
	DetailJA   string
	Severity   string
	Confidence string
	Path       string
	Offset     int64
	Snippet    string
	SHA256     string
	MTime      time.Time
}

// Progress reports work done inside a long action.
type Progress struct {
	Done    int
	Total   int
	Current string
}

// ScanEvent is emitted while a scan runs.
type ScanEvent struct {
	Type     string // "target" | "progress" | "finding" | "log" | "error" | "done"
	Target   *ScanTarget
	Progress *Progress
	Finding  *Finding
	Line     string
	Err      string
}

// Verdict values, from strongest to weakest.
const (
	VerdictConfirmed    = "CONFIRMED"
	VerdictLikely       = "LIKELY"
	VerdictInconclusive = "INCONCLUSIVE"
	VerdictClear        = "CLEAR_OF_LISTED_IOCS"
)

// ScanResult is the outcome of one scan.
type ScanResult struct {
	ID          string
	Verdict     string
	Findings    []Finding
	Targets     []ScanTarget
	RulesetVer  string
	StartedAt   time.Time
	FinishedAt  time.Time
	Limitations []string
}

// BlockPlan says what to block and how.
type BlockPlan struct {
	Domains     []string
	IPs         []string
	UseHosts    bool
	UseFirewall bool
	Persist     bool
	FlushDNS    bool
}

// FirewallRule is one rule the app owns.
type FirewallRule struct {
	Name      string
	Detail    string
	Installed bool
}

// BlockStatus is the result of applying or removing blocks.
type BlockStatus struct {
	HostsApplied bool
	HostsPath    string
	Rules        []FirewallRule
	Persisted    bool
	Verified     bool
	Failures     []string
	Warnings     []string
}

// BlockVerify is an independent check of the block.
type BlockVerify struct {
	HostsOK       bool
	HostsDetail   string
	FirewallOK    bool
	FirewallNotes []string
	AllOK         bool
}

// Clean item kinds.
const (
	CleanRegistryCLSID  = "registry_clsid"
	CleanChromeHelper   = "chrome_helper"
	CleanChromeLeftover = "chrome_leftover"
	CleanLauncherCache  = "launcher_cache"
	CleanTinygetPayload = "tinyget_payload"
	CleanTempArtifacts  = "temp_artifacts"
	CleanWineArtifact   = "wine_artifact"
)

// CleanItem is one thing the cleanup would handle.
type CleanItem struct {
	ID              string
	Kind            string
	Path            string
	Reason          string
	ReasonZH        string
	ReasonJA        string
	RuleID          string
	Size            int64
	Locked          bool
	RequiresRestart bool
}

// CleanPlan is the dry run the user reviews.
type CleanPlan struct {
	ScanID          string
	Items           []CleanItem
	RequiresRestart bool
	Warnings        []string
}

// CleanMode selects quarantine or permanent deletion.
type CleanMode string

const (
	CleanQuarantine CleanMode = "quarantine"
	CleanDelete     CleanMode = "delete"
)

// CleanResult reports what cleanup did.
type CleanResult struct {
	Quarantined     int
	Deleted         int
	Skipped         int
	Failures        []string
	RequiresRestart bool
	QuarantineDir   string
	Actions         []Action
}

// QuarantineEntry is one item held in quarantine.
type QuarantineEntry struct {
	ID              string
	OriginalPath    string
	QuarantinedPath string
	RuleID          string
	SHA256          string
	Size            int64
	MTime           time.Time
	CreatedAt       time.Time
}

// ExposureOptions tunes the exposure scan.
type ExposureOptions struct {
	IncludeWine   bool
	ExtraPrefixes []string
}

// ExposureItem is one credential or config path from the incident report.
type ExposureItem struct {
	ID       string
	Category string
	Label    string
	Path     string
	Kind     string // "file" | "dir" | "glob" | "registry" | "env"
	Severity string
	Action   string
	Exists   bool
	Size     int64
	MTime    time.Time
	Note     string
}

// ExposureCategory summarizes one group.
type ExposureCategory struct {
	Name    string
	Total   int
	Present int
}

// ExposureResult is the outcome of the exposure scan.
type ExposureResult struct {
	Items       []ExposureItem
	Categories  []ExposureCategory
	StartedAt   time.Time
	FinishedAt  time.Time
	Limitations []string
}

// Action is one thing the user did, in order.
type Action struct {
	At     time.Time
	Kind   string
	Detail string
}

// ReportData is everything a saved report contains.
type ReportData struct {
	App         AppInfo
	Scan        ScanResult
	Block       *BlockStatus
	BlockVerify *BlockVerify
	Clean       *CleanResult
	Exposure    *ExposureResult
	Actions     []Action
	GeneratedAt time.Time
}
