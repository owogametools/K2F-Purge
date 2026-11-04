// Package service is the app's use-case layer: it owns the rules, remembers
// what the user did, and calls the scanner and the system packages. The
// interface calls it; it never calls the interface.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/owogametools/k2f-purge/internal/astrlink"
	"github.com/owogametools/k2f-purge/internal/block"
	"github.com/owogametools/k2f-purge/internal/clean"
	"github.com/owogametools/k2f-purge/internal/elev"
	"github.com/owogametools/k2f-purge/internal/exposure"
	"github.com/owogametools/k2f-purge/internal/ioc"
	"github.com/owogametools/k2f-purge/internal/model"
	"github.com/owogametools/k2f-purge/internal/report"
	"github.com/owogametools/k2f-purge/internal/scan"
	"github.com/owogametools/k2f-purge/internal/secrets"
)

// Service holds the engine state for one window.
type Service struct {
	rules *ioc.Rules
	info  model.AppInfo

	mu          sync.Mutex
	scan        *model.ScanResult
	block       *model.BlockStatus
	blockVerify *model.BlockVerify
	clean       *model.CleanResult
	exposure    *model.ExposureResult
	actions     []model.Action
	cancel      context.CancelFunc
}

// New loads the embedded rules and reports what this process may do.
func New(name, version, goos, goarch, user string) (*Service, error) {
	rules, err := ioc.Load()
	if err != nil {
		return nil, err
	}
	mode := elev.Mode()
	s := &Service{rules: rules}
	s.info = model.AppInfo{
		Name:           name,
		Version:        version,
		OS:             goos,
		Arch:           goarch,
		User:           user,
		Elevated:       elev.IsElevated(),
		ElevationMode:  mode,
		CanBlock:       mode != "limited",
		CanClean:       mode != "limited",
		RulesetVersion: rules.Version,
	}
	return s, nil
}

// Info describes the app and the privileges it has.
func (s *Service) Info() model.AppInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.info
}

// Rules is the loaded ruleset.
func (s *Service) Rules() *ioc.Rules { return s.rules }

// Action records something the user did.
func (s *Service) Action(kind, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.actions = append(s.actions, model.Action{At: time.Now(), Kind: kind, Detail: detail})
}

// Cancel stops the running long action, if any.
func (s *Service) Cancel() {
	s.mu.Lock()
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Service) startCancelable() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.cancel = cancel
	s.mu.Unlock()
	return ctx, func() {
		cancel()
		s.mu.Lock()
		if s.cancel != nil {
			s.cancel = nil
		}
		s.mu.Unlock()
	}
}

// Scan runs the detection engine and remembers the result.
func (s *Service) Scan(opts model.ScanOptions, emit func(model.ScanEvent)) (*model.ScanResult, error) {
	ctx, done := s.startCancelable()
	defer done()

	res, err := scan.Run(ctx, s.rules, opts, emit)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.scan = res
	s.actions = append(s.actions, model.Action{At: time.Now(), Kind: "scan", Detail: "verdict " + res.Verdict})
	s.mu.Unlock()
	return res, nil
}

// LastScan returns the most recent scan, if any.
func (s *Service) LastScan() *model.ScanResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scan
}

// BlockPlan is the default plan for the incident's indicators.
func (s *Service) BlockPlan() model.BlockPlan {
	return block.Plan(s.rules.Domains, s.rules.IPs)
}

// BlockApply installs the hosts and firewall blocks.
func (s *Service) BlockApply(p model.BlockPlan, emit func(model.Progress)) (*model.BlockStatus, error) {
	ctx, done := s.startCancelable()
	defer done()

	st, verify, err := s.runBlockOp(ctx, "block.apply", p, emit, func(st *model.BlockStatus) *model.BlockVerify {
		v := block.Verify(context.Background(), len(p.ProgramPaths) > 0)
		st.Verified = v.AllOK
		return &v
	})
	if err != nil {
		return st, err
	}
	s.rememberBlock(st, verify, "block", "applied")
	return st, nil
}

// BlockRemove removes only the rules this app owns.
func (s *Service) BlockRemove(emit func(model.Progress)) (*model.BlockStatus, error) {
	ctx, done := s.startCancelable()
	defer done()

	st, verify, err := s.runBlockOp(ctx, "block.remove", model.BlockPlan{}, emit, func(st *model.BlockStatus) *model.BlockVerify {
		v := block.Verify(context.Background(), false)
		st.Verified = !v.HostsOK && !v.FirewallOK
		return &v
	})
	if err != nil {
		return st, err
	}
	s.rememberBlock(st, verify, "unblock", "removed")
	return st, nil
}

// runBlockOp runs the block work in this process when it already holds the
// rights, and through the `--elevated-op` child otherwise (Linux and macOS,
// where the GUI itself stays unprivileged). A child cannot stream progress,
// so that path reports whole steps before and after.
func (s *Service) runBlockOp(ctx context.Context, op string, p model.BlockPlan, emit func(model.Progress), verify func(*model.BlockStatus) *model.BlockVerify) (*model.BlockStatus, *model.BlockVerify, error) {
	if elev.Mode() == elev.ModeLimited {
		return nil, nil, errors.New("blocking needs administrator rights: relaunch K2F PURGE and accept the UAC prompt")
	}
	if elev.Mode() != elev.ModePerOp {
		var (
			st  *model.BlockStatus
			err error
		)
		if op == "block.remove" {
			st, err = block.Remove(ctx, emit)
		} else {
			st, err = block.Apply(ctx, p, emit)
		}
		if err != nil {
			return st, nil, err
		}
		return st, verify(st), nil
	}
	if emit != nil {
		emit(model.Progress{Current: op + ": waiting for administrator approval"})
	}
	raw, err := elev.RunPrivileged(ctx, op, p)
	if err != nil {
		return nil, nil, err
	}
	var st model.BlockStatus
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, nil, fmt.Errorf("elevated %s: %w", op, err)
	}
	if emit != nil {
		emit(model.Progress{Current: op + ": done", Done: 1, Total: 1})
	}
	// The child already verified inside its privileged context; asking the
	// unprivileged parent would only report a false negative.
	v := model.BlockVerify{HostsDetail: "verified by the elevated helper"}
	if op == "block.remove" {
		// Verified here means "the block is gone", so both checks stay
		// false: hosts is not sinkholed and no rule is present.
		v.AllOK = st.Verified
		return &st, &v, nil
	}
	v.HostsOK = st.HostsApplied
	v.FirewallOK = st.Verified
	v.AllOK = st.Verified
	for _, r := range st.Rules {
		if !r.Installed {
			v.FirewallOK = false
			v.AllOK = false
		}
	}
	return &st, &v, nil
}

func (s *Service) rememberBlock(st *model.BlockStatus, verify *model.BlockVerify, kind, detail string) {
	s.mu.Lock()
	s.block = st
	s.blockVerify = verify
	s.actions = append(s.actions, model.Action{At: time.Now(), Kind: kind, Detail: detail})
	s.mu.Unlock()
}

// BlockVerify checks the block independently. expectProgram also checks the
// tbs_browser.exe program rules.
func (s *Service) BlockVerify(expectProgram bool) model.BlockVerify {
	v := block.Verify(context.Background(), expectProgram)
	s.mu.Lock()
	s.blockVerify = &v
	s.mu.Unlock()
	return v
}

// TBSBrowserPath resolves the launcher's embedded browser. The custom
// Launcher directory wins; otherwise the launcher installs from the last
// scan are tried. Both the install root and the Launcher folder are
// accepted.
func (s *Service) TBSBrowserPath(extraDirs []string) (string, bool) {
	roots := append([]string(nil), extraDirs...)
	s.mu.Lock()
	if s.scan != nil {
		for _, t := range s.scan.Targets {
			if t.Kind == model.TargetLauncherInstall {
				roots = append(roots, t.Path)
			}
		}
	}
	s.mu.Unlock()
	return scan.FindTBSBrowser(roots)
}

// CleanPlan builds the dry run from the last scan.
func (s *Service) CleanPlan() (*model.CleanPlan, error) {
	s.mu.Lock()
	last := s.scan
	s.mu.Unlock()
	if last == nil {
		return nil, errors.New("scan first: there is nothing to clean")
	}
	return clean.Plan(last)
}

// CleanApply quarantines or deletes the chosen items.
func (s *Service) CleanApply(plan *model.CleanPlan, ids []string, mode model.CleanMode, emit func(model.Progress)) (*model.CleanResult, error) {
	ctx, done := s.startCancelable()
	defer done()

	res, err := clean.Apply(ctx, plan, ids, mode, emit)
	if err != nil {
		return res, err
	}
	s.mu.Lock()
	s.clean = res
	s.actions = append(s.actions, model.Action{At: time.Now(), Kind: "clean", Detail: string(mode)})
	s.mu.Unlock()
	return res, nil
}

// QuarantineList lists what is held for restore.
func (s *Service) QuarantineList() ([]model.QuarantineEntry, error) { return clean.QuarantineList() }

// QuarantineRestore puts quarantined items back.
func (s *Service) QuarantineRestore(ids []string) error {
	ctx, done := s.startCancelable()
	defer done()
	if err := clean.Restore(ctx, ids); err != nil {
		return err
	}
	s.Action("restore", "restored quarantined items")
	return nil
}

// QuarantinePurge deletes quarantined items for good.
func (s *Service) QuarantinePurge(ids []string) error {
	ctx, done := s.startCancelable()
	defer done()
	if err := clean.Purge(ctx, ids); err != nil {
		return err
	}
	s.Action("purge", "deleted quarantined items")
	return nil
}

// ExposureScan checks which credential paths exist.
func (s *Service) ExposureScan(opts model.ExposureOptions, emit func(model.Progress)) (*model.ExposureResult, error) {
	ctx, done := s.startCancelable()
	defer done()

	res, err := exposure.Scan(ctx, opts, emit)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.exposure = res
	s.actions = append(s.actions, model.Action{At: time.Now(), Kind: "exposure", Detail: "completed"})
	s.mu.Unlock()
	return res, nil
}

// SecretScan reads the files the exposure catalogue found and lists the
// credentials inside them. It is a separate, explicit action: the path
// check above never opens a file.
func (s *Service) SecretScan(emit func(model.Progress)) (*model.SecretResult, error) {
	s.mu.Lock()
	exp := s.exposure
	s.mu.Unlock()
	if exp == nil {
		return nil, errors.New("run the exposure check first")
	}
	ctx, done := s.startCancelable()
	defer done()

	res, err := secrets.Scan(ctx, exp.Items, emit)
	if res != nil {
		s.mu.Lock()
		exp.Secrets = res
		s.actions = append(s.actions, model.Action{
			At:     time.Now(),
			Kind:   "secrets",
			Detail: fmt.Sprintf("content scan: %d findings", len(res.Findings)),
		})
		s.mu.Unlock()
	}
	return res, err
}

// AstrLinkStatus reports whether the bundled model is readable. It never
// downloads anything.
func (s *Service) AstrLinkStatus() model.AstrLinkStatus { return astrlink.Lookup() }

// AstrLinkScan runs the optional local model over the same files the
// exposure catalogue found. It needs an exposure result and a model that
// is already on disk.
func (s *Service) AstrLinkScan(emit func(model.Progress)) (*model.SecretResult, error) {
	s.mu.Lock()
	exp := s.exposure
	s.mu.Unlock()
	if exp == nil {
		return nil, errors.New("run the exposure check first")
	}
	if st := astrlink.Lookup(); !st.Available {
		if st.Note == "" {
			st.Note = "model files are missing"
		}
		return nil, fmt.Errorf("AstrLink model unavailable: %s", st.Note)
	}
	ctx, done := s.startCancelable()
	defer done()

	res, err := astrlink.Scan(ctx, exp.Items, emit)
	if res != nil {
		s.mu.Lock()
		exp.AstrLink = res
		s.actions = append(s.actions, model.Action{
			At:     time.Now(),
			Kind:   "astrlink",
			Detail: fmt.Sprintf("model scan: %d findings", len(res.Findings)),
		})
		s.mu.Unlock()
	}
	return res, err
}

// ExposureMarkdown is the rotation checklist.
func (s *Service) ExposureMarkdown() string {
	s.mu.Lock()
	res := s.exposure
	s.mu.Unlock()
	if res == nil {
		return ""
	}
	return exposure.ExportMarkdown(res)
}

// ReportData gathers everything the user did in this session.
func (s *Service) ReportData() model.ReportData {
	s.mu.Lock()
	defer s.mu.Unlock()
	data := model.ReportData{
		App:         s.info,
		Block:       s.block,
		BlockVerify: s.blockVerify,
		Clean:       s.clean,
		Exposure:    s.exposure,
		Actions:     append([]model.Action(nil), s.actions...),
		GeneratedAt: time.Now(),
	}
	if s.scan != nil {
		data.Scan = *s.scan
	}
	return data
}

// SaveReport writes the markdown and JSON report to dir.
func (s *Service) SaveReport(dir string) (string, error) {
	path, err := report.Save(dir, s.ReportData())
	if err != nil {
		return "", err
	}
	s.Action("report", path)
	return path, nil
}
