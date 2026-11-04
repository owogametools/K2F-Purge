package scan

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/owogametools/k2f-purge/internal/ioc"
	"github.com/owogametools/k2f-purge/internal/model"
)

const (
	defaultMaxMB = 128
	maxWorkers   = 4
)

// Run discovers targets from the live environment and scans them.
func Run(ctx context.Context, rules *ioc.Rules, opts model.ScanOptions, emit func(model.ScanEvent)) (*model.ScanResult, error) {
	return RunWithPaths(ctx, DefaultPaths(), rules, opts, emit)
}

// RunWithPaths is Run with an injected path snapshot. Tests use this so the
// live disk is never touched.
func RunWithPaths(ctx context.Context, p Paths, rules *ioc.Rules, opts model.ScanOptions, emit func(model.ScanEvent)) (*model.ScanResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if rules == nil {
		loaded, err := ioc.Load()
		if err != nil {
			return nil, err
		}
		rules = loaded
	}
	if err := rules.Validate(); err != nil {
		return nil, err
	}
	if opts.MaxFileMB <= 0 {
		opts.MaxFileMB = defaultMaxMB
	}
	maxBytes := int64(opts.MaxFileMB) * 1024 * 1024

	emitFn := func(ev model.ScanEvent) {
		if emit != nil {
			emit(ev)
		}
	}

	result := &model.ScanResult{
		ID:         newScanID(),
		RulesetVer: rules.Version,
		StartedAt:  time.Now().UTC(),
	}

	targets := DiscoverTargets(p, opts)
	result.Targets = targets
	for i := range targets {
		t := targets[i]
		emitFn(model.ScanEvent{Type: "target", Target: &t, Line: "target " + t.Kind + " " + t.Path})
	}

	var limitations []string
	if p.GOOS != "windows" {
		limitations = append(limitations, "Chrome PlatformExperienceHelper check skipped: GOOS is not windows")
	}
	if !registrySupported() {
		limitations = append(limitations, "HKCU CLSID registry check skipped: not a Windows build")
	}

	files, extra := collectFiles(targets, p.GOOS)
	limitations = append(limitations, extra...)
	if hasLauncher(targets) && !hasScopeFiles(files, "launcher-log") {
		limitations = append(limitations, "launcher debug.log not found; logs may have rotated or been deleted")
	}
	if !hasLauncher(targets) {
		limitations = append(limitations, "no NIKKE launcher data or install directory was found")
	}

	var (
		mu       sync.Mutex
		findings []model.Finding
		seen     = map[string]struct{}{}
	)
	addFinding := func(f model.Finding) {
		if f.Snippet != "" {
			f.Snippet = sanitizeSnippet(f.Snippet)
		}
		key := f.RuleID + "\x00" + strings.ToLower(filepath.ToSlash(f.Path))
		mu.Lock()
		defer mu.Unlock()
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		findings = append(findings, f)
		cp := f
		emitFn(model.ScanEvent{Type: "finding", Finding: &cp})
	}

	for _, c := range rules.Checks {
		if c.Kind != "registry_key" {
			continue
		}
		if !registrySupported() {
			continue
		}
		if err := ctx.Err(); err != nil {
			return finish(result, findings, limitations, emitFn, err)
		}
		if forbiddenRegistryKey(c.Pattern) {
			limitations = append(limitations, "refused registry check "+c.ID+": HKLM is forbidden")
			continue
		}
		emitFn(model.ScanEvent{Type: "log", Line: "registry query " + c.Pattern})
		exists, err := registryQuery(c.Pattern)
		if err != nil {
			limitations = append(limitations, "registry query failed for "+c.ID+": "+err.Error())
			emitFn(model.ScanEvent{Type: "error", Err: err.Error()})
			continue
		}
		if exists {
			addFinding(model.Finding{
				RuleID:     c.ID,
				Title:      c.Title,
				Detail:     c.Detail,
				TitleZH:    c.TitleZH,
				DetailZH:   c.DetailZH,
				TitleJA:    c.TitleJA,
				DetailJA:   c.DetailJA,
				Severity:   c.Severity,
				Confidence: c.Confidence,
				Path:       c.Pattern,
			})
		}
	}

	wantHash := false
	for _, c := range rules.Checks {
		if c.Kind == "hash" {
			wantHash = true
			break
		}
	}

	total := len(files)
	if total == 0 {
		total = 1
	}
	var done atomic.Int32
	progress := func(current string) {
		n := int(done.Add(1))
		emitFn(model.ScanEvent{
			Type:     "progress",
			Progress: &model.Progress{Done: n, Total: total, Current: current},
			Line:     current,
		})
	}

	jobs := make(chan fileRef)
	var wg sync.WaitGroup
	workers := maxWorkers
	if len(files) < workers {
		workers = len(files)
	}
	if workers < 1 {
		workers = 1
	}
	worker := func() {
		defer wg.Done()
		for ref := range jobs {
			if ctx.Err() != nil {
				return
			}
			processFile(ref, rules, wantHash, maxBytes, addFinding, emitFn, &limitations, &mu)
			progress(ref.path)
		}
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker()
	}
	for _, ref := range files {
		if ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
		case jobs <- ref:
		}
	}
	close(jobs)
	wg.Wait()

	result.Findings = findings
	result.Limitations = limitations
	result.Verdict = Verdict(findings, targets)
	result.FinishedAt = time.Now().UTC()
	emitFn(model.ScanEvent{Type: "done", Line: result.Verdict})
	if err := ctx.Err(); err != nil {
		result.Limitations = append(result.Limitations, "scan cancelled")
		if result.Verdict == model.VerdictClear {
			result.Verdict = model.VerdictInconclusive
		}
		return result, err
	}
	return result, nil
}

func finish(result *model.ScanResult, findings []model.Finding, limitations []string, emitFn func(model.ScanEvent), err error) (*model.ScanResult, error) {
	result.Findings = findings
	result.Limitations = append(limitations, "scan cancelled")
	result.Verdict = model.VerdictInconclusive
	result.FinishedAt = time.Now().UTC()
	emitFn(model.ScanEvent{Type: "done", Line: result.Verdict})
	return result, err
}

func processFile(ref fileRef, rules *ioc.Rules, wantHash bool, maxBytes int64, addFinding func(model.Finding), emitFn func(model.ScanEvent), limitations *[]string, mu *sync.Mutex) {
	base := filepath.Base(ref.path)
	parent := filepath.Base(filepath.Dir(ref.path))

	for _, c := range rules.Checks {
		if !scopeApplies(c.Scope, ref.scopes) && c.Kind != "hash" {
			continue
		}
		switch c.Kind {
		case "filename":
			if matchFilename(c.Pattern, base) {
				addFinding(fileFinding(c, ref.path, 0, base, "", time.Time{}))
			}
		case "dir_glob":
			if c.Scope == "chrome-helper" && strings.EqualFold(base, "platform_experience_helper.dll") && isHex64(parent) {
				addFinding(fileFinding(c, ref.path, 0, base, "", time.Time{}))
			}
		}
	}

	needles := needlesFor(ref.scopes, rules.Checks)
	needRead := wantHash || len(needles) > 0
	if !needRead {
		return
	}

	res := scanFile(ref.path, needles, wantHash, maxBytes)
	if res.tooLarge {
		mu.Lock()
		*limitations = append(*limitations, fmt.Sprintf("skipped %s: exceeds %d MB", ref.path, maxBytes/(1024*1024)))
		mu.Unlock()
		emitFn(model.ScanEvent{Type: "log", Line: "skip too large " + ref.path})
		return
	}
	if res.readErr != nil {
		mu.Lock()
		*limitations = append(*limitations, "read error "+ref.path+": "+res.readErr.Error())
		mu.Unlock()
		emitFn(model.ScanEvent{Type: "error", Err: res.readErr.Error(), Line: ref.path})
		return
	}
	for _, h := range res.hits {
		addFinding(fileFinding(h.check, ref.path, h.offset, h.snippet, firstNonEmpty(h.sha256, res.sha256), h.mtime))
	}
	if res.hashed {
		for _, c := range rules.Checks {
			if c.Kind != "hash" {
				continue
			}
			if hashMatches(c, res.sha256, rules.SHA256) {
				addFinding(fileFinding(c, ref.path, 0, res.sha256, res.sha256, res.mtime))
			}
		}
	}

	for _, c := range rules.Checks {
		if c.Kind != "regex" || !scopeApplies(c.Scope, ref.scopes) {
			continue
		}
		re, err := regexp.Compile(c.Pattern)
		if err != nil {
			mu.Lock()
			*limitations = append(*limitations, "invalid regex "+c.ID+": "+err.Error())
			mu.Unlock()
			continue
		}
		if hit, off, snip := regexSearchFile(ref.path, re, maxBytes); hit {
			addFinding(fileFinding(c, ref.path, off, snip, res.sha256, res.mtime))
		}
	}
}

func fileFinding(c ioc.Check, path string, offset int64, snippet, sum string, mtime time.Time) model.Finding {
	if mtime.IsZero() {
		if st, err := os.Lstat(path); err == nil {
			mtime = st.ModTime()
			if sum == "" && st.Size() <= 8<<20 {
				if h, err := hashFile(path, st.Size()); err == nil {
					sum = h
				}
			}
		}
	}
	return model.Finding{
		RuleID:     c.ID,
		Title:      c.Title,
		Detail:     c.Detail,
		TitleZH:    c.TitleZH,
		DetailZH:   c.DetailZH,
		TitleJA:    c.TitleJA,
		DetailJA:   c.DetailJA,
		Severity:   c.Severity,
		Confidence: c.Confidence,
		Path:       path,
		Offset:     offset,
		Snippet:    snippet,
		SHA256:     sum,
		MTime:      mtime,
	}
}

func needlesFor(scopes []string, checks []ioc.Check) []needle {
	var out []needle
	for _, c := range checks {
		if c.Kind != "contains" && !(c.Kind == "filename" && c.Scope == "code-cache") {
			continue
		}
		if !scopeApplies(c.Scope, scopes) {
			continue
		}
		for _, part := range splitPat(c.Pattern) {
			out = append(out, needle{check: c, pat: []byte(part)})
		}
	}
	return out
}

func scopeApplies(scope string, scopes []string) bool {
	if scope == "any" || scope == "" {
		return true
	}
	return hasScope(scopes, scope)
}

func matchFilename(pattern, name string) bool {
	for _, part := range splitPat(pattern) {
		if strings.ContainsAny(part, "*?[") {
			ok, err := filepath.Match(part, name)
			if err == nil && ok {
				return true
			}
			ok, err = filepath.Match(strings.ToLower(part), strings.ToLower(name))
			if err == nil && ok {
				return true
			}
			continue
		}
		if strings.EqualFold(part, name) {
			return true
		}
		lowerName := strings.ToLower(name)
		lowerPart := strings.ToLower(part)
		if strings.HasPrefix(lowerName, lowerPart) {
			return true
		}
	}
	return false
}

func splitPat(p string) []string {
	raw := strings.Split(p, "|")
	out := make([]string, 0, len(raw))
	for _, part := range raw {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func hashMatches(c ioc.Check, sum string, all []string) bool {
	if sum == "" {
		return false
	}
	if strings.TrimSpace(c.Pattern) == "" {
		for _, h := range all {
			if strings.EqualFold(h, sum) {
				return true
			}
		}
		return false
	}
	for _, part := range splitPat(c.Pattern) {
		if strings.EqualFold(part, sum) {
			return true
		}
	}
	return false
}

func hasLauncher(targets []model.ScanTarget) bool {
	for _, t := range targets {
		if !t.Exists {
			continue
		}
		if t.Kind == model.TargetLauncherData || t.Kind == model.TargetLauncherInstall {
			return true
		}
	}
	return false
}

func hasScopeFiles(files []fileRef, scope string) bool {
	for _, f := range files {
		if hasScope(f.scopes, scope) {
			return true
		}
	}
	return false
}

func forbiddenRegistryKey(key string) bool {
	u := strings.ToUpper(key)
	return strings.Contains(u, "HKEY_LOCAL_MACHINE") || strings.HasPrefix(u, "HKLM\\")
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func newScanID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b[:])
}

func regexSearchFile(path string, re *regexp.Regexp, maxBytes int64) (bool, int64, string) {
	res := scanFile(path, nil, false, maxBytes)
	if res.tooLarge || res.readErr != nil {
		return false, 0, ""
	}
	f, err := os.Open(path)
	if err != nil {
		return false, 0, ""
	}
	defer f.Close()
	buf := make([]byte, chunkSize+4096)
	carry := 0
	var fileIndex int64
	read := int64(0)
	for {
		n, rerr := f.Read(buf[carry:])
		if n > 0 {
			window := buf[:carry+n]
			if loc := re.FindIndex(window); loc != nil {
				return true, fileIndex + int64(loc[0]), snippetAt(window, loc[0], loc[1]-loc[0])
			}
			overlap := 4096
			if overlap > len(window) {
				overlap = len(window)
			}
			copy(buf[:overlap], window[len(window)-overlap:])
			fileIndex += int64(len(window) - overlap)
			carry = overlap
			read += int64(n)
			if maxBytes > 0 && read > maxBytes {
				break
			}
		}
		if rerr != nil {
			break
		}
		if n == 0 {
			break
		}
	}
	return false, 0, ""
}
