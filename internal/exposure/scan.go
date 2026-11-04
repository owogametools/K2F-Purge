package exposure

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/owogametools/k2f-purge/internal/model"
)

const (
	maxWorkers = 4
	globCap    = 20
)

var categoryOrder = []string{
	"ssh", "gpg", "ai-tools", "cloud", "dev-tools", "shell-history",
	"browsers", "wallets", "projects", "nikke", "system",
}

// Scan walks the live profile with Lstat only.
func Scan(ctx context.Context, opts model.ExposureOptions, emit func(model.Progress)) (*model.ExposureResult, error) {
	home, _ := os.UserHomeDir()
	return scanAll(ctx, liveEnv(home), opts, emit)
}

// ScanWithHome is Scan bound to an injected home directory. Profile variables
// (%APPDATA%, ~, %USERPROFILE%, ...) are derived from home so tests never
// touch the real user profile. Extra environment variables are treated as unset.
func ScanWithHome(ctx context.Context, home string, opts model.ExposureOptions, emit func(model.Progress)) (*model.ExposureResult, error) {
	return scanAll(ctx, fixtureEnv(runtime.GOOS, home), opts, emit)
}

func scanAll(ctx context.Context, env Env, opts model.ExposureOptions, emit func(model.Progress)) (*model.ExposureResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	started := time.Now().UTC()
	result := &model.ExposureResult{StartedAt: started}

	jobs := make([]job, 0, len(catalog)+8)
	for _, row := range catalog {
		if row.Group == groupBrowser {
			continue
		}
		jobs = append(jobs, job{row: row, env: env})
	}

	var prefixes []string
	if opts.IncludeWine || len(opts.ExtraPrefixes) > 0 {
		prefixes = findWinePrefixes(env.Home, env.GOOS, opts)
		for _, pfx := range prefixes {
			for _, user := range wineUsers(pfx) {
				wenv := env
				wenv.HostOS = env.GOOS
				wenv.GOOS = "windows"
				wenv.WinePrefix = pfx
				wenv.WineUser = user
				wenv.AbsRoot = ""
				prefixTag := "wine-" + sanitizeID(filepath.Base(pfx)+"-"+user)
				for _, row := range catalog {
					if row.Group == groupBrowser || row.Group == groupRegistry {
						continue
					}
					jobs = append(jobs, job{row: row, env: wenv, idPrefix: prefixTag, note: "wine prefix " + pfx})
				}
			}
		}
	}

	items, cancelled, err := runJobs(ctx, jobs, emit)
	if err != nil && !cancelled {
		return nil, err
	}

	browserItems := expandBrowsers(ctx, env, items)
	if len(browserItems) > 0 {
		items = append(items, browserItems...)
	} else {
		items = append(items, unexpandedBrowserItems(env)...)
	}

	sort.SliceStable(items, func(i, j int) bool {
		if items[i].ID != items[j].ID {
			return items[i].ID < items[j].ID
		}
		return items[i].Path < items[j].Path
	})

	result.Items = items
	result.Categories = summarize(items)
	result.FinishedAt = time.Now().UTC()
	result.Limitations = limitations(env, prefixes, cancelled)
	if cancelled {
		return result, ctx.Err()
	}
	return result, nil
}

type job struct {
	row      catalogRow
	env      Env
	idPrefix string
	note     string
}

func runJobs(ctx context.Context, jobs []job, emit func(model.Progress)) ([]model.ExposureItem, bool, error) {
	total := len(jobs)
	var done atomic.Int32
	var mu sync.Mutex
	var out []model.ExposureItem
	var firstErr error
	cancelled := false

	sem := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup
	for _, j := range jobs {
		if ctx.Err() != nil {
			cancelled = true
			break
		}
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			items := probeRow(j)
			mu.Lock()
			out = append(out, items...)
			mu.Unlock()
			n := int(done.Add(1))
			if emit != nil {
				cur := j.row.Path
				if len(items) > 0 {
					cur = items[0].Path
				}
				emit(model.Progress{Done: n, Total: total, Current: cur})
			}
		}(j)
	}
	wg.Wait()
	if ctx.Err() != nil {
		cancelled = true
		firstErr = ctx.Err()
	}
	return out, cancelled, firstErr
}

func probeRow(j job) []model.ExposureItem {
	id := j.row.ID
	if j.idPrefix != "" {
		id = j.idPrefix + "-" + j.row.ID
	}
	base := model.ExposureItem{
		ID:       id,
		Category: j.row.Category,
		Label:    j.row.Label,
		Path:     j.row.Path,
		Kind:     j.row.Kind,
		Severity: j.row.Severity,
		Action:   j.row.Action,
		Note:     j.note,
	}

	if j.row.Kind == "registry" || j.row.Group == groupRegistry {
		base.Note = joinNote(base.Note, "registry keys are not opened (Lstat-only scan)")
		return []model.ExposureItem{base}
	}

	res := ResolvePath(j.env, j.row.Path)
	if res.MissingVar != "" {
		base.Note = joinNote(base.Note, "environment variable not set")
		base.Path = j.row.Path
		return []model.ExposureItem{base}
	}
	if res.Skip {
		base.Note = joinNote(base.Note, res.Note)
		return []model.ExposureItem{base}
	}
	base.Path = res.Path

	kind := j.row.Kind
	if kind == "glob" || hasGlob(res.Path) {
		matches, truncated, err := expandGlob(res.Path)
		if err != nil {
			base.Note = joinNote(base.Note, "glob error: "+err.Error())
			return []model.ExposureItem{base}
		}
		if len(matches) == 0 {
			exists, size, mtime := lstat(res.Path)
			base.Exists = exists
			base.Size = size
			base.MTime = mtime
			return []model.ExposureItem{base}
		}
		out := make([]model.ExposureItem, 0, len(matches))
		for i, m := range matches {
			it := base
			if len(matches) > 1 {
				it.ID = base.ID + "#" + itoa(i+1)
			}
			it.Path = m
			exists, size, mtime := lstat(m)
			it.Exists = exists
			it.Size = size
			it.MTime = mtime
			if truncated && i == 0 {
				it.Note = joinNote(it.Note, "truncated to 20 matches")
			}
			out = append(out, it)
		}
		return out
	}

	exists, size, mtime := lstat(res.Path)
	base.Exists = exists
	base.Size = size
	base.MTime = mtime
	return []model.ExposureItem{base}
}

func lstat(path string) (bool, int64, time.Time) {
	if path == "" {
		return false, 0, time.Time{}
	}
	st, err := os.Lstat(path)
	if err != nil {
		return false, 0, time.Time{}
	}
	return true, st.Size(), st.ModTime().UTC()
}

func hasGlob(path string) bool {
	return strings.ContainsAny(path, `*?`) || strings.Contains(path, "**")
}

func expandGlob(pattern string) ([]string, bool, error) {
	if strings.Contains(pattern, "**") {
		return globStarStar(pattern, globCap)
	}
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, false, err
	}
	sort.Strings(matches)
	if len(matches) > globCap {
		return matches[:globCap], true, nil
	}
	return matches, false, nil
}

func globStarStar(pattern string, limit int) ([]string, bool, error) {
	idx := strings.Index(pattern, "**")
	if idx < 0 {
		return nil, false, nil
	}
	prefix := strings.TrimRight(pattern[:idx], `\/`)
	suffix := strings.TrimLeft(pattern[idx+2:], `\/`)
	if suffix == "" {
		suffix = "*"
	}
	st, err := os.Lstat(prefix)
	if err != nil || !st.IsDir() {
		return nil, false, nil
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return nil, false, nil
	}
	var matches []string
	truncated := false
	walkErr := filepath.WalkDir(prefix, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if len(matches) >= limit {
			truncated = true
			return fs.SkipAll
		}
		info, lerr := d.Info()
		if lerr != nil {
			lst, lstatErr := os.Lstat(path)
			if lstatErr != nil {
				return nil
			}
			info = lst
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		ok, _ := filepath.Match(suffix, filepath.Base(path))
		if ok {
			matches = append(matches, path)
		}
		return nil
	})
	sort.Strings(matches)
	if len(matches) > limit {
		matches = matches[:limit]
		truncated = true
	}
	return matches, truncated, walkErr
}

func expandBrowsers(ctx context.Context, env Env, probed []model.ExposureItem) []model.ExposureItem {
	var roots []string
	seen := map[string]struct{}{}
	for _, it := range probed {
		if !it.Exists || !isBrowserRoot(it.Path) {
			continue
		}
		key := strings.ToLower(filepath.ToSlash(it.Path))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		roots = append(roots, it.Path)
	}
	if len(roots) == 0 {
		return nil
	}
	var profiles []string
	for _, root := range roots {
		profiles = append(profiles, browserProfiles(root)...)
	}
	if len(profiles) == 0 {
		return nil
	}
	var jobs []job
	for _, row := range catalogByGroup(groupBrowser) {
		for _, profile := range profiles {
			if ctx.Err() != nil {
				break
			}
			sub := browserSubpath(row.Path)
			joined := env.join(profile, sub)
			jr := row
			jr.Path = joined
			if row.Kind == "glob" || looksLikePrefixGlob(row.Path) {
				jr.Kind = "glob"
				jr.Path = prefixGlob(joined, row.Path)
			}
			jobs = append(jobs, job{
				row:      jr,
				env:      env,
				idPrefix: sanitizeID(filepath.Base(profile)),
				note:     "browser profile " + profile,
			})
		}
	}
	items, _, _ := runJobs(ctx, jobs, nil)
	// Cap 20 results per original browser catalog id.
	count := map[string]int{}
	var out []model.ExposureItem
	for _, it := range items {
		base := it.ID
		if i := strings.Index(it.ID, "-browser-"); i >= 0 {
			base = it.ID[i+1:]
		}
		if hash := strings.Index(base, "#"); hash >= 0 {
			base = base[:hash]
		}
		if count[base] >= globCap {
			continue
		}
		count[base]++
		out = append(out, it)
	}
	return out
}

func unexpandedBrowserItems(env Env) []model.ExposureItem {
	var out []model.ExposureItem
	for _, row := range catalogByGroup(groupBrowser) {
		out = append(out, model.ExposureItem{
			ID:       row.ID,
			Category: row.Category,
			Label:    row.Label,
			Path:     row.Path,
			Kind:     row.Kind,
			Severity: row.Severity,
			Action:   row.Action,
			Note:     "no browser profile root present",
		})
	}
	return out
}

func isBrowserRoot(path string) bool {
	low := strings.ToLower(filepath.ToSlash(path))
	return strings.Contains(low, "user data") ||
		strings.HasSuffix(low, "firefox/profiles") ||
		strings.HasSuffix(low, "opera stable")
}

func browserProfiles(root string) []string {
	low := strings.ToLower(filepath.ToSlash(root))
	if strings.HasSuffix(low, "opera stable") {
		if st, err := os.Lstat(root); err == nil && st.IsDir() {
			return []string{root}
		}
		return nil
	}
	var profiles []string
	if strings.HasSuffix(low, "firefox/profiles") {
		matches, _ := filepath.Glob(filepath.Join(root, "*"))
		for _, m := range matches {
			st, err := os.Lstat(m)
			if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
				continue
			}
			profiles = append(profiles, m)
		}
		return profiles
	}
	def := filepath.Join(root, "Default")
	if st, err := os.Lstat(def); err == nil && st.IsDir() && st.Mode()&os.ModeSymlink == 0 {
		profiles = append(profiles, def)
	}
	matches, _ := filepath.Glob(filepath.Join(root, "Profile *"))
	for _, m := range matches {
		st, err := os.Lstat(m)
		if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			continue
		}
		profiles = append(profiles, m)
	}
	return profiles
}

func browserSubpath(raw string) string {
	s := strings.TrimLeft(raw, `\/`)
	s = strings.TrimRight(s, `\/`)
	switch {
	case strings.HasSuffix(s, "%04x"):
		return strings.TrimSuffix(s, "%04x")
	case strings.HasSuffix(s, "-") || strings.HasSuffix(s, "_"):
		return s
	}
	return s
}

func looksLikePrefixGlob(raw string) bool {
	s := strings.TrimRight(raw, `\/`)
	return strings.HasSuffix(s, "-") || strings.HasSuffix(s, "_") || strings.HasSuffix(s, "%04x")
}

func prefixGlob(joined, raw string) string {
	s := strings.TrimRight(raw, `\/`)
	switch {
	case strings.HasSuffix(s, "%04x"):
		return joined + "*"
	case strings.HasSuffix(s, "-"), strings.HasSuffix(s, "_"):
		return joined + "*"
	}
	if !hasGlob(joined) {
		return joined
	}
	return joined
}

func findWinePrefixes(home, goos string, opts model.ExposureOptions) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(p string) {
		p = filepath.Clean(p)
		if p == "" || p == "." {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		if !isWinePrefix(p) {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, extra := range opts.ExtraPrefixes {
		add(extra)
	}
	if !opts.IncludeWine || home == "" {
		return out
	}
	if goos == "windows" {
		return out
	}
	for _, pattern := range unixPrefixGlobs(home, goos) {
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			add(m)
		}
	}
	add(filepath.Join(home, ".wine"))
	return out
}

func unixPrefixGlobs(home, goos string) []string {
	globs := []string{
		filepath.Join(home, ".steam", "steam", "steamapps", "compatdata", "*", "pfx"),
		filepath.Join(home, ".steam", "root", "steamapps", "compatdata", "*", "pfx"),
		filepath.Join(home, ".local", "share", "Steam", "steamapps", "compatdata", "*", "pfx"),
		filepath.Join(home, ".local", "share", "steam", "steamapps", "compatdata", "*", "pfx"),
		filepath.Join(home, ".var", "app", "com.valvesoftware.Steam", ".local", "share", "Steam", "steamapps", "compatdata", "*", "pfx"),
		filepath.Join(home, ".local", "share", "wineprefixes", "*"),
		filepath.Join(home, ".local", "share", "bottles", "bottles", "*"),
		filepath.Join(home, ".cxoffice", "*"),
		filepath.Join(home, "Games", "Heroic", "Prefixes", "*"),
	}
	if goos == "darwin" {
		globs = append(globs,
			filepath.Join(home, "Library", "Application Support", "Steam", "steamapps", "compatdata", "*", "pfx"),
			filepath.Join(home, "Library", "Application Support", "CrossOver", "Bottles", "*"),
			filepath.Join(home, "Library", "Containers", "com.isaacmarovitz.Whisky", "Bottles", "*"),
		)
	}
	return globs
}

func isWinePrefix(path string) bool {
	if st, err := os.Lstat(filepath.Join(path, "drive_c")); err == nil && st.IsDir() {
		return true
	}
	if _, err := os.Lstat(filepath.Join(path, "system.reg")); err == nil {
		return true
	}
	return false
}

func wineUsers(pfx string) []string {
	dir := filepath.Join(pfx, "drive_c", "users")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	skip := map[string]struct{}{
		"public": {}, "default": {}, "default user": {}, "all users": {},
	}
	var users []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if _, ok := skip[strings.ToLower(name)]; ok {
			continue
		}
		users = append(users, name)
	}
	return users
}

func summarize(items []model.ExposureItem) []model.ExposureCategory {
	type acc struct{ total, present int }
	m := map[string]*acc{}
	var extra []string
	inOrder := map[string]struct{}{}
	for _, n := range categoryOrder {
		inOrder[n] = struct{}{}
	}
	for _, it := range items {
		a := m[it.Category]
		if a == nil {
			a = &acc{}
			m[it.Category] = a
			if _, ok := inOrder[it.Category]; !ok && it.Category != "" {
				extra = append(extra, it.Category)
			}
		}
		a.total++
		if it.Exists {
			a.present++
		}
	}
	var out []model.ExposureCategory
	for _, name := range categoryOrder {
		if a, ok := m[name]; ok {
			out = append(out, model.ExposureCategory{Name: name, Total: a.total, Present: a.present})
		}
	}
	sort.Strings(extra)
	for _, name := range extra {
		a := m[name]
		out = append(out, model.ExposureCategory{Name: name, Total: a.total, Present: a.present})
	}
	return out
}

func limitations(env Env, prefixes []string, cancelled bool) []string {
	var out []string
	out = append(out, "existence only: paths are checked with Lstat; file contents are never opened")
	out = append(out, "registry keys are listed but not opened")
	if env.GOOS != "windows" {
		out = append(out, "Windows-only absolute paths skipped on this OS")
	}
	if len(prefixes) > 0 {
		out = append(out, "wine/proton prefixes scanned: "+strings.Join(prefixes, ", "))
	}
	if cancelled {
		out = append(out, "scan cancelled before completion")
	}
	return out
}

func joinNote(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + "; " + b
}

func sanitizeID(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
