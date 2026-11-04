package clean

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/owogametools/k2f-purge/internal/model"
)

// Apply quarantines or deletes the selected plan items. Paths are
// re-checked against the allowlist; the UI cannot pass an arbitrary
// path. Empty ids means every item in the plan.
func Apply(ctx context.Context, plan *model.CleanPlan, ids []string, mode model.CleanMode, emit func(model.Progress)) (*model.CleanResult, error) {
	if plan == nil {
		return nil, fmt.Errorf("nil plan")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if mode == "" {
		mode = model.CleanQuarantine
	}
	want := map[string]struct{}{}
	for _, id := range ids {
		want[id] = struct{}{}
	}
	var items []model.CleanItem
	for _, it := range plan.Items {
		if len(want) == 0 || containsID(want, it.ID) {
			items = append(items, it)
		}
	}
	res := &model.CleanResult{}
	if len(items) == 0 {
		return res, nil
	}

	roots := collectRoots(nil)

	session, man, err := newSessionDir()
	if err != nil {
		return nil, err
	}
	res.QuarantineDir = session

	for i, it := range items {
		if err := ctx.Err(); err != nil {
			res.Failures = append(res.Failures, err.Error())
			break
		}
		progress(emit, i, len(items), it.Path)
		act, restart, err := applyOne(ctx, session, man, it, roots, mode)
		if act.Kind != "" {
			res.Actions = append(res.Actions, act)
		}
		if err != nil {
			res.Failures = append(res.Failures, fmt.Sprintf("%s: %v", it.Path, err))
			res.Skipped++
			continue
		}
		if restart {
			res.RequiresRestart = true
		}
		switch mode {
		case model.CleanDelete:
			res.Deleted++
		default:
			res.Quarantined++
		}
	}
	if err := writeManifest(session, man); err != nil {
		res.Failures = append(res.Failures, "manifest: "+err.Error())
	}
	if mode == model.CleanDelete {
		if err := purgeSessionFiles(session, man); err != nil {
			res.Failures = append(res.Failures, "purge after delete: "+err.Error())
		}
	}
	progress(emit, len(items), len(items), "done")
	return res, nil
}

func applyOne(ctx context.Context, session string, man *manifest, it model.CleanItem, roots []string, mode model.CleanMode) (model.Action, bool, error) {
	now := time.Now().UTC()
	if err := validateItem(it, roots); err != nil {
		return model.Action{}, false, err
	}
	walkRoots := append(append([]string{}, roots...), it.Path)
	if it.Kind == model.CleanRegistryCLSID || isRegistryPath(it.Path) {
		if err := allowedRegistryKey(it.Path); err != nil {
			return model.Action{}, false, err
		}
		regName := it.ID + ".reg"
		dest := filepath.Join(session, "files", regName)
		if err := registryExport(ctx, it.Path, dest); err != nil {
			return model.Action{}, false, err
		}
		_ = os.Chmod(dest, 0o600)
		if err := registryDelete(ctx, it.Path); err != nil {
			return model.Action{At: now, Kind: "registry_export", Detail: dest}, false, err
		}
		man.Items = append(man.Items, manifestItem{
			ID:           it.ID,
			Kind:         model.CleanRegistryCLSID,
			OriginalPath: it.Path,
			RuleID:       it.RuleID,
			RegistryKey:  it.Path,
			RegistryFile: regName,
		})
		return model.Action{At: now, Kind: "registry_delete", Detail: it.Path}, false, nil
	}

	if isHelperParent(it.Path) {
		return model.Action{}, false, errHelperParent
	}
	resolved, err := resolveNoEscape(it.Path, walkRoots)
	if err != nil {
		return model.Action{}, false, err
	}
	if _, err := os.Lstat(resolved); err != nil {
		return model.Action{}, false, err
	}
	if err := walkNoEscape(resolved, walkRoots); err != nil {
		return model.Action{}, false, err
	}

	stored, sum, size, mtime, err := storeFile(session, resolved)
	restart := false
	if err != nil {
		if isSharingViolation(err) {
			dst := filepath.Join(session, "files", "locked__"+sanitizeBase(filepath.Base(resolved)))
			if err2 := copyRecursive(resolved, dst); err2 != nil {
				if err3 := scheduleDeleteOnReboot(resolved); err3 != nil {
					return model.Action{}, false, fmt.Errorf("locked file: copy %v; delay-delete %v", err2, err3)
				}
				restart = true
				man.Items = append(man.Items, manifestItem{
					ID: it.ID, Kind: it.Kind, OriginalPath: resolved, RuleID: it.RuleID,
				})
				return model.Action{At: now, Kind: "reboot-pending", Detail: resolved}, true, nil
			}
			_ = lockdown(dst)
			if err2 := os.RemoveAll(resolved); err2 != nil {
				if isSharingViolation(err2) {
					_ = scheduleDeleteOnReboot(resolved)
					restart = true
				} else {
					return model.Action{At: now, Kind: "quarantine", Detail: dst}, false, err2
				}
			}
			sum, size, _ = hashPath(dst)
			stored = filepath.Base(dst)
			mtime = time.Now()
		} else {
			return model.Action{}, false, err
		}
	}
	man.Items = append(man.Items, manifestItem{
		ID:           it.ID,
		Kind:         it.Kind,
		OriginalPath: resolved,
		StoredName:   stored,
		RuleID:       it.RuleID,
		SHA256:       sum,
		Size:         size,
		MTime:        mtime,
	})
	kind := "quarantine"
	if mode == model.CleanDelete {
		kind = "delete"
	}
	return model.Action{At: now, Kind: kind, Detail: resolved + " -> " + stored}, restart, nil
}

// Restore moves quarantined items back. Registry items use `reg import`.
func Restore(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return fmt.Errorf("no ids")
	}
	want := map[string]struct{}{}
	for _, id := range ids {
		want[id] = struct{}{}
	}
	dirs, mans, err := listManifests()
	if err != nil {
		return err
	}
	var last error
	found := 0
	for i, man := range mans {
		changed := false
		var keep []manifestItem
		for _, it := range man.Items {
			if _, ok := want[it.ID]; !ok {
				keep = append(keep, it)
				continue
			}
			found++
			if err := restoreItem(dirs[i], it); err != nil {
				last = err
				keep = append(keep, it)
				continue
			}
			changed = true
		}
		if changed {
			man.Items = keep
			if err := writeManifest(dirs[i], man); err != nil {
				last = err
			}
		}
	}
	if found == 0 {
		return fmt.Errorf("no matching quarantine ids")
	}
	return last
}

// Purge permanently deletes quarantined files. The UI must confirm with
// the word PURGE before calling this.
func Purge(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return fmt.Errorf("no ids")
	}
	want := map[string]struct{}{}
	for _, id := range ids {
		want[id] = struct{}{}
	}
	dirs, mans, err := listManifests()
	if err != nil {
		return err
	}
	var last error
	found := 0
	for i, man := range mans {
		changed := false
		var keep []manifestItem
		for _, it := range man.Items {
			if _, ok := want[it.ID]; !ok {
				keep = append(keep, it)
				continue
			}
			found++
			if err := purgeItem(dirs[i], it); err != nil {
				last = err
				keep = append(keep, it)
				continue
			}
			changed = true
		}
		if changed {
			man.Items = keep
			if len(keep) == 0 {
				_ = os.RemoveAll(dirs[i])
			} else if err := writeManifest(dirs[i], man); err != nil {
				last = err
			}
		}
	}
	if found == 0 {
		return fmt.Errorf("no matching quarantine ids")
	}
	return last
}

func purgeSessionFiles(session string, man *manifest) error {
	var last error
	for _, it := range man.Items {
		if err := purgeItem(session, it); err != nil {
			last = err
		}
	}
	return last
}

func containsID(want map[string]struct{}, id string) bool {
	_, ok := want[id]
	return ok
}

func progress(emit func(model.Progress), done, total int, current string) {
	if emit != nil {
		emit(model.Progress{Done: done, Total: total, Current: current})
	}
}
