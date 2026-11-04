package clean

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/owogametools/k2f-purge/internal/model"
)

var quarantineOverride string

// QuarantineRoot is <UserConfigDir>/K2F PURGE/quarantine.
func QuarantineRoot() (string, error) {
	if quarantineOverride != "" {
		if err := os.MkdirAll(quarantineOverride, 0o700); err != nil {
			return "", err
		}
		return quarantineOverride, nil
	}
	if testing.Testing() {
		return "", fmt.Errorf("quarantine root must be overridden in tests")
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(cfg, "K2F PURGE", "quarantine")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

type manifest struct {
	ID        string         `json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	Items     []manifestItem `json:"items"`
}

type manifestItem struct {
	ID           string    `json:"id"`
	Kind         string    `json:"kind"`
	OriginalPath string    `json:"original_path"`
	StoredName   string    `json:"stored_name"`
	RuleID       string    `json:"rule_id"`
	SHA256       string    `json:"sha256"`
	Size         int64     `json:"size"`
	MTime        time.Time `json:"mtime"`
	RegistryKey  string    `json:"registry_key,omitempty"`
	RegistryFile string    `json:"registry_file,omitempty"`
}

func newSessionDir() (string, *manifest, error) {
	root, err := QuarantineRoot()
	if err != nil {
		return "", nil, err
	}
	id := strconv.FormatInt(time.Now().Unix(), 10)
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(filepath.Join(dir, "files"), 0o700); err != nil {
		return "", nil, err
	}
	man := &manifest{ID: id, CreatedAt: time.Now().UTC()}
	return dir, man, nil
}

func writeManifest(dir string, man *manifest) error {
	data, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0o600)
}

func readManifest(dir string) (*manifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var man manifest
	if err := json.Unmarshal(data, &man); err != nil {
		return nil, err
	}
	return &man, nil
}

func listManifests() ([]string, []*manifest, error) {
	root, err := QuarantineRoot()
	if err != nil {
		return nil, nil, err
	}
	ents, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	var dirs []string
	var mans []*manifest
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		man, err := readManifest(dir)
		if err != nil {
			continue
		}
		dirs = append(dirs, dir)
		mans = append(mans, man)
	}
	return dirs, mans, nil
}

// QuarantineList flattens every session's manifest.
func QuarantineList() ([]model.QuarantineEntry, error) {
	dirs, mans, err := listManifests()
	if err != nil {
		return nil, err
	}
	var out []model.QuarantineEntry
	for i, man := range mans {
		for _, it := range man.Items {
			stored := filepath.Join(dirs[i], "files", it.StoredName)
			if it.RegistryFile != "" {
				stored = filepath.Join(dirs[i], "files", it.RegistryFile)
			}
			out = append(out, model.QuarantineEntry{
				ID:              it.ID,
				OriginalPath:    it.OriginalPath,
				QuarantinedPath: stored,
				RuleID:          it.RuleID,
				SHA256:          it.SHA256,
				Size:            it.Size,
				MTime:           it.MTime,
				CreatedAt:       man.CreatedAt,
			})
		}
	}
	return out, nil
}

func storeFile(session string, src string) (storedName, sum string, size int64, mtime time.Time, err error) {
	st, err := os.Lstat(src)
	if err != nil {
		return "", "", 0, time.Time{}, err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return "", "", 0, time.Time{}, fmt.Errorf("refusing to quarantine symlink %s", src)
	}
	sum, size, err = hashPath(src)
	if err != nil {
		return "", "", 0, time.Time{}, err
	}
	base := filepath.Base(src)
	base = sanitizeBase(base)
	storedName = sum + "__" + base
	dst := filepath.Join(session, "files", storedName)
	if err := relocate(src, dst); err != nil {
		return "", "", 0, time.Time{}, err
	}
	_ = lockdown(dst)
	return storedName, sum, size, st.ModTime(), nil
}

func hashPath(path string) (string, int64, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return "", 0, err
	}
	if st.IsDir() {
		return hashDir(path)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func hashDir(root string) (string, int64, error) {
	h := sha256.New()
	var total int64
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink inside %s: %s", root, p)
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if info.IsDir() {
			fmt.Fprintf(h, "d:%s\n", rel)
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		fh := sha256.New()
		n, err := io.Copy(fh, f)
		f.Close()
		if err != nil {
			return err
		}
		total += n
		fmt.Fprintf(h, "f:%s:%x:%d\n", rel, fh.Sum(nil), n)
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), total, nil
}

func sanitizeBase(name string) string {
	name = filepath.Base(name)
	if name == "." || name == ".." || name == string(os.PathSeparator) {
		return "file"
	}
	name = strings.ReplaceAll(name, string(os.PathSeparator), "_")
	name = strings.ReplaceAll(name, "/", "_")
	return name
}

func relocate(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	if err := copyRecursive(src, dst); err != nil {
		_ = os.RemoveAll(dst)
		return err
	}
	if err := os.RemoveAll(src); err != nil {
		return err
	}
	return nil
}

func copyRecursive(src, dst string) error {
	fi, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to copy symlink %s", src)
	}
	if fi.IsDir() {
		if err := os.MkdirAll(dst, 0o700); err != nil {
			return err
		}
		ents, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, e := range ents {
			if err := copyRecursive(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	return copyFile(src, dst)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

func lockdown(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		_ = os.Chmod(path, 0o700)
		ents, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		for _, e := range ents {
			if err := lockdown(filepath.Join(path, e.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	return os.Chmod(path, 0o600)
}

func restoreItem(session string, it manifestItem) error {
	if it.Kind == model.CleanRegistryCLSID {
		reg := filepath.Join(session, "files", it.RegistryFile)
		return registryImport(reg)
	}
	src := filepath.Join(session, "files", it.StoredName)
	if _, err := os.Lstat(src); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(it.OriginalPath), 0o755); err != nil {
		return err
	}
	return relocate(src, it.OriginalPath)
}

func purgeItem(session string, it manifestItem) error {
	var first error
	if it.StoredName != "" {
		if err := os.RemoveAll(filepath.Join(session, "files", it.StoredName)); err != nil {
			first = err
		}
	}
	if it.RegistryFile != "" {
		if err := os.RemoveAll(filepath.Join(session, "files", it.RegistryFile)); err != nil && first == nil {
			first = err
		}
	}
	return first
}
