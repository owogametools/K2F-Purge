package astrlink

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/owogametools/k2f-purge/internal/model"
)

// The model is pinned by revision and by each file's size and SHA-256.
// Nothing is downloaded: the release ships the files beside the app, and
// a developer may point K2F_ASTRLINK_DIR at a copy.
const (
	rev    = "7216b6a3b897ef903d4b1ba367ae6fb95b0fa5e4"
	revDir = "7216b6a3b897"
)

type fileSpec struct {
	name string
	size int64
	sha  string
}

var modelFiles = []fileSpec{
	{"model_int8.onnx", 330781, "0a070d3113615e33ba3b84d6bd486f663a377c04c4b056e7381732179f51832a"},
	{"model_int8.onnx_data", 37124608, "0ba34216ceead01e0ae2dfd8e46d52b67e7aee80b04f722d9b758613a91c0067"},
	{"tokenizer.json", 1502881, "0cf3b235ef125658015a6c8026a5fe6f28088bf825101a990ec18a10200feef4"},
}

// verified caches the SHA-256 check per directory, keyed by a signature
// of the files' sizes and modification times. A directory whose contents
// changed is verified again.
var (
	verifyMu sync.Mutex
	verified = map[string]string{}
)

// Lookup finds the model and checks it, in order: K2F_ASTRLINK_DIR,
// <exe dir>/astrlink-guard/<rev12>/,
// <cwd>/resources/astrlink-guard/<rev12>/ and
// <UserCacheDir>/k2f-purge/astrlink/<rev12>/. All three files must be
// present with the pinned sizes and SHA-256, checked once per directory.
func Lookup() model.AstrLinkStatus {
	dirs := lookupDirs()
	var last model.AstrLinkStatus
	had := false
	for _, dir := range dirs {
		st, present := checkDir(dir)
		if !present {
			if !had {
				last, had = st, true
			}
			continue
		}
		return st
	}
	if had {
		if last.Note == "" {
			last.Note = "astrlink model files not found"
		}
		return last
	}
	return model.AstrLinkStatus{Note: "astrlink model files not found"}
}

func lookupDirs() []string {
	if dir := os.Getenv("K2F_ASTRLINK_DIR"); dir != "" {
		return []string{dir}
	}
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Join(filepath.Dir(exe), "astrlink-guard", revDir))
	}
	if cwd, err := os.Getwd(); err == nil {
		dirs = append(dirs, filepath.Join(cwd, "resources", "astrlink-guard", revDir))
	}
	if cache, err := os.UserCacheDir(); err == nil {
		dirs = append(dirs, filepath.Join(cache, "k2f-purge", "astrlink", revDir))
	}
	return dirs
}

// checkDir checks one directory. present is false when a file is missing,
// so Lookup may try the next directory. When all files are there, a
// failed size or hash check returns present true: a stale copy is
// reported, not skipped silently.
func checkDir(dir string) (model.AstrLinkStatus, bool) {
	st := model.AstrLinkStatus{Dir: dir}
	infos := make([]os.FileInfo, len(modelFiles))
	var sig string
	for i, f := range modelFiles {
		info, err := os.Stat(filepath.Join(dir, f.name))
		if err != nil {
			st.Note = fmt.Sprintf("astrlink model files not found in %s", dir)
			return st, false
		}
		if !info.Mode().IsRegular() {
			st.Note = fmt.Sprintf("astrlink model file %s is not a regular file", f.name)
			return st, true
		}
		infos[i] = info
		st.Bytes += info.Size()
		sig += fmt.Sprintf("%d:%d|", info.Size(), info.ModTime().UnixNano())
	}
	for i, f := range modelFiles {
		if infos[i].Size() != f.size {
			st.Note = fmt.Sprintf("size mismatch: %s is %d bytes, want %d", f.name, infos[i].Size(), f.size)
			return st, true
		}
	}
	verifyMu.Lock()
	cached, ok := verified[dir]
	verifyMu.Unlock()
	if ok && cached == sig {
		st.Available = true
		st.Note = "astrlink model verified"
		return st, true
	}
	for _, f := range modelFiles {
		sum, err := fileSHA256(filepath.Join(dir, f.name))
		if err != nil {
			st.Note = fmt.Sprintf("read %s: %v", f.name, err)
			return st, true
		}
		if sum != f.sha {
			st.Note = fmt.Sprintf("sha256 mismatch: %s is %s", f.name, sum)
			return st, true
		}
	}
	verifyMu.Lock()
	verified[dir] = sig
	verifyMu.Unlock()
	st.Available = true
	st.Note = "astrlink model verified"
	return st, true
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
