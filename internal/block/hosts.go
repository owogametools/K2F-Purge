package block

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	markerBegin     = "# >>> K2F PURGE BLOCK BEGIN"
	markerBeginFull = "# >>> K2F PURGE BLOCK BEGIN v1 — managed by K2F PURGE, do not edit"
	markerEnd       = "# <<< K2F PURGE BLOCK END"
)

var hostsPathOverride string

func hostsPath() string {
	if hostsPathOverride != "" {
		return hostsPathOverride
	}
	return defaultHostsPath()
}

func defaultHostsPath() string {
	if runtime.GOOS == "windows" {
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = os.Getenv("windir")
		}
		if root == "" {
			root = `C:\Windows`
		}
		return filepath.Join(root, "System32", "drivers", "etc", "hosts")
	}
	return "/etc/hosts"
}

func applyHosts(domains []string) error {
	domains = sanitizeDomains(domains)
	if len(domains) == 0 {
		domains = append([]string(nil), defaultDomains...)
	}
	path := hostsPath()
	if testing.Testing() && path == defaultHostsPath() {
		return fmt.Errorf("refused to touch the real hosts file in tests")
	}
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	nl := detectNewline(existing)
	block := buildBlock(domains, nl)
	next, err := upsertBlock(existing, block, nl)
	if err != nil {
		return err
	}
	if bytes.Equal(existing, next) {
		return nil
	}
	if len(existing) > 0 {
		if err := backupFile(path, existing); err != nil {
			return fmt.Errorf("hosts backup: %w", err)
		}
	}
	mode := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	return atomicWrite(path, next, mode)
}

func removeHosts() error {
	path := hostsPath()
	if testing.Testing() && path == defaultHostsPath() {
		return fmt.Errorf("refused to touch the real hosts file in tests")
	}
	existing, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	next, found, err := stripBlock(existing)
	if err != nil {
		return err
	}
	if !found || bytes.Equal(existing, next) {
		return nil
	}
	if err := backupFile(path, existing); err != nil {
		return fmt.Errorf("hosts backup: %w", err)
	}
	mode := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	return atomicWrite(path, next, mode)
}

func verifyHostsFile(domains []string) (bool, string) {
	path := hostsPath()
	if testing.Testing() && path == defaultHostsPath() {
		return false, "hosts path not overridden in tests"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err.Error()
	}
	start, end, found, err := findBlock(data)
	if err != nil {
		return false, err.Error()
	}
	if !found {
		return false, "K2F PURGE marker block not present"
	}
	body := data[start:end]
	missing := make([]string, 0)
	for _, d := range domains {
		if !bytes.Contains(body, []byte(d)) {
			missing = append(missing, d)
		}
	}
	if len(missing) > 0 {
		return false, "missing domains: " + strings.Join(missing, ", ")
	}
	return true, path
}

func buildBlock(domains []string, nl string) string {
	var b strings.Builder
	b.WriteString(markerBeginFull)
	b.WriteString(nl)
	for _, d := range domains {
		b.WriteString("0.0.0.0 ")
		b.WriteString(d)
		b.WriteString(nl)
	}
	for _, d := range domains {
		b.WriteString("::1     ")
		b.WriteString(d)
		b.WriteString(nl)
	}
	b.WriteString(markerEnd)
	b.WriteString(nl)
	return b.String()
}

func upsertBlock(content []byte, block, nl string) ([]byte, error) {
	start, end, found, err := findBlock(content)
	if err != nil {
		return nil, err
	}
	blockBytes := []byte(block)
	if !found {
		if len(content) == 0 {
			return blockBytes, nil
		}
		out := make([]byte, 0, len(content)+2+len(blockBytes))
		out = append(out, content...)
		if !bytes.HasSuffix(content, []byte(nl)) {
			out = append(out, []byte(nl)...)
		}
		out = append(out, blockBytes...)
		return out, nil
	}
	out := make([]byte, 0, start+(len(content)-end)+len(blockBytes))
	out = append(out, content[:start]...)
	out = append(out, blockBytes...)
	out = append(out, content[end:]...)
	return out, nil
}

func stripBlock(content []byte) ([]byte, bool, error) {
	start, end, found, err := findBlock(content)
	if err != nil {
		return nil, false, err
	}
	if !found {
		return content, false, nil
	}
	out := make([]byte, 0, start+(len(content)-end))
	out = append(out, content[:start]...)
	out = append(out, content[end:]...)
	return out, true, nil
}

func findBlock(content []byte) (start, end int, found bool, err error) {
	si := bytes.Index(content, []byte(markerBegin))
	if si < 0 {
		return 0, 0, false, nil
	}
	lineStart := si
	for lineStart > 0 && content[lineStart-1] != '\n' {
		lineStart--
	}
	ei := bytes.Index(content[si:], []byte(markerEnd))
	if ei < 0 {
		return 0, 0, false, fmt.Errorf("malformed K2F PURGE hosts block: missing end marker")
	}
	ei += si
	lineEnd := ei + len(markerEnd)
	if lineEnd < len(content) && content[lineEnd] == '\r' {
		lineEnd++
	}
	if lineEnd < len(content) && content[lineEnd] == '\n' {
		lineEnd++
	}
	return lineStart, lineEnd, true, nil
}

func detectNewline(b []byte) string {
	if bytes.Contains(b, []byte("\r\n")) {
		return "\r\n"
	}
	if runtime.GOOS == "windows" && len(b) == 0 {
		return "\r\n"
	}
	return "\n"
}

func backupFile(path string, data []byte) error {
	bak := path + ".k2f-backup-" + strconv.FormatInt(time.Now().Unix(), 10)
	return os.WriteFile(bak, data, 0o644)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".k2f-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	_ = os.Chmod(tmpName, mode)

	if err := os.Rename(tmpName, path); err != nil {
		if runtime.GOOS != "windows" {
			return err
		}
		bak := path + ".k2f-rename"
		_ = os.Remove(bak)
		if err2 := os.Rename(path, bak); err2 != nil {
			return err
		}
		if err2 := os.Rename(tmpName, path); err2 != nil {
			_ = os.Rename(bak, path)
			return err2
		}
		_ = os.Remove(bak)
		cleanup = false
		return nil
	}
	cleanup = false
	return nil
}
