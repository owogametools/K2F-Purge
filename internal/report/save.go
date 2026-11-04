package report

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/owogametools/k2f-purge/internal/model"
)

// Save writes scan-report-<timestamp>.md and .json into dir (created if needed)
// with mode 0600. It returns the markdown path.
func Save(dir string, r model.ReportData) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("report: empty dir")
	}
	if r.GeneratedAt.IsZero() {
		r.GeneratedAt = time.Now().UTC()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	stamp := r.GeneratedAt.UTC().Format("20060102T150405Z")
	mdPath := filepath.Join(dir, "scan-report-"+stamp+".md")
	jsonPath := filepath.Join(dir, "scan-report-"+stamp+".json")

	md := Markdown(r)
	js, err := JSON(r)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(mdPath, []byte(md), 0o600); err != nil {
		return "", err
	}
	if err := os.WriteFile(jsonPath, js, 0o600); err != nil {
		return "", err
	}
	return mdPath, nil
}
