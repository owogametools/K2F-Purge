package report

import (
	"strings"
	"testing"
	"time"

	"github.com/owogametools/k2f-purge/internal/model"
)

func TestReportCarriesFullSecret(t *testing.T) {
	value := "sk" + "-" + "proj" + "-" + "Qw3z" + "X8Qw" + "3zX8" + "Qw3z"
	data := model.ReportData{
		Exposure: &model.ExposureResult{
			StartedAt: time.Now(),
			Secrets: &model.SecretResult{
				FilesScanned: 1,
				Findings: []model.SecretFinding{{
					Engine: "rule", Provider: "OpenAI", Kind: "api-key",
					Severity: "critical", Path: "x", Line: 1, Value: value, Masked: "sk-pro…Qw3z",
				}},
			},
		},
	}
	b, err := JSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), value) {
		t.Fatal("json report does not contain the full value")
	}
	md := Markdown(data)
	if !strings.Contains(md, value) {
		t.Fatal("markdown report does not contain the full value")
	}
	if !strings.Contains(md, "警告") {
		t.Fatal("markdown report has no full-secret warning")
	}
}
