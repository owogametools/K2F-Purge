package exposure

import (
	"strings"
	"testing"

	"github.com/owogametools/k2f-purge/internal/model"
)

func TestExportMarkdownIncludesFullSecret(t *testing.T) {
	value := "sk" + "-" + "proj" + "-" + "Ab3x" + "Y9Ab" + "3xY9" + "Ab3x"
	res := &model.ExposureResult{
		Secrets: &model.SecretResult{
			FilesScanned: 3,
			Findings: []model.SecretFinding{{
				Engine: "rule", Provider: "OpenAI", Kind: "api-key", Severity: "critical",
				Path: `C:\Users\bee\.zshrc`, Line: 12, Value: value, Masked: "sk-pro…Ab3x",
				Action: "Revoke it.", ActionZH: "撤銷它。",
			}},
		},
	}
	md := ExportMarkdown(res)
	if !strings.Contains(md, value) {
		t.Fatal("export does not contain the full value")
	}
	if !strings.Contains(md, "警告") {
		t.Fatal("export has no full-secret warning")
	}
	if !strings.Contains(md, "洩漏的敏感資料（規則）") {
		t.Fatal("export has no secrets section")
	}
}

func TestExportMarkdownWithoutSecretsHasNoWarning(t *testing.T) {
	md := ExportMarkdown(&model.ExposureResult{})
	if strings.Contains(md, "警告") {
		t.Fatal("warning shown without a content scan")
	}
}
