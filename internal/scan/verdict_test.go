package scan

import (
	"testing"

	"github.com/owogametools/k2f-purge/internal/model"
)

func TestVerdictTable(t *testing.T) {
	launcher := []model.ScanTarget{{
		Kind: model.TargetLauncherData, Path: "/x", Exists: true,
	}}
	missing := []model.ScanTarget{{
		Kind: model.TargetLauncherData, Path: "/x", Exists: false,
	}}
	wineOnly := []model.ScanTarget{{
		Kind: model.TargetWinePrefix, Path: "/pfx", Exists: true,
	}}
	tests := []struct {
		name     string
		findings []model.Finding
		targets  []model.ScanTarget
		want     string
	}{
		{
			name:     "confirmed beats likely",
			findings: []model.Finding{{Confidence: model.ConfidenceLikely}, {Confidence: model.ConfidenceConfirmed}},
			targets:  launcher,
			want:     model.VerdictConfirmed,
		},
		{
			name:     "likely",
			findings: []model.Finding{{Confidence: model.ConfidenceLikely}},
			targets:  launcher,
			want:     model.VerdictLikely,
		},
		{
			name:     "info only with launcher is clear",
			findings: []model.Finding{{Confidence: model.ConfidenceInfo}},
			targets:  launcher,
			want:     model.VerdictClear,
		},
		{
			name:     "no findings, launcher present",
			findings: nil,
			targets:  launcher,
			want:     model.VerdictClear,
		},
		{
			name:     "no launcher",
			findings: nil,
			targets:  missing,
			want:     model.VerdictInconclusive,
		},
		{
			name:     "wine prefix is not a launcher target",
			findings: nil,
			targets:  wineOnly,
			want:     model.VerdictInconclusive,
		},
		{
			name:     "empty targets",
			findings: nil,
			targets:  nil,
			want:     model.VerdictInconclusive,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Verdict(tt.findings, tt.targets)
			if got != tt.want {
				t.Fatalf("got %s want %s", got, tt.want)
			}
		})
	}
}
