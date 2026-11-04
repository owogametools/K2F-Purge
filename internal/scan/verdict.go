package scan

import "github.com/owogametools/k2f-purge/internal/model"

// Verdict rolls findings and targets into one of the four documented outcomes.
func Verdict(findings []model.Finding, targets []model.ScanTarget) string {
	hasConfirmed := false
	hasLikely := false
	for _, f := range findings {
		switch f.Confidence {
		case model.ConfidenceConfirmed:
			hasConfirmed = true
		case model.ConfidenceLikely:
			hasLikely = true
		}
	}
	if hasConfirmed {
		return model.VerdictConfirmed
	}
	if hasLikely {
		return model.VerdictLikely
	}
	if !hasLauncher(targets) {
		return model.VerdictInconclusive
	}
	return model.VerdictClear
}
