package clean

import (
	"context"
	"encoding/json"

	"github.com/owogametools/k2f-purge/internal/elev"
	"github.com/owogametools/k2f-purge/internal/model"
)

func init() {
	_ = elev.Register("clean.apply", func(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
		var in struct {
			Plan *model.CleanPlan `json:"plan"`
			IDs  []string         `json:"ids"`
			Mode model.CleanMode  `json:"mode"`
		}
		if err := json.Unmarshal(payload, &in); err != nil {
			return nil, err
		}
		res, err := Apply(ctx, in.Plan, in.IDs, in.Mode, nil)
		if err != nil {
			return nil, err
		}
		return json.Marshal(res)
	})
	_ = elev.Register("clean.restore", func(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
		var in struct {
			IDs []string `json:"ids"`
		}
		if err := json.Unmarshal(payload, &in); err != nil {
			return nil, err
		}
		if err := Restore(ctx, in.IDs); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"ok": true})
	})
	_ = elev.Register("clean.purge", func(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
		var in struct {
			IDs []string `json:"ids"`
		}
		if err := json.Unmarshal(payload, &in); err != nil {
			return nil, err
		}
		if err := Purge(ctx, in.IDs); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"ok": true})
	})
	_ = elev.Register("registry.export", func(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
		var in struct {
			Key  string `json:"key"`
			Dest string `json:"dest"`
		}
		if err := json.Unmarshal(payload, &in); err != nil {
			return nil, err
		}
		if err := registryExport(ctx, in.Key, in.Dest); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"ok": true})
	})
	_ = elev.Register("registry.delete", func(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
		var in struct {
			Key string `json:"key"`
		}
		if err := json.Unmarshal(payload, &in); err != nil {
			return nil, err
		}
		if err := registryDelete(ctx, in.Key); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"ok": true})
	})
}
