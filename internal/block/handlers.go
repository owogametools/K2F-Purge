package block

import (
	"context"
	"encoding/json"

	"github.com/owogametools/k2f-purge/internal/elev"
	"github.com/owogametools/k2f-purge/internal/model"
)

func init() {
	_ = elev.Register("hosts.apply", func(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
		var p model.BlockPlan
		if len(payload) > 0 {
			_ = json.Unmarshal(payload, &p)
		}
		if err := applyHosts(p.Domains); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"path": hostsPath()})
	})
	_ = elev.Register("hosts.remove", func(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
		if err := removeHosts(); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"ok": true})
	})
	_ = elev.Register("firewall.apply", func(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
		var p model.BlockPlan
		_ = json.Unmarshal(payload, &p)
		ips, bad := validateIPs(p.IPs)
		if len(ips) == 0 {
			ips = append([]string(nil), defaultIPs...)
		}
		rules, persisted, warns, fails := applyFirewall(ctx, ips, p.Persist)
		return json.Marshal(map[string]any{
			"rules": rules, "persisted": persisted, "warnings": warns, "failures": fails, "bad": bad,
		})
	})
	_ = elev.Register("firewall.remove", func(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
		warns, fails := removeFirewall(ctx)
		return json.Marshal(map[string]any{"warnings": warns, "failures": fails})
	})
	_ = elev.Register("dns.flush", func(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
		if err := flushDNS(ctx); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"ok": true})
	})
	_ = elev.Register("block.apply", func(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
		var p model.BlockPlan
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		st, err := Apply(ctx, p, nil)
		if err != nil {
			return nil, err
		}
		return json.Marshal(st)
	})
	_ = elev.Register("block.remove", func(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
		st, err := Remove(ctx, nil)
		if err != nil {
			return nil, err
		}
		return json.Marshal(st)
	})
}
