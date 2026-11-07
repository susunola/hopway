package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"mac-proxy/internal/engine"
	"mac-proxy/internal/profile"
)

type desktopPolicy struct {
	engine.Policy
	SelectedID string `json:"selectedId,omitempty"`
}

func desktopPolicyPath(dir string) string {
	return filepath.Join(dir, "outbound-policy.json")
}

func readDesktopPolicy(dir string) (*desktopPolicy, error) {
	if dir == "" {
		return nil, nil
	}
	data, err := os.ReadFile(desktopPolicyPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var saved desktopPolicy
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, err
	}
	switch saved.Mode {
	case "fastest", "global", "rule", "direct":
	case "auto":
		if saved.Auto == nil {
			return nil, errors.New("missing automatic routing settings")
		}
	default:
		return nil, errors.New("unknown saved outbound mode")
	}
	saved.ExpectedProbeKey = ""
	return &saved, nil
}

func readRegionalPolicy(dir string) (*engine.Policy, error) {
	if dir == "" {
		return nil, nil
	}
	data, err := os.ReadFile(filepath.Join(dir, "auto-policy.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var policy engine.Policy
	if err := json.Unmarshal(data, &policy); err != nil || policy.Mode != "auto" || policy.Auto == nil {
		return nil, errors.New("invalid regional routing settings")
	}
	return &policy, nil
}

// DesktopStartupPolicy also powers the stopped app's route summary. Reading
// the policy does not lock or write the profile.
func DesktopStartupPolicy(loaded profile.Loaded, dir string) engine.Policy {
	saved, _ := readDesktopPolicy(dir)
	regional, _ := readRegionalPolicy(dir)
	return chooseDesktopPolicy(loaded, saved, regional)
}

func chooseDesktopPolicy(loaded profile.Loaded, saved *desktopPolicy, regional *engine.Policy) engine.Policy {
	if saved != nil {
		return saved.resolve(loaded.Merged)
	}
	if regional != nil {
		return *regional
	}
	user := loaded.User
	policy := engine.Policy{Mode: loaded.Merged.Mode, Selected: loaded.Merged.Selected}
	// The legacy template (including versions without a MATCH entry) did
	// not express an explicit choice to use the direct catch-all.
	if user.Mode == "rule" && user.Selected == "DIRECT" && len(user.RuleSets) == 0 &&
		(len(user.Rules) == 0 || (len(user.Rules) == 1 && user.Rules[0].Type == engine.RuleMatch && user.Rules[0].Via == "DIRECT")) {
		policy.Mode = "fastest"
	}
	return policy
}

func (saved desktopPolicy) resolve(config engine.Config) engine.Policy {
	policy := saved.Policy
	if policy.Mode == "auto" {
		return policy
	}
	if policy.Mode == "direct" {
		policy.Selected = "DIRECT"
		return policy
	}
	if saved.SelectedID == "" && (policy.Selected == "DIRECT" || policy.Selected == "REJECT") {
		return policy
	}
	policy.Selected = "REJECT"
	matches := 0
	consider := func(name string, group bool) {
		if (saved.SelectedID != "" && saved.SelectedID == config.OutboundID(name, group)) ||
			(saved.SelectedID == "" && saved.Selected == name) {
			policy.Selected = name
			matches++
		}
	}
	for _, node := range config.Nodes {
		consider(node.Name, false)
	}
	for _, group := range config.Groups {
		consider(group.Name, true)
	}
	if matches != 1 {
		policy.Selected = "REJECT"
	}
	return policy
}

// EnableDesktopRouting runs before Start. A node launched from the node list
// must be selected before the listeners are served.
func (s *Supervisor) EnableDesktopRouting(initial *engine.Policy) {
	s.desktopRouting = true
	s.initialPolicy = initial
	saved, err := readDesktopPolicy(s.dataDir)
	if err != nil {
		s.loaded.Warnings = append(s.loaded.Warnings, "无法读取上次的出站选择")
	}
	s.desktopPolicy = saved
}

func (s *Supervisor) saveDesktopPolicy(policy engine.Policy) error {
	saved := &desktopPolicy{Policy: policy}
	saved.ExpectedProbeKey = ""
	if policy.Mode == "global" || policy.Mode == "rule" || policy.Mode == "fastest" {
		switch policy.Selected {
		case "", "DIRECT", "REJECT":
		default:
			group := false
			for _, item := range s.loaded.Merged.Groups {
				if item.Name == policy.Selected {
					group = true
					break
				}
			}
			saved.SelectedID = s.loaded.Merged.OutboundID(policy.Selected, group)
		}
	}
	if s.path != "" && s.dataDir != "" {
		data, err := json.Marshal(saved)
		if err != nil {
			return err
		}
		if err := engine.WriteAtomic(desktopPolicyPath(s.dataDir), data); err != nil {
			return errors.New("无法保存出站选择")
		}
	}
	s.desktopPolicy = saved
	return nil
}
