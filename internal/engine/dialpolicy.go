package engine

import (
	"errors"
	"fmt"
)

// DialPolicy is what automatic routing does when it has no healthy candidate
// left (every node failed, ran out of quota, or the first probe has not
// finished). Blocking is the default: silently sending traffic out directly
// would leak it past the proxy the user asked for.
type DialPolicy struct {
	// OnExhausted is "block" (default) or "direct".
	OnExhausted string `json:"onExhausted,omitempty"`
}

func (policy DialPolicy) validate() error {
	switch policy.OnExhausted {
	case "", "block", "direct":
		return nil
	default:
		return fmt.Errorf("dialPolicy.onExhausted must be block or direct, got %q", policy.OnExhausted)
	}
}

var errNoHealthyCandidate = errors.New("no healthy automatic candidate")

// exhaustedChoice is the single dial candidate used when automatic routing has
// nothing healthy to try.
func (engine *Engine) exhaustedChoice() choice {
	if engine.dialPolicy.OnExhausted == "direct" {
		return choice{via: "DIRECT"}
	}
	return choice{via: "REJECT"}
}
