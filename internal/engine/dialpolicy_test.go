package engine

import (
	"strings"
	"testing"

	"mac-proxy/internal/backend"
)

// When automatic routing has no healthy candidate the default must block: a
// silent direct connection would leak the traffic the user asked to proxy.
func TestExhaustedCandidatesHonourTheDialPolicy(t *testing.T) {
	for _, test := range []struct {
		setting string
		want    string
	}{
		{"", "REJECT"},
		{"block", "REJECT"},
		{"direct", "DIRECT"},
	} {
		config := Default()
		config.DialPolicy = DialPolicy{OnExhausted: test.setting}
		core, err := New(config, backend.Native{})
		if err != nil {
			t.Fatalf("onExhausted=%q: %v", test.setting, err)
		}
		core.mu.Lock()
		candidates := core.choices("AUTO")
		core.mu.Unlock()
		if len(candidates) != 1 || candidates[0].via != test.want {
			t.Fatalf("onExhausted=%q chose %+v, want %s", test.setting, candidates, test.want)
		}
		core.Close()
	}
}

func TestDialPolicyRejectsUnknownAction(t *testing.T) {
	config := Default()
	config.DialPolicy = DialPolicy{OnExhausted: "leak"}
	_, err := New(config, backend.Native{})
	if err == nil || !strings.Contains(err.Error(), "onExhausted") {
		t.Fatalf("unknown action was accepted: %v", err)
	}
}
