package engine

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestAtomicConfigurationWriteAtRenameBoundary(t *testing.T) {
	const initial = `{"mode":"rule","nodes":[]}`
	const updated = `{"mode":"global","nodes":[]}`
	if stage := os.Getenv("HOPWAY_ATOMIC_FIXTURE_STAGE"); stage != "" {
		path := os.Getenv("HOPWAY_ATOMIC_FIXTURE_PATH")
		if stage == "staged" {
			if _, err := stageWrite(path, []byte(updated)); err != nil {
				t.Fatal(err)
			}
		} else if err := WriteAtomic(path, []byte(updated)); err != nil {
			t.Fatal(err)
		}
		// Terminate without running deferred cleanup in the child.
		os.Exit(42)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := WriteAtomic(path, []byte(initial)); err != nil {
		t.Fatal(err)
	}
	for _, boundary := range []struct{ stage, want string }{{"staged", initial}, {"committed", updated}} {
		child := exec.Command(os.Args[0], "-test.run=^TestAtomicConfigurationWriteAtRenameBoundary$")
		child.Env = append(os.Environ(), "HOPWAY_ATOMIC_FIXTURE_STAGE="+boundary.stage, "HOPWAY_ATOMIC_FIXTURE_PATH="+path)
		out, err := child.CombinedOutput()
		if status, ok := err.(*exec.ExitError); !ok || status.ExitCode() != 42 {
			t.Fatalf("fixture did not exit at %s: %v\n%s", boundary.stage, err, out)
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, []byte(boundary.want)) {
			t.Fatalf("%s: incomplete published file: %q, %v", boundary.stage, got, err)
		}
	}
}
