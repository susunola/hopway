// Package process finds which local application opened a connection to
// HopWay's listeners, without a TUN device: the client's socket is looked up
// in the kernel's connection table by its address pair.
package process

import (
	"errors"
	"path/filepath"
	"strings"
)

type Owner struct {
	PID  uint32 `json:"pid,omitempty"`
	Path string `json:"path,omitempty"` // executable
	Name string `json:"name,omitempty"` // executable file name
	App  string `json:"app,omitempty"`  // outermost .app bundle name, if any
	User string `json:"user,omitempty"`
}

// Label is what to show a person: the app bundle name when there is one, so
// "Google Chrome Helper (Renderer)" reads as "Google Chrome".
func (o *Owner) Label() string {
	if o == nil {
		return ""
	}
	if o.App != "" {
		return o.App
	}
	return o.Name
}

var ErrUnsupported = errors.New("process lookup is not supported on this platform")

func newOwner(pid uint32, path, user string) *Owner {
	owner := &Owner{PID: pid, Path: path, User: user}
	if path != "" {
		owner.Name = filepath.Base(path)
		owner.App = BundleName(path)
	}
	return owner
}

// BundleName returns the outermost "X.app" component of path, without ".app".
func BundleName(path string) string {
	for _, part := range strings.Split(path, "/") {
		if len(part) > 4 && strings.HasSuffix(part, ".app") {
			return strings.TrimSuffix(part, ".app")
		}
	}
	return ""
}
