//go:build !hopway_native && (darwin || linux)

package process

import (
	"context"
	"net/netip"
	"sync"

	sbprocess "github.com/sagernet/sing-box/common/process"
	"github.com/sagernet/sing-box/log"
)

var (
	searcherOnce sync.Once
	searcher     sbprocess.Searcher
	searcherErr  error
)

// Lookup finds the process owning the TCP socket client that is connected to
// server. On macOS this reads net.inet.tcp.pcblist_n (cached briefly by
// sing-box) and resolves the executable with proc_pidpath.
func Lookup(client, server netip.AddrPort) (*Owner, error) {
	// A logger is required: the Linux searcher logs through it unconditionally.
	searcherOnce.Do(func() {
		searcher, searcherErr = sbprocess.NewSearcher(sbprocess.Config{Logger: log.NewNOPFactory().Logger()})
	})
	if searcherErr != nil {
		return nil, searcherErr
	}
	info, err := sbprocess.FindProcessInfo(searcher, context.Background(), "tcp", client, server)
	if err != nil {
		return nil, err
	}
	return newOwner(info.ProcessID, info.ProcessPath, info.UserName), nil
}
