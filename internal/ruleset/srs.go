//go:build !hopway_native

package ruleset

import (
	"context"
	"fmt"
	"io"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
)

// parseSRS reads a sing-box binary rule set (GeoIP, GeoSite and friends).
// Only default rules are used; logical rules and port/process fields are
// counted as skipped.
func parseSRS(ctx context.Context, reader io.Reader) (*Content, error) {
	compat, err := srs.Read(reader, false) // keep compact matchers
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("invalid .srs rule set: %w", err)
	}
	plain, err := compat.Upgrade()
	if err != nil {
		return nil, err
	}
	c := newContent()
	for _, rule := range plain.Rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if rule.Type != C.RuleTypeDefault && rule.Type != "" {
			c.Skipped++
			continue
		}
		options := rule.DefaultOptions
		if options.Invert || len(options.Port) != 0 || len(options.PortRange) != 0 || len(options.ProcessName) != 0 ||
			len(options.SourceIPCIDR) != 0 || len(options.Network) != 0 {
			c.Skipped++ // conditions HopWay would silently widen; do not guess
			continue
		}
		if options.DomainMatcher != nil {
			c.domainSets = append(c.domainSets, options.DomainMatcher)
			domains, suffixes := options.DomainMatcher.Dump()
			c.Entries += len(domains) + len(suffixes)
		}
		if options.IPSet != nil {
			c.ipSets = append(c.ipSets, options.IPSet)
			c.Entries += len(options.IPSet.Prefixes())
		}
		for _, value := range options.DomainKeyword {
			c.addKeyword(value)
		}
		for _, value := range options.DomainRegex {
			if c.addRegex(value) != nil {
				c.Skipped++
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c, nil
}
