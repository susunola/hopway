//go:build !hopway_native

package ruleset

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
)

// parseSRS reads a sing-box binary rule set (GeoIP, GeoSite and friends).
// Only default rules are used; logical rules and port/process fields are
// counted as skipped.
func parseSRS(ctx context.Context, data []byte) (*Content, error) {
	sizes, cost, err := scanSRS(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("invalid .srs rule set: %w", err)
	}
	compat, err := srs.Read(contextReader{ctx, bytes.NewReader(data)}, false) // keep compact matchers
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
	if len(plain.Rules) != len(sizes) {
		return nil, errors.New("SRS record count changed during decoding")
	}
	c := newContent()
	c.cost = cost
	for i, rule := range plain.Rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if rule.Type != C.RuleTypeDefault && rule.Type != "" {
			c.Skipped++
			continue
		}
		options := rule.DefaultOptions
		if options.Invert || sizes[i].unsupported {
			c.Skipped++ // conditions HopWay would silently widen; do not guess
			continue
		}
		if options.DomainMatcher != nil {
			c.domainSets = append(c.domainSets, options.DomainMatcher)
			c.Entries += sizes[i].domains
		}
		if options.IPSet != nil {
			c.ipSets = append(c.ipSets, options.IPSet)
			c.Entries += sizes[i].ranges
		}
		for _, value := range options.DomainKeyword {
			c.addKeyword(value)
		}
		for _, value := range options.DomainRegex {
			if err := c.addRegex(value); err != nil {
				if errors.Is(err, errRuleSetBudget) {
					return nil, err
				}
				c.Skipped++
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c, nil
}
