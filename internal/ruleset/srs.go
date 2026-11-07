//go:build !hopway_native

package ruleset

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
)

const maxSRSExpandedSize = 32 << 20

// The sing-box decoder takes compressed input and does not expose its
// decompressor. Bound expansion before handing it any rule records.
func checkSRSExpansion(ctx context.Context, reader io.Reader) error {
	var header [len(srs.MagicBytes) + 1]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err
	}
	if !bytes.Equal(header[:len(srs.MagicBytes)], srs.MagicBytes[:]) {
		return errors.New("invalid sing-box rule-set file")
	}
	// A buffered source avoids one-byte calls into the underlying reader.
	expanded, err := zlib.NewReader(bufio.NewReader(reader))
	if err != nil {
		return err
	}
	defer expanded.Close()
	size, err := io.Copy(io.Discard, io.LimitReader(contextReader{ctx, expanded}, maxSRSExpandedSize+1))
	if err != nil {
		return err
	}
	if size > maxSRSExpandedSize {
		return errors.New("expanded .srs rule set is larger than 32 MB")
	}
	return ctx.Err()
}

// parseSRS reads a sing-box binary rule set (GeoIP, GeoSite and friends).
// Only default rules are used; logical rules and port/process fields are
// counted as skipped.
func parseSRS(ctx context.Context, data []byte) (*Content, error) {
	if err := checkSRSExpansion(ctx, contextReader{ctx, bytes.NewReader(data)}); err != nil {
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
