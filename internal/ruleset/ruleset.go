// Package ruleset compiles domain and IP lists (Clash rule providers,
// sing-box .srs files such as GeoIP/GeoSite) into lookup structures that can
// be swapped atomically when a remote list refreshes.
package ruleset

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"regexp/syntax"
	"strings"
)

const (
	maxCompileCost     = 128 << 20
	maxRegexLength     = 2048
	maxRegexComplexity = 8192
)

var errRuleSetBudget = errors.New("rule set exceeds the compilation budget")

// Content is one compiled list. It is immutable once built.
type Content struct {
	exact    map[string]bool
	suffix   map[string]bool // matches the domain itself and its subdomains
	subOnly  map[string]bool // matches subdomains only (".example.com", "*.example.com")
	keywords []string
	regexes  []*regexp.Regexp
	ip       prefixes
	// Compact matchers kept as loaded from .srs files, which hold
	// GeoSite/GeoIP lists far too large to copy into maps.
	domainSets []interface{ Match(string) bool }
	ipSets     []interface{ Contains(netip.Addr) bool }
	Entries    int // usable entries
	Skipped    int // entries of kinds HopWay cannot match (ports, processes, ...)
	cost       uint64
}

// MemoryCost is a conservative accounting weight, not a measurement of the
// Go heap. It covers objects that can grow much faster than the input bytes.
func (c *Content) MemoryCost() uint64 {
	if c == nil {
		return 0
	}
	return c.cost
}

func (c *Content) charge(cost uint64) error {
	if cost > maxCompileCost-c.cost {
		return errRuleSetBudget
	}
	c.cost += cost
	return nil
}

func newContent() *Content {
	return &Content{exact: map[string]bool{}, suffix: map[string]bool{}, subOnly: map[string]bool{}}
}

func (c *Content) addDomain(value string) {
	if value = normalize(value); value != "" {
		c.exact[value] = true
		c.Entries++
	}
}

func (c *Content) addSuffix(value string) {
	value = strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.HasPrefix(value, "+."):
		value = value[2:]
	case strings.HasPrefix(value, "*."), strings.HasPrefix(value, "."):
		if v := normalize(strings.TrimLeft(value, "*.")); v != "" {
			c.subOnly[v] = true
			c.Entries++
		}
		return
	}
	if value = normalize(value); value != "" {
		c.suffix[value] = true
		c.Entries++
	}
}

func (c *Content) addKeyword(value string) {
	if value = strings.ToLower(strings.TrimSpace(value)); value != "" {
		c.keywords = append(c.keywords, value)
		c.Entries++
	}
}

func (c *Content) addRegex(value string) error {
	if len(value) > maxRegexLength {
		return errRuleSetBudget
	}
	expression, err := syntax.Parse(value, syntax.Perl)
	if err != nil {
		return err
	}
	complexity := regexComplexity(expression)
	if complexity > maxRegexComplexity {
		return errRuleSetBudget
	}
	if err := c.charge(uint64(512 + complexity*128)); err != nil {
		return err
	}
	re, err := regexp.Compile(value)
	if err != nil {
		return err
	}
	c.regexes = append(c.regexes, re)
	c.Entries++
	return nil
}

func regexComplexity(expression *syntax.Regexp) int {
	size := 1 + len(expression.Rune)
	for _, sub := range expression.Sub {
		size += regexComplexity(sub)
	}
	if expression.Op == syntax.OpRepeat {
		count := expression.Max
		if count < 0 {
			count = expression.Min + 1
		}
		size *= max(count, 1)
	}
	return min(size, maxRegexComplexity+1)
}

func (c *Content) addCIDR(value string) error {
	value = strings.TrimSpace(value)
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		addr, addrErr := netip.ParseAddr(value)
		if addrErr != nil {
			return fmt.Errorf("invalid IP prefix %q", value)
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	if prefix.Addr().Is4In6() {
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), max(prefix.Bits()-96, 0))
	}
	c.ip.add(prefix)
	c.Entries++
	return nil
}

// MatchDomain reports whether host (lower case, no trailing dot) is listed.
func (c *Content) MatchDomain(host string) bool {
	if c == nil {
		return false
	}
	if c.exact[host] {
		return true
	}
	first := true
	for name := host; ; first = false {
		if c.suffix[name] || (!first && c.subOnly[name]) {
			return true
		}
		dot := strings.IndexByte(name, '.')
		if dot < 0 {
			break
		}
		name = name[dot+1:]
	}
	for _, keyword := range c.keywords {
		if strings.Contains(host, keyword) {
			return true
		}
	}
	for _, re := range c.regexes {
		if re.MatchString(host) {
			return true
		}
	}
	for _, set := range c.domainSets {
		if set.Match(host) {
			return true
		}
	}
	return false
}

func (c *Content) MatchIP(addr netip.Addr) bool {
	if c == nil {
		return false
	}
	if c.ip.contains(addr) {
		return true
	}
	addr = addr.Unmap()
	for _, set := range c.ipSets {
		if set.Contains(addr) {
			return true
		}
	}
	return false
}

func (c *Content) HasIP() bool { return c != nil && (len(c.ip.byPrefix) != 0 || len(c.ipSets) != 0) }

type prefixes struct {
	byPrefix map[netip.Prefix]bool
	lengths4 []int
	lengths6 []int
}

func (p *prefixes) add(prefix netip.Prefix) {
	if p.byPrefix == nil {
		p.byPrefix = map[netip.Prefix]bool{}
	}
	prefix = prefix.Masked()
	if p.byPrefix[prefix] {
		return
	}
	p.byPrefix[prefix] = true
	lengths := &p.lengths6
	if prefix.Addr().Is4() {
		lengths = &p.lengths4
	}
	for _, bits := range *lengths {
		if bits == prefix.Bits() {
			return
		}
	}
	*lengths = append(*lengths, prefix.Bits())
}

func (p *prefixes) contains(addr netip.Addr) bool {
	addr = addr.Unmap()
	lengths := p.lengths6
	if addr.Is4() {
		lengths = p.lengths4
	}
	for _, bits := range lengths {
		if prefix, err := addr.Prefix(bits); err == nil && p.byPrefix[prefix] {
			return true
		}
	}
	return false
}

func normalize(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if strings.ContainsAny(host, "/: *") {
		return ""
	}
	return host
}

// Formats and behaviours, following Clash rule providers.
const (
	FormatSRS  = "srs"
	FormatYAML = "yaml"
	FormatText = "text"

	BehaviorDomain    = "domain"
	BehaviorIPCIDR    = "ipcidr"
	BehaviorClassical = "classical"
)

// DetectFormat guesses the format from a URL or path.
func DetectFormat(location string) string {
	location = strings.ToLower(strings.SplitN(location, "?", 2)[0])
	switch {
	case strings.HasSuffix(location, ".srs"):
		return FormatSRS
	case strings.HasSuffix(location, ".yaml"), strings.HasSuffix(location, ".yml"):
		return FormatYAML
	}
	return FormatText
}

// Parse compiles data in the given format.
func Parse(format, behavior string, data []byte) (*Content, error) {
	return ParseContext(context.Background(), format, behavior, data)
}

type contextReader struct {
	ctx context.Context
	io.Reader
}

func (reader contextReader) Read(data []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.Reader.Read(data)
}

// ParseContext compiles a candidate without publishing it. Cancellation
// aborts reading and discards any partially compiled index.
func ParseContext(ctx context.Context, format, behavior string, data []byte) (*Content, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch format {
	case FormatSRS:
		return parseSRS(ctx, data)
	case FormatYAML, FormatText, "":
	default:
		return nil, fmt.Errorf("unsupported rule-set format %q", format)
	}
	if behavior == "" {
		behavior = BehaviorClassical
	}
	c := newContent()
	reader := contextReader{ctx, bytes.NewReader(data)}
	if format == FormatYAML || (format == "" && bytes.Contains(data, []byte("payload:"))) {
		if err := c.parseYAML(ctx, behavior, data); err != nil {
			return nil, err
		}
	} else {
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 64<<10), 1<<20)
		for scanner.Scan() {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if err := c.addLine(behavior, scanner.Text()); err != nil {
				return nil, err
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Content) addLine(behavior, line string) error {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
		return nil
	}
	if err := c.charge(96 + uint64(len(line))); err != nil {
		return err
	}
	var err error
	switch behavior {
	case BehaviorDomain:
		line = strings.Trim(line, `'"`)
		if strings.HasPrefix(line, "+.") || strings.HasPrefix(line, ".") || strings.HasPrefix(line, "*.") {
			c.addSuffix(line)
		} else {
			c.addDomain(line)
		}
	case BehaviorIPCIDR:
		err = c.addCIDR(strings.Trim(line, `'"`))
	case BehaviorClassical:
		err = c.addClassical(line)
	default:
		return fmt.Errorf("unsupported rule-set behavior %q", behavior)
	}
	if err != nil {
		if errors.Is(err, errRuleSetBudget) {
			return err
		}
		c.Skipped++
	}
	return nil
}

func (c *Content) addClassical(line string) error {
	kind, fields, ok := strings.Cut(line, ",")
	if !ok {
		return errors.New("malformed")
	}
	value, _, _ := strings.Cut(fields, ",")
	value = strings.TrimSpace(value)
	switch strings.ToUpper(strings.TrimSpace(kind)) {
	case "DOMAIN":
		c.addDomain(value)
	case "DOMAIN-SUFFIX":
		c.addSuffix("+." + strings.TrimLeft(value, "+."))
	case "DOMAIN-KEYWORD":
		c.addKeyword(value)
	case "DOMAIN-REGEX":
		return c.addRegex(value)
	case "IP-CIDR", "IP-CIDR6":
		return c.addCIDR(value)
	default:
		c.Skipped++
	}
	return nil
}
