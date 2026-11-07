// Package ruleset compiles domain and IP lists (Clash rule providers,
// sing-box .srs files such as GeoIP/GeoSite) into lookup structures that can
// be swapped atomically when a remote list refreshes.
package ruleset

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync/atomic"

	"go.yaml.in/yaml/v3"
)

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
	re, err := regexp.Compile(value)
	if err != nil {
		return err
	}
	c.regexes = append(c.regexes, re)
	c.Entries++
	return nil
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

// Set is a named list whose content can be replaced while it is in use.
type Set struct {
	Name    string
	content atomic.Pointer[Content]
}

func NewSet(name string) *Set { return &Set{Name: name} }

func (s *Set) Load() *Content            { return s.content.Load() }
func (s *Set) Store(c *Content)          { s.content.Store(c) }
func (s *Set) MatchDomain(h string) bool { return s.content.Load().MatchDomain(h) }
func (s *Set) MatchIP(a netip.Addr) bool { return s.content.Load().MatchIP(a) }
func (s *Set) HasIP() bool               { return s.content.Load().HasIP() }

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
	switch format {
	case FormatSRS:
		return parseSRS(data)
	case FormatYAML, FormatText, "":
	default:
		return nil, fmt.Errorf("unsupported rule-set format %q", format)
	}
	if behavior == "" {
		behavior = BehaviorClassical
	}
	var lines []string
	if format == FormatYAML || (format == "" && bytes.Contains(data, []byte("payload:"))) {
		var doc struct {
			Payload []string `yaml:"payload"`
		}
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, errors.New("rule-set YAML must contain a payload list")
		}
		lines = doc.Payload
	} else {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 64<<10), 1<<20)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}
	c := newContent()
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
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
			return nil, fmt.Errorf("unsupported rule-set behavior %q", behavior)
		}
		if err != nil {
			c.Skipped++
		}
	}
	return c, nil
}

func (c *Content) addClassical(line string) error {
	parts := strings.Split(line, ",")
	if len(parts) < 2 {
		return errors.New("malformed")
	}
	value := strings.TrimSpace(parts[1])
	switch strings.ToUpper(strings.TrimSpace(parts[0])) {
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
