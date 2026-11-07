//go:build !hopway_native

package ruleset

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
)

const maxSRSExpandedSize = 32 << 20

// SRS v1–v5 item tags, following the pinned sing-box decoder.
const (
	srsQueryType byte = iota
	srsNetwork
	srsDomain
	srsKeyword
	srsRegex
	srsSourceIP
	srsIP
	srsSourcePort
	srsSourcePortRange
	srsPort
	srsPortRange
	srsProcessName
	srsProcessPath
	srsPackageName
	srsSSID
	srsBSSID
	srsAdGuard
	srsProcessPathRegex
	srsNetworkType
	srsNetworkExpensive
	srsNetworkConstrained
	srsInterfaceAddress
	srsDefaultInterfaceAddress
	srsPackageNameRegex
	srsEnd byte = 0xff
)

type srsRuleSize struct {
	domains     int
	ranges      int
	unsupported bool
}

type srsScanner struct {
	*bufio.Reader
	ctx  context.Context
	used uint64
}

func (s *srsScanner) charge(count, unit uint64) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if count > (maxCompileCost-s.used)/unit {
		return errRuleSetBudget
	}
	s.used += count * unit
	return nil
}

func scanSRS(ctx context.Context, data []byte) ([]srsRuleSize, uint64, error) {
	var header [len(srs.MagicBytes) + 1]byte
	source := bytes.NewReader(data)
	if _, err := io.ReadFull(source, header[:]); err != nil {
		return nil, 0, err
	}
	if !bytes.Equal(header[:len(srs.MagicBytes)], srs.MagicBytes[:]) || header[len(srs.MagicBytes)] > C.RuleSetVersionCurrent {
		return nil, 0, errors.New("invalid sing-box rule-set header")
	}
	expanded, err := zlib.NewReader(source)
	if err != nil {
		return nil, 0, err
	}
	defer expanded.Close()
	limit := &io.LimitedReader{R: contextReader{ctx, expanded}, N: maxSRSExpandedSize + 1}
	scan := &srsScanner{Reader: bufio.NewReader(limit), ctx: ctx}
	sizes, scanErr := scan.rules()
	// Read through the checksum and detect oversize even if the decoder
	// stopped after the declared records.
	_, tailErr := io.Copy(io.Discard, scan.Reader)
	if limit.N == 0 {
		return nil, 0, errors.New("expanded .srs rule set is larger than 32 MB")
	}
	if scanErr != nil {
		return nil, 0, scanErr
	}
	if tailErr != nil {
		return nil, 0, tailErr
	}
	return sizes, scan.used, ctx.Err()
}

func (s *srsScanner) rules() ([]srsRuleSize, error) {
	count, err := s.count(2048)
	if err != nil {
		return nil, err
	}
	sizes := make([]srsRuleSize, count)
	for i := range sizes {
		if err := s.rule(0, &sizes[i]); err != nil {
			return nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
	}
	return sizes, nil
}

func (s *srsScanner) word() (uint64, error) {
	data, err := s.Peek(8)
	if err != nil {
		return 0, err
	}
	word := binary.BigEndian.Uint64(data)
	_, err = s.Discard(8)
	return word, err
}

func (s *srsScanner) count(unit uint64) (uint64, error) {
	count, err := binary.ReadUvarint(s)
	if err != nil {
		return 0, err
	}
	return count, s.charge(count, unit)
}

func (s *srsScanner) skip(n uint64) error {
	_, err := s.Discard(int(n)) // all variable lengths are charged before use
	return err
}

func (s *srsScanner) vector(width uint64) error {
	count, err := s.count(width * 4)
	if err != nil {
		return err
	}
	return s.skip(count * width)
}

func (s *srsScanner) strings() error {
	count, err := s.count(64)
	if err != nil {
		return err
	}
	for range count {
		if err := s.vector(1); err != nil {
			return err
		}
	}
	return nil
}

func (s *srsScanner) address(prefix bool) error {
	size, err := binary.ReadUvarint(s)
	if err != nil {
		return err
	}
	if size != 4 && size != 16 {
		return errors.New("invalid IP address length")
	}
	if prefix {
		size++
	}
	return s.skip(size)
}

func (s *srsScanner) prefixes() error {
	count, err := s.count(128)
	if err != nil {
		return err
	}
	for range count {
		if err := s.address(true); err != nil {
			return err
		}
	}
	return nil
}

func (s *srsScanner) ranges() (int, error) {
	version, err := s.ReadByte()
	if err != nil {
		return 0, err
	}
	if version != 1 {
		return 0, errors.New("invalid IP set version")
	}
	count, err := s.word()
	if err != nil {
		return 0, err
	}
	if err := s.charge(count, 128); err != nil {
		return 0, err
	}
	for range count {
		for range 2 {
			if err := s.address(false); err != nil {
				return 0, err
			}
		}
	}
	return int(count), nil
}

func (s *srsScanner) tree() (int, error) {
	if err := s.skip(1); err != nil { // format marker used by sing's succinct matcher
		return 0, err
	}
	leafWords, err := s.count(32)
	if err != nil {
		return 0, err
	}
	leaves := 0
	lastLeaf := -1
	for i := range leafWords {
		word, err := s.word()
		if err != nil {
			return 0, err
		}
		leaves += bits.OnesCount64(word)
		if word != 0 {
			lastLeaf = int(i)*64 + 63 - bits.LeadingZeros64(word)
		}
	}
	words, err := s.count(40)
	if err != nil {
		return 0, err
	}
	// A zero adds a child, and a one ends the current node's children.
	// Reject disconnected nodes or out-of-bounds leaves before decoding.
	pending, nodes := 1, 0
	for range words {
		if err := s.ctx.Err(); err != nil {
			return 0, err
		}
		word, err := s.word()
		if err != nil {
			return 0, err
		}
		for range 64 {
			if pending == 0 {
				if word != 0 {
					return 0, errors.New("disconnected succinct tree node")
				}
				break // unused padding
			}
			if word&1 != 0 {
				pending--
				nodes++
			} else {
				pending++
			}
			word >>= 1
		}
	}
	labels, err := s.count(4)
	if err != nil {
		return 0, err
	}
	if pending != 0 || nodes == 0 || int(labels) != nodes-1 || lastLeaf >= nodes {
		return 0, errors.New("invalid succinct tree size")
	}
	return leaves, s.skip(labels)
}

func (s *srsScanner) rule(depth int, size *srsRuleSize) error {
	if depth > 100 {
		return errors.New("logical rule nested too deep")
	}
	kind, err := s.ReadByte()
	if err != nil {
		return err
	}
	switch kind {
	case 0:
		for {
			tag, err := s.ReadByte()
			if err != nil {
				return err
			}
			if tag == srsEnd {
				return s.skip(1) // invert flag
			}
			if size != nil && tag != srsDomain && tag != srsIP && tag != srsKeyword && tag != srsRegex {
				size.unsupported = true
			}
			if err := s.item(tag, size); err != nil {
				return err
			}
		}
	case 1:
		if err := s.skip(1); err != nil { // logical mode
			return err
		}
		count, err := s.count(2048)
		if err != nil {
			return err
		}
		for range count {
			if err := s.rule(depth+1, nil); err != nil {
				return err
			}
		}
		return s.skip(1)
	default:
		return errors.New("unknown SRS rule type")
	}
}

func (s *srsScanner) item(tag byte, size *srsRuleSize) error {
	switch tag {
	case srsQueryType, srsSourcePort, srsPort:
		return s.vector(2)
	case srsNetworkType:
		return s.vector(1)
	case srsNetwork, srsKeyword, srsRegex, srsSourcePortRange, srsPortRange, srsProcessName, srsProcessPath,
		srsPackageName, srsSSID, srsBSSID, srsProcessPathRegex, srsPackageNameRegex:
		return s.strings()
	case srsDomain, srsAdGuard:
		count, err := s.tree()
		if tag == srsDomain && size != nil {
			size.domains = count
		}
		return err
	case srsSourceIP, srsIP:
		count, err := s.ranges()
		if tag == srsIP && size != nil {
			size.ranges = count
		}
		return err
	case srsNetworkExpensive, srsNetworkConstrained:
		return nil
	case srsInterfaceAddress:
		count, err := s.count(256)
		if err != nil {
			return err
		}
		for range count {
			if err := s.skip(1); err != nil {
				return err
			}
			if err := s.prefixes(); err != nil {
				return err
			}
		}
		return nil
	case srsDefaultInterfaceAddress:
		return s.prefixes()
	default:
		return fmt.Errorf("unknown SRS rule item %d", tag)
	}
}
