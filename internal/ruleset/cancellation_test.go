package ruleset

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

type cancelDuringParse struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (ctx *cancelDuringParse) Err() error {
	ctx.checks--
	if ctx.checks == 0 {
		ctx.cancel()
	}
	return ctx.Context.Err()
}

func TestLargeRuleSetParseCancelsWithoutReturningPartialIndex(t *testing.T) {
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &cancelDuringParse{Context: base, cancel: cancel, checks: 1000}
	data := bytes.Repeat([]byte("DOMAIN,example.test\n"), 500000)
	content, err := ParseContext(ctx, FormatText, BehaviorClassical, data)
	if !errors.Is(err, context.Canceled) || content != nil {
		t.Fatalf("canceled parser published a partial index: %v, %v", content, err)
	}
}
