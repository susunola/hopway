//go:build hopway_native

package ruleset

import (
	"context"
	"errors"
)

func parseSRS(context.Context, []byte) (*Content, error) {
	return nil, errors.New(".srs rule sets need the sing-box build")
}
