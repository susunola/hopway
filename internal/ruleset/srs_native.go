//go:build hopway_native

package ruleset

import (
	"context"
	"errors"
	"io"
)

func parseSRS(context.Context, io.Reader) (*Content, error) {
	return nil, errors.New(".srs rule sets need the sing-box build")
}
