//go:build hopway_native

package ruleset

import "errors"

func parseSRS([]byte) (*Content, error) {
	return nil, errors.New(".srs rule sets need the sing-box build")
}
