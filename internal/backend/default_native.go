//go:build hopway_native

package backend

// Default is the backend used by licence-sensitive builds.
func Default() Backend { return Native{} }
