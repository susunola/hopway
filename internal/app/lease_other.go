//go:build !darwin && !linux

package app

import "os"

func acquireLease(string) (*os.File, error) { return nil, nil }
