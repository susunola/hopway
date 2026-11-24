package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// Startup stages can stall independently: a configuration on a slow disk, a
// port held by another process, or an engine that cannot finish building.
// Each stage gets its own budget so a hang reports the stage instead of
// leaving the app waiting on an empty stdout pipe.
const (
	startupConfigTimeout = 30 * time.Second
	startupListenTimeout = 5 * time.Second
	startupEngineTimeout = 30 * time.Second
)

// startupError names the startup stage that failed or stopped making progress.
// The Swift shell shows Error() verbatim, so it must stay actionable.
type startupError struct {
	Stage string
	After time.Duration
	Err   error
}

func (e *startupError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("启动失败（%s）：%v", e.Stage, e.Err)
	}
	return fmt.Sprintf("启动超过 %s 仍卡在「%s」", e.After, e.Stage)
}

func (e *startupError) Unwrap() error { return e.Err }

// asStartupError wraps a stage failure once; an error that already names its
// stage is passed through unchanged.
func asStartupError(stage string, err error) error {
	if err == nil {
		return nil
	}
	var existing *startupError
	if errors.As(err, &existing) {
		return err
	}
	return &startupError{Stage: stage, Err: err}
}

type listenResult struct {
	listener *net.TCPListener
	err      error
}

// listenWithin runs one listener bind under its own deadline. A bind that
// finishes after the deadline is closed instead of leaking.
func listenWithin(stage string, limit time.Duration, bind func() (*net.TCPListener, error)) (*net.TCPListener, error) {
	done := make(chan listenResult, 1)
	go func() {
		listener, err := bind()
		done <- listenResult{listener: listener, err: err}
	}()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case result := <-done:
		return result.listener, asStartupError(stage, result.err)
	case <-timer.C:
		go func() {
			if result := <-done; result.listener != nil {
				result.listener.Close()
			}
		}()
		return nil, &startupError{Stage: stage, After: limit}
	}
}

type loadResult[T any] struct {
	value T
	err   error
}

// loadWithin runs a startup step that owns a resource. If it finishes after
// the deadline the late value is handed to release so the process does not
// keep a half-built supervisor or engine alive.
func loadWithin[T any](stage string, limit time.Duration, load func() (T, error), release func(T)) (T, error) {
	var zero T
	done := make(chan loadResult[T], 1)
	go func() {
		value, err := load()
		done <- loadResult[T]{value: value, err: err}
	}()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case result := <-done:
		return result.value, asStartupError(stage, result.err)
	case <-timer.C:
		go func() {
			result := <-done
			if release != nil {
				release(result.value)
			}
		}()
		return zero, &startupError{Stage: stage, After: limit}
	}
}

// startupContext bounds a stage that accepts a context (the engine build and
// the configuration load both observe it).
func startupContext(parent context.Context, limit time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, limit)
}
