package engine

import (
	"errors"
	"fmt"
	"time"
)

// PerformanceConfig tunes dialing, tunnels and health checks. Zero uses defaults.
type PerformanceConfig struct {
	DialTimeoutMS        int `json:"dialTimeoutMs,omitempty"`
	FailoverTimeoutMS    int `json:"failoverTimeoutMs,omitempty"`
	ProbeTimeoutMS       int `json:"probeTimeoutMs,omitempty"`
	ProbeConcurrency     int `json:"probeConcurrency,omitempty"`
	AutoRouteIntervalSec int `json:"autoRouteIntervalSec,omitempty"`
	TCPIdleTimeoutSec    int `json:"tcpIdleTimeoutSec,omitempty"`
}

type performanceLimits struct {
	dialTimeout       time.Duration
	failoverTimeout   time.Duration
	probeTimeout      time.Duration
	probeConcurrency  int
	autoRouteInterval time.Duration
	tcpIdleTimeout    time.Duration
}

func (config PerformanceConfig) limits() (performanceLimits, error) {
	for _, field := range []struct {
		name             string
		value, low, high int
	}{
		{"dialTimeoutMs", config.DialTimeoutMS, 250, 30000},
		{"failoverTimeoutMs", config.FailoverTimeoutMS, 100, 29999},
		{"probeTimeoutMs", config.ProbeTimeoutMS, 1000, 12000},
		{"probeConcurrency", config.ProbeConcurrency, 1, probeParallel},
		{"autoRouteIntervalSec", config.AutoRouteIntervalSec, 15, 3600},
		{"tcpIdleTimeoutSec", config.TCPIdleTimeoutSec, 15, 86400},
	} {
		if field.value != 0 && (field.value < field.low || field.value > field.high) {
			return performanceLimits{}, fmt.Errorf("performance.%s must be between %d and %d", field.name, field.low, field.high)
		}
	}
	dial := time.Duration(config.DialTimeoutMS) * time.Millisecond
	if dial == 0 {
		dial = 10 * time.Second
	}
	failover := time.Duration(config.FailoverTimeoutMS) * time.Millisecond
	if failover == 0 {
		failover = min(5*time.Second, dial/2)
	} else if failover >= dial {
		return performanceLimits{}, errors.New("performance.failoverTimeoutMs must be shorter than dialTimeoutMs")
	}
	probe := time.Duration(config.ProbeTimeoutMS) * time.Millisecond
	if probe == 0 {
		probe = 6 * time.Second
	}
	parallel := config.ProbeConcurrency
	if parallel == 0 {
		parallel = probeParallel
	}
	interval := time.Duration(config.AutoRouteIntervalSec) * time.Second
	if interval == 0 {
		interval = time.Minute
	}
	return performanceLimits{dial, failover, probe, parallel, interval, time.Duration(config.TCPIdleTimeoutSec) * time.Second}, nil
}
