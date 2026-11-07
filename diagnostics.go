package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"runtime"
	"runtime/pprof"
	"strconv"
	"time"

	"mac-proxy/internal/app"
)

const maxProfileBytes = 8 << 20

var errProfileSize = errors.New("diagnostic profile exceeds the output limit")

type profileBuffer struct {
	bytes.Buffer
	tooLarge bool
}

func (b *profileBuffer) Write(data []byte) (int, error) {
	if len(data) > maxProfileBytes-b.Len() {
		b.tooLarge = true
		return 0, errProfileSize
	}
	return b.Buffer.Write(data)
}

type diagnosticSample struct {
	payload    profileBuffer
	heap       runtime.MemStats
	goroutines int
	err        error
}

func (sample *diagnosticSample) readStats() {
	runtime.ReadMemStats(&sample.heap)
	sample.goroutines = runtime.NumGoroutine()
}

func collectDiagnostic(ctx context.Context, kind string, seconds int, forceGC bool) *diagnosticSample {
	sample := &diagnosticSample{}
	if err := ctx.Err(); err != nil {
		sample.err = err
		return sample
	}
	if kind == "cpu" {
		if err := pprof.StartCPUProfile(&sample.payload); err != nil {
			sample.err = err
			return sample
		}
		timer := time.NewTimer(time.Duration(seconds) * time.Second)
		select {
		case <-ctx.Done():
		case <-timer.C:
		}
		timer.Stop()
		pprof.StopCPUProfile()
		sample.readStats()
	} else {
		if forceGC {
			runtime.GC()
		}
		sample.readStats()
		sample.err = pprof.Lookup(kind).WriteTo(&sample.payload, 0)
	}
	if sample.payload.tooLarge {
		sample.err = errProfileSize
	} else if err := ctx.Err(); err != nil {
		sample.err = err
	}
	return sample
}

func serveDiagnostic(supervisor *app.Supervisor, slot chan struct{}, writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	kind := query.Get("kind")
	seconds := 0
	var err error
	switch kind {
	case "cpu":
		seconds, err = strconv.Atoi(query.Get("seconds"))
		if err != nil || seconds < 1 || seconds > 5 || query.Has("gc") {
			http.Error(writer, "CPU sampling requires 1 to 5 seconds", http.StatusBadRequest)
			return
		}
	case "heap", "goroutine":
		if query.Has("seconds") || query.Has("gc") && (kind != "heap" || query.Get("gc") != "1") {
			http.Error(writer, "invalid snapshot options", http.StatusBadRequest)
			return
		}
	default:
		http.Error(writer, "expected cpu, heap or goroutine profile", http.StatusBadRequest)
		return
	}
	select {
	case slot <- struct{}{}:
	default:
		http.Error(writer, "another diagnostic sample is running", http.StatusTooManyRequests)
		return
	}
	results := make(chan *diagnosticSample, 1)
	ctx := request.Context()
	if err := supervisor.StartControlWork(ctx, func(ctx context.Context) {
		defer func() { <-slot }()
		results <- collectDiagnostic(ctx, kind, seconds, query.Get("gc") == "1")
	}); err != nil {
		<-slot
		controlWorkError(writer, err)
		return
	}
	select {
	case <-ctx.Done():
	case sample := <-results:
		if ctx.Err() != nil {
			return
		}
		if sample.err != nil {
			http.Error(writer, sample.err.Error(), http.StatusInternalServerError)
			return
		}
		header := writer.Header()
		header.Set("Content-Type", "application/octet-stream")
		header.Set("X-HopWay-Heap-Alloc", strconv.FormatUint(sample.heap.HeapAlloc, 10))
		header.Set("X-HopWay-Heap-Inuse", strconv.FormatUint(sample.heap.HeapInuse, 10))
		header.Set("X-HopWay-GC-Cycles", strconv.FormatUint(uint64(sample.heap.NumGC), 10))
		header.Set("X-HopWay-Goroutines", strconv.Itoa(sample.goroutines))
		_, _ = writer.Write(sample.payload.Bytes())
	}
}
