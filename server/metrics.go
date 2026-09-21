package main

import (
	"context"
	"errors"
	"time"

	grpcprom "github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus"
	"github.com/prometheus/client_golang/prometheus"
)

// grpcMetrics feeds the standard grpc_server_* series (started/handled/msg
// counters and the handling-time histogram). The histogram reaches 120 s
// because a probe of a torrent-backed source waits for the seeder to fetch
// the first pieces; the default buckets stop at 10 s and would put slow
// probes into +Inf.
var grpcMetrics = grpcprom.NewServerMetrics(
	grpcprom.WithServerHandlingTimeHistogram(
		grpcprom.WithHistogramBuckets([]float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120}),
	),
)

// Probe outcomes. The gRPC code is always Internal on failure, so it cannot
// tell a source that never delivered a byte before the deadline (timeout)
// from ffprobe rejecting the file (error). A caller that hung up (canceled)
// is neither and must not inflate the error rate.
const (
	outcomeOK       = "ok"
	outcomeTimeout  = "timeout"
	outcomeCanceled = "canceled"
	outcomeError    = "error"
)

// Cache verdicts. "error" is the cache being unreachable rather than a miss:
// with Redis down every probe runs ffprobe, and that must show as a cache
// outage, not as a sudden 100% miss rate.
const (
	cacheHit   = "hit"
	cacheMiss  = "miss"
	cacheError = "error"
)

var (
	probesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "prober_probes_total",
		Help: "Probes served, by outcome and cache verdict. A cache hit with outcome=error is a cached failure being replayed.",
	}, []string{"outcome", "cache"})

	// Observed only for probes that actually ran ffprobe: a cache hit takes
	// a millisecond and would swamp the buckets that describe ffprobe.
	probeSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "prober_probe_seconds",
		Help:    "Wall time of an ffprobe run (cache misses only), by outcome.",
		Buckets: []float64{0.5, 1, 2, 5, 10, 20, 30, 60},
	}, []string{"outcome"})
)

func init() {
	prometheus.MustRegister(grpcMetrics, probesTotal, probeSeconds)
	// The label sets are closed, so every series can exist from the start:
	// a dashboard then shows 0 rather than "no data", and rate() over a
	// counter that appears mid-window does not miss its first increment.
	for _, o := range []string{outcomeOK, outcomeTimeout, outcomeCanceled, outcomeError} {
		probeSeconds.WithLabelValues(o)
		for _, c := range []string{cacheHit, cacheMiss, cacheError} {
			probesTotal.WithLabelValues(o, c)
		}
	}
}

// observeProbeRun records one ffprobe run that the cache did not spare us.
func observeProbeRun(err error, cache string, d time.Duration) {
	o := probeOutcome(err)
	probesTotal.WithLabelValues(o, cache).Inc()
	probeSeconds.WithLabelValues(o).Observe(d.Seconds())
}

// observeCacheHit records a probe answered from the cache; the cached value
// may be a failure (ErrorText prefix), which counts as outcome=error.
func observeCacheHit(cachedFailure bool) {
	o := outcomeOK
	if cachedFailure {
		o = outcomeError
	}
	probesTotal.WithLabelValues(o, cacheHit).Inc()
}

// probeOutcome maps the error ffprobe finished with onto a bounded label.
func probeOutcome(err error) string {
	switch {
	case err == nil:
		return outcomeOK
	case errors.Is(err, context.DeadlineExceeded):
		return outcomeTimeout
	case errors.Is(err, context.Canceled):
		return outcomeCanceled
	}
	return outcomeError
}
