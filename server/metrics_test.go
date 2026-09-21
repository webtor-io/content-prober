package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/go-redis/redis"
	pkgerrors "github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	pb "github.com/webtor-io/content-prober/content-prober"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestProbeOutcome(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, outcomeOK},
		{"deadline", context.DeadlineExceeded, outcomeTimeout},
		{"deadline wrapped the way probeRaw wraps", errWrap(context.DeadlineExceeded), outcomeTimeout},
		{"caller hung up", context.Canceled, outcomeCanceled},
		{"ffprobe rejected the file", errors.New("exit status 1"), outcomeError},
		{"ffprobe missing", errors.New("exec: \"ffprobe\": executable file not found"), outcomeError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := probeOutcome(c.err); got != c.want {
				t.Fatalf("probeOutcome(%v) = %q, want %q", c.err, got, c.want)
			}
		})
	}
}

func errWrap(err error) error { return pkgerrors.Wrapf(err, "probing failed") }

// memCache stands in for Redis: a map plus redis.Nil for a miss.
type memCache map[string]string

func (m memCache) Get(key string) *redis.StringCmd {
	if v, ok := m[key]; ok {
		return redis.NewStringResult(v, nil)
	}
	return redis.NewStringResult("", redis.Nil)
}

func (m memCache) Set(key string, value interface{}, _ time.Duration) *redis.StatusCmd {
	m[key] = value.(string)
	return redis.NewStatusResult("OK", nil)
}

// TestGRPCServerMetrics drives RPCs through the production interceptor chain
// over bufconn: one answered from cache, one replaying a cached failure, one
// cache miss. The miss must run ffprobe; an empty PATH makes that fail the
// same way on every host, so the test needs no ffprobe and no network.
func TestGRPCServerMetrics(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	const okURL = "http://example.invalid/ok.mkv"
	const badURL = "http://example.invalid/bad.mkv"
	const missURL = "http://example.invalid/miss.mkv"
	cache := memCache{
		buildCacheKey(okURL, "", ""):  `{"format":{"duration":"1.5"}}`,
		buildCacheKey(badURL, "", ""): ErrorText + "probing failed: exit status 1",
	}

	lis := bufconn.Listen(1 << 20)
	s := newGRPCServer(&server{redis: cache})
	go func() { _ = s.Serve(lis) }()
	defer s.Stop()

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := pb.NewContentProberClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	handledOK := map[string]string{"grpc_service": "ContentProber", "grpc_method": "Probe", "grpc_code": "OK"}
	handledErr := map[string]string{"grpc_service": "ContentProber", "grpc_method": "Probe", "grpc_code": "Internal"}
	probedOK := map[string]string{"outcome": outcomeOK, "cache": cacheHit}
	probedErr := map[string]string{"outcome": outcomeError, "cache": cacheHit}
	probedMiss := map[string]string{"outcome": outcomeError, "cache": cacheMiss}
	before := map[*map[string]string]float64{}
	for _, l := range []*map[string]string{&handledOK, &handledErr} {
		before[l] = counterValue(t, "grpc_server_handled_total", *l)
	}
	for _, l := range []*map[string]string{&probedOK, &probedErr, &probedMiss} {
		before[l] = counterValue(t, "prober_probes_total", *l)
	}
	runsBefore := histogramCount(t, "prober_probe_seconds", map[string]string{"outcome": outcomeError})

	rep, err := client.Probe(ctx, &pb.ProbeRequest{Url: okURL})
	if err != nil || rep.GetFormat().GetDuration() != "1.5" {
		t.Fatalf("cached probe: rep=%v err=%v", rep, err)
	}
	if _, err = client.Probe(ctx, &pb.ProbeRequest{Url: badURL}); status.Code(err) != codes.Internal {
		t.Fatalf("cached failure: want codes.Internal, got %v", err)
	}
	if _, err = client.Probe(ctx, &pb.ProbeRequest{Url: missURL}); status.Code(err) != codes.Internal {
		t.Fatalf("cache miss without ffprobe: want codes.Internal, got %v", err)
	}

	for name, l := range map[string]*map[string]string{"handled OK": &handledOK} {
		if got := counterValue(t, "grpc_server_handled_total", *l) - before[l]; got != 1 {
			t.Fatalf("%s %v: got +%v, want +1", name, *l, got)
		}
	}
	if got := counterValue(t, "grpc_server_handled_total", handledErr) - before[&handledErr]; got != 2 {
		t.Fatalf("handled Internal %v: got +%v, want +2", handledErr, got)
	}
	for name, l := range map[string]*map[string]string{"probed ok/hit": &probedOK, "probed error/hit": &probedErr, "probed error/miss": &probedMiss} {
		if got := counterValue(t, "prober_probes_total", *l) - before[l]; got != 1 {
			t.Fatalf("%s %v: got +%v, want +1", name, *l, got)
		}
	}
	// Only the miss ran ffprobe, so only it lands in the histogram.
	if got := histogramCount(t, "prober_probe_seconds", map[string]string{"outcome": outcomeError}) - runsBefore; got != 1 {
		t.Fatalf("prober_probe_seconds{outcome=error} count: got +%v, want +1", got)
	}
	// InitializeMetrics: a code nobody returned exists at 0.
	handledOK["grpc_code"] = "Unavailable"
	if got := counterValue(t, "grpc_server_handled_total", handledOK); got != 0 {
		t.Fatalf("grpc_server_handled_total%v: got %v, want pre-initialised 0", handledOK, got)
	}
}

// counterValue reads one series of a counter vec from the default registry.
// An absent series is fatal rather than 0: telling "present at 0" from
// "absent" is what the InitializeMetrics check needs.
func counterValue(t *testing.T, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			if labelsMatch(m, labels) {
				return m.GetCounter().GetValue()
			}
		}
	}
	t.Fatalf("no series %s%v", name, labels)
	return 0
}

func histogramCount(t *testing.T, name string, labels map[string]string) uint64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			if labelsMatch(m, labels) {
				return m.GetHistogram().GetSampleCount()
			}
		}
	}
	t.Fatalf("no series %s%v", name, labels)
	return 0
}

func labelsMatch(m *dto.Metric, labels map[string]string) bool {
	have := map[string]string{}
	for _, lp := range m.GetLabel() {
		have[lp.GetName()] = lp.GetValue()
	}
	for k, v := range labels {
		if have[k] != v {
			return false
		}
	}
	return true
}
