package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/go-redis/redis"
)

// fakeFFprobe puts an executable "ffprobe" running script first on PATH. The
// rest of PATH stays, so the script can run sleep and other tools.
func fakeFFprobe(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ffprobe"), []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// TestProbeRawCachesOnlyFileFailures: a probe the caller abandoned (cancel or
// deadline) must leave no cached error behind, or every other caller of the
// same file gets "probing failed" for an hour. A failure of the file itself
// is still cached.
func TestProbeRawCachesOnlyFileFailures(t *testing.T) {
	const url = "http://example.invalid/file.mkv"
	key := buildCacheKey(url, "", "")

	t.Run("caller cancelled", func(t *testing.T) {
		pidFile := filepath.Join(t.TempDir(), "pid")
		fakeFFprobe(t, fmt.Sprintf(`echo $$ > '%s'; exec sleep 30`, pidFile))
		cache := memCache{}
		ctx, cancel := context.WithCancel(context.Background())
		go func() { // hang up once ffprobe is running
			for b, _ := os.ReadFile(pidFile); len(b) == 0; b, _ = os.ReadFile(pidFile) {
				time.Sleep(10 * time.Millisecond)
			}
			cancel()
		}()
		_, err := (&server{redis: cache}).probeRaw(ctx, url, "", "")
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("want context.Canceled, got %v", err)
		}
		// With its last caller gone, ffprobe itself is killed.
		pid, err := strconv.Atoi(strings.TrimSpace(readFile(t, pidFile)))
		if err != nil {
			t.Fatal(err)
		}
		waitFor(t, "ffprobe killed", func() bool { return syscall.Kill(pid, 0) == syscall.ESRCH })
		if v, ok := cache[key]; ok {
			t.Fatalf("cancelled probe was cached: %q", v)
		}
	})

	t.Run("caller deadline", func(t *testing.T) {
		fakeFFprobe(t, "exec sleep 30")
		cache := memCache{}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_, err := (&server{redis: cache}).probeRaw(ctx, url, "", "")
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("want context.DeadlineExceeded, got %v", err)
		}
		if v, ok := cache[key]; ok {
			t.Fatalf("timed-out probe was cached: %q", v)
		}
	})

	t.Run("ffprobe rejected the file", func(t *testing.T) {
		fakeFFprobe(t, "exit 1")
		cache := memCache{}
		if _, err := (&server{redis: cache}).probeRaw(context.Background(), url, "", ""); err == nil {
			t.Fatal("want an error")
		}
		if v := cache[key]; v != ErrorText+"probing failed: exit status 1" {
			t.Fatalf("file failure not cached as such: %q", v)
		}
	})
}

// TestProbeRawSharesRunsPerFile: requests for a file that is already being
// probed join that ffprobe run instead of starting another, and a caller that
// hangs up does not take the run away from the callers still waiting.
func TestProbeRawSharesRunsPerFile(t *testing.T) {
	const url = "http://example.invalid/file.mkv"
	key := buildCacheKey(url, "", "")
	dir := t.TempDir()
	runsFile, release := filepath.Join(dir, "runs"), filepath.Join(dir, "release")
	fakeFFprobe(t, fmt.Sprintf(`echo run >> '%s'; while [ ! -e '%s' ]; do sleep 0.05; done; echo '{}'`, runsFile, release))
	runs := func() int { return strings.Count(readFile(t, runsFile), "\n") }
	cache := &lockedCache{m: memCache{}}
	s := &server{redis: cache}

	type result struct {
		out string
		err error
	}
	probe := func(ctx context.Context) chan result {
		c := make(chan result, 1)
		go func() {
			out, err := s.probeRaw(ctx, url, "", "")
			c <- result{out, err}
		}()
		return c
	}

	leaving, leave := context.WithCancel(context.Background())
	defer leave()
	first := probe(leaving)
	waitFor(t, "first run", func() bool { return runs() == 1 })
	second := probe(context.Background())
	waitFor(t, "second request", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return runs() == 2 || s.runs[key] != nil && s.runs[key].waiters == 2
	})

	leave()
	if r := <-first; !errors.Is(r.err, context.Canceled) {
		t.Fatalf("first request: want context.Canceled, got %v", r.err)
	}
	if err := os.WriteFile(release, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if r := <-second; r.err != nil || r.out != "{}\n" {
		t.Fatalf("second request: out=%q err=%v", r.out, r.err)
	}
	if n := runs(); n != 1 {
		t.Fatalf("ffprobe ran %d times for one file, want 1", n)
	}
	if v := cache.Get(key).Val(); v != "{}\n" {
		t.Fatalf("shared run not cached: %q", v)
	}
}

// lockedCache is memCache for requests running concurrently.
type lockedCache struct {
	mu sync.Mutex
	m  memCache
}

func (c *lockedCache) Get(key string) *redis.StringCmd {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m.Get(key)
}

func (c *lockedCache) Set(key string, value interface{}, d time.Duration) *redis.StatusCmd {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m.Set(key, value, d)
}

func readFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}
