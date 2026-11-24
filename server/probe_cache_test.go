package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
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
		fakeFFprobe(t, "exec sleep 30")
		cache := memCache{}
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(100*time.Millisecond, cancel)
		_, err := (&server{redis: cache}).probeRaw(ctx, url, "", "")
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("want context.Canceled, got %v", err)
		}
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
