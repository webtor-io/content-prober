package main

import (
	"context"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// TestFFprobeRunsUnderMemoryCap: ffprobe runs with the address-space cap, and
// the URL reaches it byte for byte even though it goes through a shell.
func TestFFprobeRunsUnderMemoryCap(t *testing.T) {
	// Shell metacharacters that url.URL.String() leaves as they are. The
	// spaces (kept in the query) split the URL if "$@" loses its quotes.
	const url = "http://example.invalid/a'b;c&d$(id)$HOME*.mkv?x=1  2&y='2'"
	fakeFFprobe(t, `ulimit -v; printf '%s\n' "$@"`)

	out, err := ffprobe(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")

	wantArgs := []string{"-show_format", "-show_streams", "-show_chapters", "-print_format", "json", url}
	if got := lines[1:]; strings.Join(got, "\x00") != strings.Join(wantArgs, "\x00") {
		t.Errorf("ffprobe argv:\n got %q\nwant %q", got, wantArgs)
	}

	// Elsewhere the shell may refuse ulimit -v (macOS does); production is
	// Linux, where it must stick.
	if runtime.GOOS == "linux" {
		if want := strconv.Itoa(ffprobeMemoryLimitKiB); lines[0] != want {
			t.Errorf("ffprobe ulimit -v = %q, want %s", lines[0], want)
		}
	}
}
