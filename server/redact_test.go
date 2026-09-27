package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	joonix "github.com/joonix/log"
	log "github.com/sirupsen/logrus"
)

const (
	testAPIKey = "8f2c1d9e-secret-api-key"
	testToken  = "eyJhbGciOiJIUzI1NiJ9.secret-token.sig"
)

var testSourceURL = "http://thp.internal:80/0123456789abcdef0123456789abcdef01234567/Movie%20Name.mkv?api-key=" +
	testAPIKey + "&token=" + testToken

// logLeakPaths logs the source URL the ways server/main.go does.
func logLeakPaths(l *log.Logger) {
	l.WithField("cacheKey", "abc").WithField("sourceURL", testSourceURL).Info("Setting cache")
	l.WithField("cmd", "/usr/bin/ffprobe -show_format -show_streams -print_format json "+testSourceURL).Info("Running ffprobe command")
	l.WithField("output", `{"format":{"filename":"`+testSourceURL+`","format_name":"matroska,webm"}}`).Info("Probing finished")
	l.WithField("stderr", testSourceURL+": Server returned 403 Forbidden").WithError(errors.New("exit status 1")).Error("Unable to probe")
	l.WithField("request", struct{ Url string }{Url: testSourceURL}).Info("Got probe request")
	l.WithField("wrapped", "http://edge/?u="+strings.ReplaceAll(strings.ReplaceAll(testSourceURL, "=", "%3D"), "&", "%26")).Info("Nested URL")
}

func newLogger(f log.Formatter) (*log.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	l := log.New()
	l.SetOutput(&buf)
	l.SetFormatter(f)
	return l, &buf
}

func TestRedactingFormatterMasksCredentials(t *testing.T) {
	l, buf := newLogger(redactingFormatter{&joonix.FluentdFormatter{}})
	logLeakPaths(l)
	out := buf.String()
	for _, secret := range []string{testAPIKey, testToken, "secret-token"} {
		if strings.Contains(out, secret) {
			t.Errorf("log still contains %q:\n%s", secret, out)
		}
	}
	if n := strings.Count(out, "api-key=REDACTED"); n < 5 {
		t.Errorf("api-key=REDACTED appears %d times, want at least 5 (one per URL log path):\n%s", n, out)
	}
	// What is not a credential stays readable.
	for _, keep := range []string{"Movie%20Name.mkv", "matroska", "Server returned 403", "exit status 1", "Setting cache"} {
		if !strings.Contains(out, keep) {
			t.Errorf("log lost %q:\n%s", keep, out)
		}
	}
}

// Negative control: the same lines through the bare formatter leak both
// values, so the test above exercises real leak paths.
func TestBareFormatterLeaks(t *testing.T) {
	l, buf := newLogger(&joonix.FluentdFormatter{})
	logLeakPaths(l)
	out := buf.String()
	if !strings.Contains(out, testAPIKey) || !strings.Contains(out, testToken) {
		t.Fatalf("expected the unredacted formatter to leak the test credentials:\n%s", out)
	}
	if !strings.Contains(out, `\u0026token=`) {
		t.Fatalf("expected encoding/json to escape & as \\u0026 (the redaction relies on it):\n%s", out)
	}
}
