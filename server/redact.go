package main

import (
	"regexp"

	log "github.com/sirupsen/logrus"
)

// secretParam matches the value of an api-key or token query parameter in a
// log line. Source URLs carry both (they come from torrent-http-proxy), and
// they reach the log through several fields: sourceURL, the ffprobe command,
// its stderr, its JSON output (format.filename) and the request/reply
// structs. The line is JSON by the time it is matched, where encoding/json has
// escaped & as &, so a value ends at &, a backslash, a quote or a space.
// %3D covers a URL nested in another URL's query.
var secretParam = regexp.MustCompile(`(?i)((?:api-key|token)(?:=|%3D))[^&\s"'\\]+`)

// redactingFormatter masks credential values in every line the wrapped
// formatter writes, so a new log field carrying a URL cannot leak them.
type redactingFormatter struct {
	log.Formatter
}

func (f redactingFormatter) Format(e *log.Entry) ([]byte, error) {
	b, err := f.Formatter.Format(e)
	if err != nil {
		return b, err
	}
	return secretParam.ReplaceAll(b, []byte("${1}REDACTED")), nil
}
