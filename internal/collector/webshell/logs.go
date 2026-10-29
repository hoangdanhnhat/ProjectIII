package webshell

import (
	"strings"

	"example.com/dfir-collector/internal/collector"
)

// maxLogFiles caps log snapshots per job, alongside maxFiles above.
const maxLogFiles = 4

func (s *scenario) collectLogs(sink collector.Sink) error {
	paths, dropped := collector.ExpandLogPatterns(strings.Split(s.opts.WebLogs, ","), maxLogFiles)
	if dropped > 0 {
		sink.Note("log file limit reached; kept %d newest of %d", maxLogFiles, maxLogFiles+dropped)
	}
	for _, path := range paths {
		if err := sink.File(logKind(), path, "web server log snapshot (live collection)"); err != nil {
			return err
		}
	}
	return nil
}
