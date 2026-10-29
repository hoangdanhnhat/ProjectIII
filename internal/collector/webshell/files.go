package webshell

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"example.com/dfir-collector/internal/collector"
	"example.com/dfir-collector/internal/protocol"
)

// maxFiles caps upload-directory files per job. The server caps a job at 260
// artifacts: 256 upload files plus the log snapshots below.
const maxFiles = 256

func (s *scenario) collectUploads(job *protocol.Job, sink collector.Sink) error {
	// The upload directory itself is opened without following symlinks, so a
	// directory reachable only through symlinks is a configuration error.
	root, err := collector.SecureOpen(s.opts.UploadsDir)
	if err != nil {
		return fmt.Errorf("%w: upload directory missing, unreadable, or contains symlinks: %v", collector.ErrNeedsConfig, err)
	}
	info, err := root.Stat()
	root.Close()
	if err != nil || !info.IsDir() {
		return fmt.Errorf("%w: upload path is not a directory", collector.ErrNeedsConfig)
	}
	count := 0
	return filepath.WalkDir(s.opts.UploadsDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			sink.Problem("%s: %v", path, walkErr)
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			sink.Problem("%s: %v", path, err)
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		script := scriptExtensions[ext]
		if !script && (job.Since == nil || info.ModTime().Before(*job.Since)) {
			return nil
		}
		if count >= maxFiles {
			sink.Problem("file count limit reached")
			return fs.SkipAll
		}
		reason := "script extension in upload directory"
		if !script {
			reason = "modified since requested time"
		}
		if err := sink.File(protocol.KindUpload, path, reason); err != nil {
			return err // transport error: abort, job stays running for retry
		}
		count++
		return nil
	})
}
