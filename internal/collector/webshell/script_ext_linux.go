//go:build linux

package webshell

// scriptExtensions are the file types that are collected even when their
// modification time is older than the job's "since" value.
var scriptExtensions = map[string]bool{
	".php":   true,
	".phtml": true,
	".phar":  true,
	".cgi":   true,
	".pl":    true,
	".py":    true,
	".sh":    true,
	".jsp":   true,
	".aspx":  true,
}
