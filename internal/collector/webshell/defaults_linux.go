//go:build linux

package webshell

import (
	"example.com/dfir-collector/internal/protocol"
)

func DefaultUploadsDir() string { return "/var/www/html/uploads" }

func DefaultWebConfig() string { return "/etc/apache2/apache2.conf" }

func DefaultWebLogs() string {
	return "/var/log/apache2/access.log,/var/log/apache2/error.log"
}

func logKind() protocol.Kind { return protocol.KindApacheLog }
