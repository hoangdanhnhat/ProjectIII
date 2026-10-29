//go:build windows

package webshell

// scriptExtensions includes the IIS/ASP.NET types plus the script types
// that are suspicious on a Windows web root. They are collected even when
// their modification time is older than the job's "since" value.
var scriptExtensions = map[string]bool{
	".php":   true,
	".phtml": true,
	".phar":  true,
	".asp":   true,
	".aspx":  true,
	".ashx":  true,
	".asmx":  true,
	".ascx":  true,
	".asa":   true,
	".cer":   true,
	".cgi":   true,
	".pl":    true,
	".py":    true,
	".sh":    true,
	".jsp":   true,
	".jspx":  true,
	".war":   true,
}
