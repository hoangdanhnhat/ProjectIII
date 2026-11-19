//go:build linux || windows

// Command dfir-agent polls the DFIR server for collection jobs and runs the
// scenario collectors registered below. It never executes server-sent
// commands; it only runs the scenario implementations compiled into it.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"example.com/dfir-collector/internal/agent"
	"example.com/dfir-collector/internal/collector"
	"example.com/dfir-collector/internal/collector/eventlog"
	hostrolecollector "example.com/dfir-collector/internal/collector/hostrole"
	memorycollector "example.com/dfir-collector/internal/collector/memory"
	"example.com/dfir-collector/internal/collector/netstat"
	"example.com/dfir-collector/internal/collector/webshell"
)

func main() {
	base := flag.String("server", "http://127.0.0.1:8080", "server URL (HTTP, or HTTPS with -tls-ca)")
	host := flag.String("host-id", "", "host ID (default: the machine hostname)")
	uploads := flag.String("uploads", webshell.DefaultUploadsDir(), "lab upload directory; never guessed automatically")
	webConfig := flag.String("web-config", webshell.DefaultWebConfig(), "web server configuration file used for role detection")
	webLogs := flag.String("web-logs", webshell.DefaultWebLogs(), "comma-separated web server log paths or glob patterns")
	eventlogChannels := flag.String("eventlog-channels", "System,Application", "comma-separated Windows event log channels")
	apacheConfig := flag.String("apache-config", "", "deprecated alias for -web-config")
	apacheLogs := flag.String("apache-logs", "", "deprecated alias for -web-logs")
	ca := flag.String("tls-ca", "", "optional PEM CA for HTTPS servers")
	interval := flag.Duration("interval", 5*time.Second, "polling interval")
	state := flag.String("state", agent.DefaultStatePath(), "local host-role state file")
	heartbeat := flag.Duration("heartbeat-interval", time.Minute, "inventory heartbeat interval")
	roleInterval := flag.Duration("role-interval", time.Hour, "automatic role detection interval")
	memTool := flag.String("memory-tool", "", "absolute path to an operator-supplied memory acquisition binary (empty disables memory.v1)")
	memSHA := flag.String("memory-tool-sha256", "", "pinned SHA-256 of -memory-tool (required with -memory-tool)")
	memName := flag.String("memory-tool-name", "", "capture tool profile: winpmem or winpmem-mini (default: derived from the executable name)")
	memVersion := flag.String("memory-tool-version", "", "capture tool version recorded in the manifest")
	memOut := flag.String("memory-out", "", "staging directory for memory images (required with -memory-tool)")
	memMax := flag.Int64("memory-max-bytes", memorycollector.DefaultMaxBytes, "maximum memory image size in bytes (must match the server's -max-memory-image)")
	memTimeout := flag.Duration("memory-timeout", memorycollector.DefaultTimeout, "maximum duration of one memory acquisition")
	memKeep := flag.Bool("memory-keep", false, "keep the local memory image after a successful upload")
	flag.Parse()
	// Visit lets "-apache-logs ''" keep its meaning (an explicitly empty list).
	set := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if set["apache-config"] {
		*webConfig = *apacheConfig
	}
	if set["apache-logs"] {
		*webLogs = *apacheLogs
	}
	if *memTool != "" {
		if *memSHA == "" {
			log.Fatal("-memory-tool-sha256 is required with -memory-tool")
		}
		if *memOut == "" {
			log.Fatal("-memory-out is required with -memory-tool")
		}
		if !filepath.IsAbs(*memTool) {
			log.Fatal("-memory-tool must be an absolute path")
		}
		if err := memorycollector.VerifyTool(*memTool, *memSHA); err != nil {
			log.Fatal(err)
		}
	}
	if *memMax < 10<<20 {
		log.Fatal("-memory-max-bytes must be at least 10 MiB")
	}
	token := os.Getenv("DFIR_AGENT_TOKEN")
	if token == "" {
		log.Fatal("DFIR_AGENT_TOKEN is required")
	}
	hostID, err := agent.ResolveHostID(*host)
	if err != nil {
		log.Fatal(err)
	}
	u, err := url.Parse(*base)
	if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") {
		log.Fatal("invalid server URL")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if *ca != "" {
		pem, err := os.ReadFile(*ca)
		if err != nil {
			log.Fatal(err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			log.Fatal("invalid CA certificate")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	if *uploads == "" {
		log.Printf("warning: -uploads is empty; jobs will report needs_configuration")
	}
	// The scenario set of this binary, explicit and greppable. A new scenario
	// is one package plus one line here, plus a server catalog entry.
	registry := collector.NewRegistry(
		webshell.New(webshell.Options{UploadsDir: *uploads, WebConfig: *webConfig, WebLogs: *webLogs}),
		netstat.New(),
		eventlog.New(eventlog.Options{Channels: eventlog.SplitChannels(*eventlogChannels)}),
		hostrolecollector.New(hostrolecollector.Options{}),
		memorycollector.New(memorycollector.Options{
			ToolPath:    *memTool,
			ToolSHA256:  *memSHA,
			ToolName:    *memName,
			ToolVersion: *memVersion,
			OutDir:      *memOut,
			MaxBytes:    *memMax,
			Timeout:     *memTimeout,
			Keep:        *memKeep,
		}),
	)
	log.Printf("agent host ID: %s", hostID)
	a := agent.New(agent.Options{
		ServerURL:         *base,
		HostID:            hostID,
		Token:             token,
		Client:            &http.Client{Timeout: 60 * time.Second, Transport: transport},
		UploadClient:      &http.Client{Transport: transport},
		Registry:          registry,
		Interval:          *interval,
		StatePath:         *state,
		HeartbeatInterval: *heartbeat,
		RoleInterval:      *roleInterval,
		MemoryImageLimit:  *memMax,
		Version:           agent.Version(),
	})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a.Run(ctx)
}
