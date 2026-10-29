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
	"syscall"
	"time"

	"example.com/dfir-collector/internal/agent"
	"example.com/dfir-collector/internal/collector"
	"example.com/dfir-collector/internal/collector/eventlog"
	"example.com/dfir-collector/internal/collector/netstat"
	"example.com/dfir-collector/internal/collector/webshell"
)

func main() {
	base := flag.String("server", "http://127.0.0.1:8080", "server URL (HTTP, or HTTPS with -tls-ca)")
	host := flag.String("host-id", "lab-ubuntu", "host ID registered on server")
	uploads := flag.String("uploads", webshell.DefaultUploadsDir(), "lab upload directory; never guessed automatically")
	webConfig := flag.String("web-config", webshell.DefaultWebConfig(), "web server configuration file used for role detection")
	webLogs := flag.String("web-logs", webshell.DefaultWebLogs(), "comma-separated web server log paths or glob patterns")
	eventlogChannels := flag.String("eventlog-channels", "System,Application", "comma-separated Windows event log channels")
	apacheConfig := flag.String("apache-config", "", "deprecated alias for -web-config")
	apacheLogs := flag.String("apache-logs", "", "deprecated alias for -web-logs")
	ca := flag.String("tls-ca", "", "optional PEM CA for HTTPS servers")
	interval := flag.Duration("interval", 5*time.Second, "polling interval")
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
	token := os.Getenv("DFIR_AGENT_TOKEN")
	if token == "" {
		log.Fatal("DFIR_AGENT_TOKEN is required")
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
	)
	a := agent.New(agent.Options{
		ServerURL: *base,
		HostID:    *host,
		Token:     token,
		Client:    &http.Client{Timeout: 60 * time.Second, Transport: transport},
		Registry:  registry,
		Interval:  *interval,
	})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a.Run(ctx)
}
