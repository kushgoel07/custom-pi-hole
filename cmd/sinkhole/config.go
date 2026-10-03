package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"custom-pi-hole/internal/sinkhole"
)

type config struct {
	listenAddress   string
	upstreamAddress string
	blocklistPath   string
	allowlistPath   string
	clientCIDRs     string
	queryTimeout    time.Duration
	maxInflight     int
}

func parseFlags() config {
	var settings config
	flag.StringVar(&settings.listenAddress, "listen", "127.0.0.1:5353", "UDP and TCP listen address")
	flag.StringVar(&settings.upstreamAddress, "upstream", "1.1.1.1:53", "upstream DNS IP:port")
	flag.StringVar(&settings.blocklistPath, "blocklist", "blocklist.txt", "local domain or hosts-format blocklist")
	flag.StringVar(&settings.allowlistPath, "allowlist", "", "optional local allowlist; overrides blocked parent domains")
	flag.StringVar(&settings.clientCIDRs, "clients", "127.0.0.0/8,::1/128", "comma-separated client CIDRs allowed to query")
	flag.DurationVar(&settings.queryTimeout, "timeout", 3*time.Second, "total upstream query timeout")
	flag.IntVar(&settings.maxInflight, "max-inflight", 64, "maximum simultaneous upstream queries")
	flag.Parse()
	return settings
}

func makeHandler(settings config) (*sinkhole.Handler, error) {
	if settings.queryTimeout <= 0 || settings.maxInflight < 1 {
		return nil, fmt.Errorf("timeout and max-inflight must be positive")
	}
	// Use an IP here so looking up the upstream cannot loop back to this server.
	host, port, err := net.SplitHostPort(settings.upstreamAddress)
	if err != nil || net.ParseIP(host) == nil || port == "" {
		return nil, fmt.Errorf("upstream must be an IP address and port")
	}
	if _, err := net.ResolveUDPAddr("udp", settings.upstreamAddress); err != nil {
		return nil, fmt.Errorf("upstream: %w", err)
	}

	blocked, err := sinkhole.LoadDomains(settings.blocklistPath)
	if err != nil {
		return nil, fmt.Errorf("blocklist: %w", err)
	}
	allowed := make(sinkhole.Domains)
	if settings.allowlistPath != "" {
		allowed, err = sinkhole.LoadDomains(settings.allowlistPath)
		if err != nil {
			return nil, fmt.Errorf("allowlist: %w", err)
		}
	}
	var clientNets []*net.IPNet
	for _, cidr := range strings.Split(settings.clientCIDRs, ",") {
		_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("client network: %w", err)
		}
		clientNets = append(clientNets, network)
	}

	log.Printf("loaded %d blocked and %d allowed domains; upstream %s", len(blocked), len(allowed), settings.upstreamAddress)
	return sinkhole.NewHandler(sinkhole.HandlerConfig{
		Blocked:     blocked,
		Allowed:     allowed,
		Upstream:    settings.upstreamAddress,
		Timeout:     settings.queryTimeout,
		ClientNets:  clientNets,
		MaxInflight: settings.maxInflight,
	}), nil
}
