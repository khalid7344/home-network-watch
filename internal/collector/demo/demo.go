package demo

import (
	"context"
	"sync"
	"time"

	"github.com/khalid7344/home-network-watch/internal/models"
)

// DemoCollector provides deterministic, synthetic DNS and WireGuard metrics.
type DemoCollector struct {
	mu                 sync.Mutex
	tickCount          int64
	simulateSpike      bool
	simulatedNewClient bool
}

// New creates a new DemoCollector with default baseline data.
func New() *DemoCollector {
	return &DemoCollector{}
}

// SetSimulateSpike enables or disables simulation of a DNS spike.
func (d *DemoCollector) SetSimulateSpike(simulate bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.simulateSpike = simulate
}

// SetSimulateNewClient enables or disables simulation of a new client appearing.
func (d *DemoCollector) SetSimulateNewClient(simulate bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.simulatedNewClient = simulate
}

// Name returns the collector name.
func (d *DemoCollector) Name() string {
	return "demo"
}

// CollectDNS produces synthetic DNS telemetry.
func (d *DemoCollector) CollectDNS(ctx context.Context) (models.DNSMetrics, models.CollectorHealth, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tickCount++

	baseQueries := int64(28450) + (d.tickCount * 42)
	baseBlocked := int64(5410) + (d.tickCount * 8)

	if d.simulateSpike {
		baseQueries = int64(95000) + (d.tickCount * 500)
		baseBlocked = int64(24000) + (d.tickCount * 120)
	}

	topDomains := map[string]int{
		"api.github.com":                1420,
		"gateway.icloud.com":            1180,
		"connectivitycheck.gstatic.com": 960,
		"time.cloudflare.com":           740,
		"raw.githubusercontent.com":     510,
		"telemetry.microsoft.com":       480,
		"graph.instagram.com":           390,
		"mqtt.home-assistant.io":        310,
		"pool.ntp.org":                  280,
		"dns.quad9.net":                 210,
	}

	activeClients := map[string]int{
		"192.168.1.10": 11200, // Primary workstation
		"192.168.1.15": 7800,  // Phone
		"192.168.1.20": 4350,  // Laptop
		"192.168.1.50": 3100,  // Home Assistant
		"192.168.1.80": 2000,  // Smart TV
	}

	if d.simulatedNewClient {
		activeClients["192.168.1.240"] = 145 // Unknown device
	}

	metrics := models.DNSMetrics{
		TotalQueries:   baseQueries,
		BlockedQueries: baseBlocked,
		TopDomains:     topDomains,
		ActiveClients:  activeClients,
	}

	health := models.CollectorHealth{
		Name:      "Pi-hole (Demo)",
		Status:    models.StatusHealthy,
		Message:   "Synthetic fixture active",
		LastCheck: time.Now(),
	}

	return metrics, health, nil
}

// CollectWireGuard produces synthetic WireGuard peer metrics.
func (d *DemoCollector) CollectWireGuard(ctx context.Context) ([]models.WGPeerState, models.CollectorHealth, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()

	peers := []models.WGPeerState{
		{
			PublicKey:       "xK82m9JqP0bW1cL4rT7yE3nZ8vQ5fD2sA1mN0pB6cV4=",
			Endpoint:        "198.51.100.24:51820",
			AllowedIPs:      []string{"10.10.0.2/32"},
			LatestHandshake: now.Add(-45 * time.Second),
			RxBytes:         145892000 + (d.tickCount * 10240),
			TxBytes:         894210000 + (d.tickCount * 65536),
		},
		{
			PublicKey:       "yL93n0KrQ1cX2dM5sU8zF4oA9wR6gE3tB2nO1qC7dW5=",
			Endpoint:        "203.0.113.88:51820",
			AllowedIPs:      []string{"10.10.0.3/32"},
			LatestHandshake: now.Add(-3 * time.Minute),
			RxBytes:         42100000 + (d.tickCount * 4096),
			TxBytes:         120500000 + (d.tickCount * 16384),
		},
		{
			PublicKey:       "zM04o1LsR2dY3eN6tV9aG5pB0xS7hF4uC3oP2rD8eX6=",
			Endpoint:        "198.51.100.105:51820",
			AllowedIPs:      []string{"10.10.0.4/32"},
			LatestHandshake: now.Add(-2 * time.Hour), // Older handshake
			RxBytes:         15200000,
			TxBytes:         34100000,
		},
		{
			PublicKey:       "wJ71l8IpO9aV0bK3qS6xD2mY7uP4eC1rZ0lM9oA5bU3=",
			Endpoint:        "(none)",
			AllowedIPs:      []string{"10.10.0.5/32"},
			LatestHandshake: time.Time{}, // Never connected
			RxBytes:         0,
			TxBytes:         0,
		},
	}

	health := models.CollectorHealth{
		Name:      "WireGuard (Demo)",
		Status:    models.StatusHealthy,
		Message:   "Synthetic fixture active (4 peers)",
		LastCheck: now,
	}

	return peers, health, nil
}

// CollectSnapshot returns an aggregated Snapshot from the demo collector.
func (d *DemoCollector) CollectSnapshot(ctx context.Context) (*models.Snapshot, []models.CollectorHealth, error) {
	dns, hDNS, err := d.CollectDNS(ctx)
	if err != nil {
		return nil, nil, err
	}
	wg, hWG, err := d.CollectWireGuard(ctx)
	if err != nil {
		return nil, nil, err
	}

	snap := &models.Snapshot{
		Timestamp:      time.Now(),
		DNSMetrics:     dns,
		WireGuardState: wg,
	}

	return snap, []models.CollectorHealth{hDNS, hWG}, nil
}
