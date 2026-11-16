package demo

import (
	"context"
	"testing"

	"github.com/khalid7344/home-network-watch/internal/models"
)

func TestDemoCollector(t *testing.T) {
	d := New()
	ctx := context.Background()

	dns, hDNS, err := d.CollectDNS(ctx)
	if err != nil {
		t.Fatalf("CollectDNS failed: %v", err)
	}
	if dns.TotalQueries <= 0 {
		t.Errorf("expected positive TotalQueries, got %d", dns.TotalQueries)
	}
	if dns.BlockedQueries <= 0 {
		t.Errorf("expected positive BlockedQueries, got %d", dns.BlockedQueries)
	}
	if len(dns.TopDomains) == 0 {
		t.Errorf("expected non-empty TopDomains")
	}
	if len(dns.ActiveClients) == 0 {
		t.Errorf("expected non-empty ActiveClients")
	}
	if hDNS.Status != models.StatusHealthy {
		t.Errorf("expected health OK, got %s", hDNS.Status)
	}

	wg, hWG, err := d.CollectWireGuard(ctx)
	if err != nil {
		t.Fatalf("CollectWireGuard failed: %v", err)
	}
	if len(wg) != 4 {
		t.Errorf("expected 4 demo WG peers, got %d", len(wg))
	}
	if hWG.Status != models.StatusHealthy {
		t.Errorf("expected WG health OK, got %s", hWG.Status)
	}

	snap, healths, err := d.CollectSnapshot(ctx)
	if err != nil {
		t.Fatalf("CollectSnapshot failed: %v", err)
	}
	if snap == nil || len(healths) != 2 {
		t.Errorf("unexpected snapshot result")
	}
}

func TestDemoCollectorSpikeAndNewClient(t *testing.T) {
	d := New()
	ctx := context.Background()

	d.SetSimulateSpike(true)
	dnsSpike, _, err := d.CollectDNS(ctx)
	if err != nil {
		t.Fatalf("CollectDNS failed: %v", err)
	}
	if dnsSpike.TotalQueries < 90000 {
		t.Errorf("expected spike queries >= 90000, got %d", dnsSpike.TotalQueries)
	}

	d.SetSimulateNewClient(true)
	dnsClient, _, err := d.CollectDNS(ctx)
	if err != nil {
		t.Fatalf("CollectDNS failed: %v", err)
	}
	if _, found := dnsClient.ActiveClients["192.168.1.240"]; !found {
		t.Errorf("expected new simulated client 192.168.1.240")
	}
}

func TestModelHelpers(t *testing.T) {
	metrics := models.DNSMetrics{
		TotalQueries:   100,
		BlockedQueries: 25,
	}
	if pct := metrics.BlockedPercentage(); pct != 25.0 {
		t.Errorf("expected 25.0%%, got %f", pct)
	}

	peer := models.WGPeerState{
		PublicKey: "abcdefghijklmnopqrstuvwxyz",
	}
	if peer.TruncatedKey() != "abcdefgh…" {
		t.Errorf("expected truncated key 'abcdefgh…', got '%s'", peer.TruncatedKey())
	}

	shortPeer := models.WGPeerState{
		PublicKey: "short",
	}
	if shortPeer.TruncatedKey() != "short" {
		t.Errorf("expected 'short', got '%s'", shortPeer.TruncatedKey())
	}
}
