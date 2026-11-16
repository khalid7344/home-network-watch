package wireguard

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/khalid7344/home-network-watch/internal/models"
)

func TestParseDumpAll(t *testing.T) {
	fixture, err := os.ReadFile("../../../demo/wg_fixture.txt")
	if err != nil {
		t.Fatalf("failed to read wg fixture: %v", err)
	}

	peers, err := ParseDump(fixture, "wg0")
	if err != nil {
		t.Fatalf("ParseDump failed: %v", err)
	}

	if len(peers) != 4 {
		t.Fatalf("expected 4 peers, got %d", len(peers))
	}

	p1 := peers[0]
	if p1.PublicKey != "xK82m9JqP0bW1cL4rT7yE3nZ8vQ5fD2sA1mN0pB6cV4=" {
		t.Errorf("unexpected peer 1 key: %s", p1.PublicKey)
	}
	if p1.Endpoint != "198.51.100.24:51820" {
		t.Errorf("unexpected endpoint: %s", p1.Endpoint)
	}
	if p1.RxBytes != 145892000 {
		t.Errorf("unexpected rx bytes: %d", p1.RxBytes)
	}
	if p1.TxBytes != 894210000 {
		t.Errorf("unexpected tx bytes: %d", p1.TxBytes)
	}
	if p1.LatestHandshake.Unix() != 1700000000 {
		t.Errorf("unexpected handshake timestamp: %v", p1.LatestHandshake)
	}

	// Peer 4 has 0 handshake
	p4 := peers[3]
	if !p4.LatestHandshake.IsZero() {
		t.Errorf("expected zero handshake for peer 4, got %v", p4.LatestHandshake)
	}
}

func TestParseDumpSingleInterface(t *testing.T) {
	dump := []byte("aA1bB2cC3dD4eE5fF6gG7hH8iI9jJ0kK1lL2mM3nN4o=\tsZ99o0KrQ1cX2dM5sU8zF4oA9wR6gE3tB2nO1qC7dW5=\t51820\toff\n" +
		"xK82m9JqP0bW1cL4rT7yE3nZ8vQ5fD2sA1mN0pB6cV4=\t(none)\t198.51.100.24:51820\t10.10.0.2/32\t1700000000\t1000\t2000\t25\n")

	peers, err := ParseDump(dump, "")
	if err != nil {
		t.Fatalf("ParseDump failed: %v", err)
	}

	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if peers[0].RxBytes != 1000 || peers[0].TxBytes != 2000 {
		t.Errorf("unexpected byte counts: %+v", peers[0])
	}
}

func TestCollectorWithMockRunner(t *testing.T) {
	mockOutput := []byte("wg0\taA1bB2cC3dD4eE5fF6gG7hH8iI9jJ0kK1lL2mM3nN4o=\tsZ99o0KrQ1cX2dM5sU8zF4oA9wR6gE3tB2nO1qC7dW5=\t51820\toff\n" +
		"wg0\txK82m9JqP0bW1cL4rT7yE3nZ8vQ5fD2sA1mN0pB6cV4=\t(none)\t198.51.100.24:51820\t10.10.0.2/32\t1700000000\t500\t600\t25\n")

	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return mockOutput, nil
	}

	col := New("wg0", runner)
	peers, health, err := col.CollectWireGuard(context.Background())
	if err != nil {
		t.Fatalf("CollectWireGuard failed: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if health.Status != models.StatusHealthy {
		t.Errorf("expected OK status, got %s", health.Status)
	}
}

func TestCollectorMissingWG(t *testing.T) {
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("executable file not found in $PATH")
	}

	col := New("wg0", runner)
	_, health, err := col.CollectWireGuard(context.Background())
	if err == nil {
		t.Fatalf("expected error when wg binary is missing, got nil")
	}
	if health.Status != models.StatusError {
		t.Errorf("expected Error status, got %s", health.Status)
	}
}

func TestCollectorSudoFallback(t *testing.T) {
	callCount := 0
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		callCount++
		if name == "wg" {
			return nil, errors.New("permission denied")
		}
		if name == "sudo" {
			return []byte("wg0\taA1=\tsZ99=\t51820\toff\nwg0\txK82=\t(none)\t1.2.3.4:51820\t10.0.0.1/32\t1700000000\t10\t20\toff\n"), nil
		}
		return nil, errors.New("unknown command")
	}

	col := New("wg0", runner)
	peers, health, err := col.CollectWireGuard(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(peers) != 1 {
		t.Errorf("expected 1 peer after sudo fallback, got %d", len(peers))
	}
	if health.Status != models.StatusHealthy {
		t.Errorf("expected OK status, got %s", health.Status)
	}
}
