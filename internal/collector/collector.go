package collector

import (
	"context"

	"github.com/khalid7344/home-network-watch/internal/models"
)

// DNSCollector defines the interface for gathering DNS metrics.
type DNSCollector interface {
	Name() string
	CollectDNS(ctx context.Context) (models.DNSMetrics, models.CollectorHealth, error)
}

// WireGuardCollector defines the interface for gathering WireGuard peer metrics.
type WireGuardCollector interface {
	Name() string
	CollectWireGuard(ctx context.Context) ([]models.WGPeerState, models.CollectorHealth, error)
}

// EngineCollector gathers metrics from both DNS and WireGuard sources.
type EngineCollector interface {
	CollectSnapshot(ctx context.Context) (*models.Snapshot, []models.CollectorHealth, error)
}
