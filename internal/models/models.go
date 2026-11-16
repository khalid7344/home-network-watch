package models

import "time"

// Severity levels for alerts.
const (
	SeverityInfo     = "INFO"
	SeverityWarning  = "WARNING"
	SeverityCritical = "CRITICAL"
)

// Alert types.
const (
	AlertTypeNewClient   = "NEW_CLIENT"
	AlertTypeDNSSpike    = "DNS_SPIKE"
	AlertTypeWGReconnect = "WG_RECONNECT"
)

// Collector status constants.
const (
	StatusHealthy  = "OK"
	StatusDegraded = "Degraded"
	StatusError    = "Error"
	StatusDisabled = "Disabled"
)

// DNSMetrics represents aggregated DNS statistics from Pi-hole or demo collector.
type DNSMetrics struct {
	TotalQueries   int64          `json:"total_queries"`
	BlockedQueries int64          `json:"blocked_queries"`
	TopDomains     map[string]int `json:"top_domains"`
	ActiveClients  map[string]int `json:"active_clients"`
}

// BlockedPercentage calculates the percentage of blocked queries.
func (d DNSMetrics) BlockedPercentage() float64 {
	if d.TotalQueries <= 0 {
		return 0.0
	}
	return (float64(d.BlockedQueries) / float64(d.TotalQueries)) * 100.0
}

// WGPeerState represents the observed state of a WireGuard peer.
type WGPeerState struct {
	PublicKey       string    `json:"public_key"`
	Endpoint        string    `json:"endpoint,omitempty"`
	AllowedIPs      []string  `json:"allowed_ips,omitempty"`
	LatestHandshake time.Time `json:"latest_handshake"` // Zero value if no recent handshake
	RxBytes         int64     `json:"rx_bytes"`
	TxBytes         int64     `json:"tx_bytes"`
}

// TruncatedKey returns the first 8 characters of the public key for display.
func (p WGPeerState) TruncatedKey() string {
	if len(p.PublicKey) <= 8 {
		return p.PublicKey
	}
	return p.PublicKey[:8] + "…"
}

// Snapshot represents a point-in-time collection of network metrics.
type Snapshot struct {
	ID             int64         `json:"id,omitempty"`
	Timestamp      time.Time     `json:"timestamp"`
	DNSMetrics     DNSMetrics    `json:"dns_metrics"`
	WireGuardState []WGPeerState `json:"wireguard_state"`
}

// Alert represents an anomaly detection event.
type Alert struct {
	ID          int64     `json:"id,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	Severity    string    `json:"severity"`
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Resolved    bool      `json:"resolved"`
}

// CollectorHealth reports the operational health of a collector.
type CollectorHealth struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	Message   string    `json:"message,omitempty"`
	LastCheck time.Time `json:"last_check"`
}
