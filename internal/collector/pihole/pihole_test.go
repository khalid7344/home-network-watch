package pihole

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/khalid7344/home-network-watch/internal/models"
)

func TestPiholeCollectorSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("auth")
		if token != "valid-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if r.URL.Path == "/admin/api.php" && r.URL.Query().Has("summaryRaw") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"dns_queries_today": 32000,
				"ads_blocked_today": 6400,
				"ads_percentage_today": 20.0,
				"unique_domains": 1200,
				"status": "enabled"
			}`))
			return
		}

		if r.URL.Path == "/admin/api.php" && r.URL.Query().Has("topItems") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"top_queries": {
					"example.com": 500,
					"github.com": 300
				},
				"top_ads": {
					"adserver.net": 120
				},
				"top_sources": {
					"192.168.1.50": 1000,
					"192.168.1.60|laptop": 800
				}
			}`))
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	client := New(server.URL, "valid-token", 2*time.Second)
	ctx := context.Background()

	metrics, health, err := client.CollectDNS(ctx)
	if err != nil {
		t.Fatalf("CollectDNS failed: %v", err)
	}

	if metrics.TotalQueries != 32000 {
		t.Errorf("expected 32000 queries, got %d", metrics.TotalQueries)
	}
	if metrics.BlockedQueries != 6400 {
		t.Errorf("expected 6400 blocked, got %d", metrics.BlockedQueries)
	}
	if len(metrics.TopDomains) != 3 {
		t.Errorf("expected 3 top domains, got %d", len(metrics.TopDomains))
	}
	if metrics.ActiveClients["192.168.1.60"] != 800 {
		t.Errorf("expected cleaned client IP 192.168.1.60 with 800 queries, got %d", metrics.ActiveClients["192.168.1.60"])
	}
	if health.Status != models.StatusHealthy {
		t.Errorf("expected health OK, got %s", health.Status)
	}
}

func TestPiholeCollectorDegradedOnTopItemsFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("summaryRaw") {
			w.Write([]byte(`{
				"dns_queries_today": 10000,
				"ads_blocked_today": 2000,
				"status": "enabled"
			}`))
			return
		}
		// topItems returns unauthorized empty array []
		w.Write([]byte(`[]`))
	}))
	defer server.Close()

	client := New(server.URL, "", 2*time.Second)
	metrics, health, err := client.CollectDNS(context.Background())
	if err != nil {
		t.Fatalf("unexpected fatal error: %v", err)
	}

	if health.Status != models.StatusDegraded {
		t.Errorf("expected Degraded health status, got %s", health.Status)
	}
	if metrics.TotalQueries != 10000 {
		t.Errorf("expected 10000 total queries, got %d", metrics.TotalQueries)
	}
}

func TestPiholeCollectorHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := New(server.URL, "", 2*time.Second)
	_, health, err := client.CollectDNS(context.Background())
	if err == nil {
		t.Fatalf("expected error on 500 status, got nil")
	}
	if health.Status != models.StatusError {
		t.Errorf("expected Error health status, got %s", health.Status)
	}
}

func TestPiholeCollectorInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`invalid-json-content`))
	}))
	defer server.Close()

	client := New(server.URL, "", 2*time.Second)
	_, health, err := client.CollectDNS(context.Background())
	if err == nil {
		t.Fatalf("expected error on invalid JSON, got nil")
	}
	if health.Status != models.StatusError {
		t.Errorf("expected Error health status, got %s", health.Status)
	}
}

func TestPiholeCollectorTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	// Set tiny timeout
	client := New(server.URL, "", 10*time.Millisecond)
	_, health, err := client.CollectDNS(context.Background())
	if err == nil {
		t.Fatalf("expected timeout error, got nil")
	}
	if health.Status != models.StatusError {
		t.Errorf("expected Error status on timeout, got %s", health.Status)
	}
}
