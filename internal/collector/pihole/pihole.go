package pihole

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/khalid7344/home-network-watch/internal/models"
)

// Client handles communication with a Pi-hole API instance.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// SummaryRawResponse matches Pi-hole's api.php?summaryRaw JSON output.
type SummaryRawResponse struct {
	DNSQueriesToday    int64   `json:"dns_queries_today"`
	AdsBlockedToday    int64   `json:"ads_blocked_today"`
	AdsPercentageToday float64 `json:"ads_percentage_today"`
	UniqueDomains      int64   `json:"unique_domains"`
	ClientsEverSeen    int64   `json:"clients_ever_seen"`
	UniqueClients      int64   `json:"unique_clients"`
	Status             string  `json:"status"`
}

// TopItemsResponse matches Pi-hole's api.php?topItems=10 JSON output.
type TopItemsResponse struct {
	TopQueries map[string]int `json:"top_queries"`
	TopAds     map[string]int `json:"top_ads"`
	TopSources map[string]int `json:"top_sources"`
}

// New creates a new Pi-hole collector client.
func New(baseURL, token string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	cleanURL := strings.TrimRight(baseURL, "/")

	return &Client{
		baseURL: cleanURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// Name returns the collector name.
func (c *Client) Name() string {
	return "pihole"
}

// CollectDNS fetches raw summary and top items from Pi-hole.
func (c *Client) CollectDNS(ctx context.Context) (models.DNSMetrics, models.CollectorHealth, error) {
	health := models.CollectorHealth{
		Name:      "Pi-hole",
		Status:    models.StatusHealthy,
		LastCheck: time.Now(),
	}

	summary, err := c.fetchSummaryRaw(ctx)
	if err != nil {
		health.Status = models.StatusError
		health.Message = fmt.Sprintf("fetch summaryRaw failed: %v", err)
		return models.DNSMetrics{}, health, err
	}

	topItems, err := c.fetchTopItems(ctx, 10)
	if err != nil {
		// If topItems fails (e.g. auth issue), mark as degraded but return what we have
		health.Status = models.StatusDegraded
		health.Message = fmt.Sprintf("summaryRaw OK, but topItems failed: %v", err)
		return models.DNSMetrics{
			TotalQueries:   summary.DNSQueriesToday,
			BlockedQueries: summary.AdsBlockedToday,
			TopDomains:     make(map[string]int),
			ActiveClients:  make(map[string]int),
		}, health, nil
	}

	topDomains := make(map[string]int)
	for k, v := range topItems.TopQueries {
		topDomains[k] = v
	}
	for k, v := range topItems.TopAds {
		topDomains[k] = v
	}

	activeClients := make(map[string]int)
	for k, v := range topItems.TopSources {
		// Pi-hole sometimes returns "ip|hostname", split to keep IP or clean name
		cleanClient := strings.Split(k, "|")[0]
		activeClients[cleanClient] = v
	}

	metrics := models.DNSMetrics{
		TotalQueries:   summary.DNSQueriesToday,
		BlockedQueries: summary.AdsBlockedToday,
		TopDomains:     topDomains,
		ActiveClients:  activeClients,
	}

	health.Message = fmt.Sprintf("Pi-hole %s: %d total queries, %d blocked", summary.Status, summary.DNSQueriesToday, summary.AdsBlockedToday)
	return metrics, health, nil
}

func (c *Client) fetchSummaryRaw(ctx context.Context) (*SummaryRawResponse, error) {
	apiEndpoint := fmt.Sprintf("%s/admin/api.php?summaryRaw", c.baseURL)
	if c.token != "" {
		apiEndpoint += "&auth=" + url.QueryEscape(c.token)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", "HomeNetworkWatch/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	var summary SummaryRawResponse
	if err := json.Unmarshal(body, &summary); err != nil {
		return nil, fmt.Errorf("unmarshaling summary JSON: %w (raw: %s)", err, string(body))
	}

	return &summary, nil
}

func (c *Client) fetchTopItems(ctx context.Context, count int) (*TopItemsResponse, error) {
	if count <= 0 {
		count = 10
	}
	apiEndpoint := fmt.Sprintf("%s/admin/api.php?topItems=%d", c.baseURL, count)
	if c.token != "" {
		apiEndpoint += "&auth=" + url.QueryEscape(c.token)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", "HomeNetworkWatch/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	// Pi-hole returns [] if unauthorized or empty
	if strings.TrimSpace(string(body)) == "[]" {
		return nil, fmt.Errorf("Pi-hole returned empty topItems (unauthorized token?)")
	}

	var topItems TopItemsResponse
	if err := json.Unmarshal(body, &topItems); err != nil {
		return nil, fmt.Errorf("unmarshaling topItems JSON: %w", err)
	}

	return &topItems, nil
}
