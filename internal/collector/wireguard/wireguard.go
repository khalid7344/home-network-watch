package wireguard

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/khalid7344/home-network-watch/internal/models"
)

// CommandRunner abstracts command execution for testability.
type CommandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Collector gathers WireGuard metrics by running `wg show <iface> dump`.
type Collector struct {
	iface  string
	runner CommandRunner
}

// DefaultRunner executes commands using os/exec.
func DefaultRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// New creates a new WireGuard collector.
func New(iface string, runner CommandRunner) *Collector {
	if runner == nil {
		runner = DefaultRunner
	}
	return &Collector{
		iface:  iface,
		runner: runner,
	}
}

// Name returns the collector name.
func (c *Collector) Name() string {
	return "wireguard"
}

// CollectWireGuard runs the wg tool and parses the output into models.WGPeerState.
func (c *Collector) CollectWireGuard(ctx context.Context) ([]models.WGPeerState, models.CollectorHealth, error) {
	health := models.CollectorHealth{
		Name:      "WireGuard",
		Status:    models.StatusHealthy,
		LastCheck: time.Now(),
	}

	var args []string
	if c.iface != "" && c.iface != "all" {
		args = []string{"show", c.iface, "dump"}
	} else {
		args = []string{"show", "all", "dump"}
	}

	output, err := c.runner(ctx, "wg", args...)
	if err != nil {
		// Try sudo wg show ... if regular wg failed with permission denied or similar
		var sudoErr error
		sudoArgs := append([]string{"wg"}, args...)
		output, sudoErr = c.runner(ctx, "sudo", sudoArgs...)
		if sudoErr != nil {
			health.Status = models.StatusError
			health.Message = fmt.Sprintf("failed running wg show: %v (sudo fallback: %v)", err, sudoErr)
			return nil, health, fmt.Errorf("running wg show: %w", err)
		}
	}

	peers, err := ParseDump(output, c.iface)
	if err != nil {
		health.Status = models.StatusDegraded
		health.Message = fmt.Sprintf("parsing wg dump output failed: %v", err)
		return nil, health, err
	}

	health.Message = fmt.Sprintf("WireGuard OK (%d peers)", len(peers))
	return peers, health, nil
}

// ParseDump parses the tab-delimited output of `wg show <iface> dump`.
func ParseDump(data []byte, targetIface string) ([]models.WGPeerState, error) {
	var peers []models.WGPeerState
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Split(line, "\t")
		// Interface line has 5 fields: iface, privkey, pubkey, port, fwmark
		// Peer line has 8 or 9 fields: iface, pubkey, preshared_key, endpoint, allowed_ips, latest_handshake, rx, tx, persistent_keepalive
		// Note: if interface is specified explicitly (e.g. wg show wg0 dump), interface name might be omitted in some wg versions,
		// but `dump` flag with `all` has 9 fields for peer, 5 for iface. With specific iface, 8 fields for peer, 4 for iface.
		if len(parts) == 5 || (len(parts) == 4 && !strings.Contains(parts[1], "=")) {
			// Interface line, skip
			continue
		}

		var pubKey, endpoint, allowedIPsStr, handshakeStr, rxStr, txStr string

		if len(parts) >= 9 {
			// wg show all dump format:
			// parts[0]: iface
			// parts[1]: pubkey
			// parts[2]: preshared_key
			// parts[3]: endpoint
			// parts[4]: allowed_ips
			// parts[5]: latest_handshake (unix epoch)
			// parts[6]: rx_bytes
			// parts[7]: tx_bytes
			// parts[8]: persistent_keepalive
			if targetIface != "" && targetIface != "all" && parts[0] != targetIface {
				continue
			}
			pubKey = parts[1]
			endpoint = parts[3]
			allowedIPsStr = parts[4]
			handshakeStr = parts[5]
			rxStr = parts[6]
			txStr = parts[7]
		} else if len(parts) >= 8 {
			// wg show wg0 dump format:
			// parts[0]: pubkey
			// parts[1]: preshared_key
			// parts[2]: endpoint
			// parts[3]: allowed_ips
			// parts[4]: latest_handshake
			// parts[5]: rx_bytes
			// parts[6]: tx_bytes
			// parts[7]: persistent_keepalive
			pubKey = parts[0]
			endpoint = parts[2]
			allowedIPsStr = parts[3]
			handshakeStr = parts[4]
			rxStr = parts[5]
			txStr = parts[6]
		} else {
			// Unrecognized line format
			continue
		}

		handshakeEpoch, _ := strconv.ParseInt(handshakeStr, 10, 64)
		var latestHandshake time.Time
		if handshakeEpoch > 0 {
			latestHandshake = time.Unix(handshakeEpoch, 0)
		}

		rxBytes, _ := strconv.ParseInt(rxStr, 10, 64)
		txBytes, _ := strconv.ParseInt(txStr, 10, 64)

		var allowedIPs []string
		if allowedIPsStr != "" && allowedIPsStr != "(none)" {
			for _, ip := range strings.Split(allowedIPsStr, ",") {
				clean := strings.TrimSpace(ip)
				if clean != "" {
					allowedIPs = append(allowedIPs, clean)
				}
			}
		}

		peers = append(peers, models.WGPeerState{
			PublicKey:       pubKey,
			Endpoint:        endpoint,
			AllowedIPs:      allowedIPs,
			LatestHandshake: latestHandshake,
			RxBytes:         rxBytes,
			TxBytes:         txBytes,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading wg output: %w", err)
	}

	return peers, nil
}
