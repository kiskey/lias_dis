// Package nftables implements the isolated firewall controller for LIAS.
//
// File:    apps/lias/internal/nftables/builder.go
// Version: 1.6 (Latched Block Set Invariant: Eliminates block-unblock oscillation loop)
package nftables

import (
	"net"
	"sync"

	"github.com/user/lias-dis/apps/lias/internal/policy"
	liasSync "github.com/user/lias-dis/apps/lias/internal/sync"
	"github.com/user/lias-dis/shared/models"
)

// Builder evaluates LIAS policies and updates the netfilter set elements.
type Builder struct {
	mu         sync.Mutex
	cache      *liasSync.Cache
	controller *Controller
}

// NewBuilder initializes a new rules builder.
func NewBuilder(cache *liasSync.Cache, controller *Controller) *Builder {
	return &Builder{
		cache:      cache,
		controller: controller,
	}
}

// Sync evaluates all devices in the local cache and applies updated sets to nftables.
//
// LATCHED BLOCK INVARIANT (CRITICAL FIX):
// Devices evaluated to ActionBlock MUST have their MACs and IPs latched into blocked_macs
// and blocked_ips REGARDLESS of whether d.Online is true or false.
//
// Rationale: Dropping a device's packets at the netdev hook causes L2 neighbor entries to fail,
// causing DIS to report d.Online = false. If d.Online = false caused the block rule to be removed,
// the device would instantly unblock, transmit a packet, get re-blocked, and loop infinitely.
// Latching ActionBlock sets eliminates this positive feedback loop entirely.
func (b *Builder) Sync(policyEngine policy.PolicyEvaluator, schedEngine policy.ScheduleEvaluator) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	devs := b.cache.List()

	allowedIPsMap := make(map[string]net.IP)
	blockedIPsMap := make(map[string]net.IP)
	allowedMACsMap := make(map[string]net.HardwareAddr)
	blockedMACsMap := make(map[string]net.HardwareAddr)

	for i := range devs {
		d := &devs[i]

		// Evaluate effective policy action for device regardless of current online observation state
		action := policyEngine.EvaluateAction(d, schedEngine)

		switch action {
		case models.ActionAllow:
			// Allowed elements are populated only when the device is actively observed online
			// to keep the @allowed sets minimal and performant.
			if !d.Online {
				continue
			}
			for _, ipStr := range d.IPs {
				if ip := net.ParseIP(ipStr); ip != nil {
					if ip4 := ip.To4(); ip4 != nil {
						allowedIPsMap[ip4.String()] = ip4
					}
				}
			}
			for _, macStr := range d.MACs {
				if mac, err := net.ParseMAC(macStr); err == nil && len(mac) == 6 {
					allowedMACsMap[mac.String()] = mac
				}
			}

		case models.ActionBlock:
			// LATCHED BLOCK INVARIANT:
			// Block elements MUST be populated for all historical/current MACs and IPs
			// EVEN IF d.Online is false!
			for _, ipStr := range d.IPs {
				if ip := net.ParseIP(ipStr); ip != nil {
					if ip4 := ip.To4(); ip4 != nil {
						blockedIPsMap[ip4.String()] = ip4
					}
				}
			}
			for _, macStr := range d.MACs {
				if mac, err := net.ParseMAC(macStr); err == nil && len(mac) == 6 {
					blockedMACsMap[mac.String()] = mac
				}
			}
		}
	}

	var allowedIPs, blockedIPs []net.IP
	for _, ip := range allowedIPsMap {
		allowedIPs = append(allowedIPs, ip)
	}
	for _, ip := range blockedIPsMap {
		blockedIPs = append(blockedIPs, ip)
	}

	var allowedMACs, blockedMACs []net.HardwareAddr
	for _, mac := range allowedMACsMap {
		allowedMACs = append(allowedMACs, mac)
	}
	for _, mac := range blockedMACsMap {
		blockedMACs = append(blockedMACs, mac)
	}

	return b.controller.Apply(
		SetElements{IPs: allowedIPs, MACs: allowedMACs},
		SetElements{IPs: blockedIPs, MACs: blockedMACs},
	)
}
