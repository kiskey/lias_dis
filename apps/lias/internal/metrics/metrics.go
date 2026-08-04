// Package metrics provides Prometheus instrumentation for LIAS.
//
// File:    apps/lias/internal/metrics/metrics.go
// Version: 1.0
package metrics

import (
    "net/http"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
    // DevicesManaged tracks the total number of devices in the LIAS cache.
    DevicesManaged = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "lias_devices_managed_total",
            Help: "Total number of devices managed by LIAS.",
        },
        []string{"status"}, // online, offline
    )

    // PolicyEvaluations tracks the number of times a policy is evaluated.
    PolicyEvaluations = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "lias_policy_evaluations_total",
            Help: "Total number of policy evaluations performed.",
        },
        []string{"action", "policy_type"}, // allow, block, schedule / global, tag, device
    )

    // NftablesSyncs tracks the number of nftables sync cycles.
    NftablesSyncs = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "lias_nftables_syncs_total",
            Help: "Total number of nftables sync cycles executed.",
        },
        []string{"status"}, // success, error
    )

    // NftablesSetSize tracks the number of elements in the nftables sets.
    NftablesSetSize = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "lias_nftables_set_size",
            Help: "Number of elements in the nftables sets.",
        },
        []string{"set_name", "action"}, // allowed_ips, blocked_macs, etc.
    )

    // SSEClients tracks the number of connected SSE clients.
    SSEClients = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "lias_sse_clients_connected",
            Help: "Number of connected SSE clients.",
        },
    )
)

func init() {
    prometheus.MustRegister(DevicesManaged)
    prometheus.MustRegister(PolicyEvaluations)
    prometheus.MustRegister(NftablesSyncs)
    prometheus.MustRegister(NftablesSetSize)
    prometheus.MustRegister(SSEClients)
}

// RegisterHandler attaches the Prometheus metrics endpoint to the provided mux.
func RegisterHandler(mux *http.ServeMux, path string) {
    mux.Handle(path, promhttp.Handler())
}
