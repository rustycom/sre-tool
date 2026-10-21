// Package metrics holds the tool's Prometheus collectors on a dedicated
// registry, so nothing registered by a library leaks into /metrics
// unannounced. Label values are bounded: routes are patterns, and
// no label carries an isolation ID or a raw path.
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics is the set of collectors the tool updates.
type Metrics struct {
	Registry         *prometheus.Registry
	HTTPRequests     *prometheus.CounterVec
	HTTPDuration     *prometheus.HistogramVec
	IsolationsActive prometheus.Gauge
	HardeningResults *prometheus.CounterVec
	RolloutDuration  *prometheus.HistogramVec
}

// New registers the collectors on a fresh registry, plus the standard Go
// runtime and process collectors.
func New() *Metrics {
	m := &Metrics{
		Registry: prometheus.NewRegistry(),
		HTTPRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sre_tool_http_requests_total",
			Help: "HTTP requests by route pattern, method and status code.",
		}, []string{"route", "method", "code"}),
		HTTPDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "sre_tool_http_request_duration_seconds",
			Help:    "HTTP request latency by route pattern and method.",
			Buckets: prometheus.DefBuckets,
		}, []string{"route", "method"}),
		IsolationsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "sre_tool_isolations_active",
			Help: "Isolations in the cluster, recomputed from a list after every isolation mutation and at startup.",
		}),
		HardeningResults: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sre_tool_hardening_workloads_total",
			Help: "Workloads handled by hardening apply, by planned action and result.",
		}, []string{"action", "result"}),
		RolloutDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "sre_tool_rollout_duration_seconds",
			Help: "Time from a hardening patch to the end of its rollout wait, by kind and result.",
			// Rollouts take seconds to minutes; the default buckets stop at 10s.
			Buckets: []float64{1, 5, 10, 30, 60, 120, 180, 300},
		}, []string{"kind", "result"}),
	}
	m.Registry.MustRegister(m.HTTPRequests, m.HTTPDuration, m.IsolationsActive, m.HardeningResults, m.RolloutDuration,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// ObserveRequest records one HTTP request.
func (m *Metrics) ObserveRequest(route, method string, code int, d time.Duration) {
	m.HTTPRequests.WithLabelValues(route, method, strconv.Itoa(code)).Inc()
	m.HTTPDuration.WithLabelValues(route, method).Observe(d.Seconds())
}

// ObserveWorkload counts one workload in a hardening apply.
func (m *Metrics) ObserveWorkload(action, result string) {
	m.HardeningResults.WithLabelValues(action, result).Inc()
}

// ObserveRollout records how long one rollout wait took.
func (m *Metrics) ObserveRollout(kind, result string, d time.Duration) {
	m.RolloutDuration.WithLabelValues(kind, result).Observe(d.Seconds())
}

// Handler serves the registry in the Prometheus text format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}
