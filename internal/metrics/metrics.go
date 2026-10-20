// Package metrics holds the tool's Prometheus collectors on a dedicated
// registry, so nothing registered by a library leaks into /metrics
// unannounced (SPEC §9). Label values are bounded: routes are patterns, and
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
	}
	m.Registry.MustRegister(m.HTTPRequests, m.HTTPDuration, m.IsolationsActive,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// ObserveRequest records one HTTP request.
func (m *Metrics) ObserveRequest(route, method string, code int, d time.Duration) {
	m.HTTPRequests.WithLabelValues(route, method, strconv.Itoa(code)).Inc()
	m.HTTPDuration.WithLabelValues(route, method).Observe(d.Seconds())
}

// Handler serves the registry in the Prometheus text format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}
