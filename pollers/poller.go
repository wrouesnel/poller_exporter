package pollers

import (
	config "github.com/wrouesnel/poller_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

const Namespace = "poller"

// Implements the basic interface for updating pollers.
type Poller interface {
	Poll()	// Causes the service to update its internal state.
}

// Hosts are the top of a service hierarchy and contain a number of pollers.
// If the host fails to be resolvable or routable, then all pollers beneath it
// stop returning data (specifically they return NaN).
type Host struct {
	Hostname string		// Host or IP to contact

	Resolvable prometheus.Gauge	// Is the hostname resolvable (IP is always true)
	PathReachable	prometheus.Gauge	// Is the host IP routable?

	Pollers []Poller	// List of services to poll
}

func NewHost(opts config.HostConfig) *Host {
	// Setup the host
	newHost := Host{
		Hostname: opts.Hostname,
		Resolvable: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: "host",
			Name: "resolvable_boolean",
			Help: "Did the last attempt to DNS resolve this host succeed?",
			ConstLabels: { "hostname" : opts.Hostname },
		}),
		PathReachable: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: "host",
			Name: "routable_boolean",
			Help: "Is the resolved IP address routable on this hosts network",
			ConstLabels: { "hostname" : opts.Hostname },
		}),
	}

	// Setup it's services
	for _, basicCfg := range opts.BasicChecks {

	}

	for _, crCfg := range opts.ChallengeResponseChecks {

	}

	for _, httpCfg := range opts.HTTPChecks {

	}

	return &newHost
}