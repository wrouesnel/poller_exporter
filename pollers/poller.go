package pollers

import (
	config "github.com/wrouesnel/poller_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

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
	return &Host{

	}
}