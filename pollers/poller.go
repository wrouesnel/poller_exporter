package pollers

import (

	"github.com/prometheus/client_golang/prometheus"
	"net"
)

const Namespace = "poller"

// Implements the basic interface for updating pollers.
type Poller interface {
	Poll()	// Causes the service to update its internal state.

	Name() string // Returns the name of the poller
	Port() uint64 // Returns the port of the poller
	Status() bool // Returns the overall status of the service
	Host() *Host // Returns the attached host of the service

	Describe(ch chan <- *prometheus.Desc)
	Collect(ch chan <- prometheus.Metric)

	doPoll() net.Conn	// Polls the base methods and returns the established connection object
}
