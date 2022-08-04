package pollers

import (
	"math"
	"net"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

const Namespace = "poller"

type Status float64

var PollStatusUnknown = Status(math.NaN()) //nolint:gochecknoglobals

const PollStatusSuccess = Status(float64(1))
const PollStatusFailed = Status(float64(0))

const MetricLabelSuccess = "successful"
const MetricLabelFailed = "failed"

type Poller interface {
	// Causes the service to update its internal state.
	Poll()

	Name() string   // Returns the name of the poller
	Proto() string  // Returns the protocol of the poller
	Port() uint64   // Returns the port of the poller
	Status() Status // Returns the overall status of the service
	Host() *Host    // Returns the attached host of the service

	Describe(ch chan<- *prometheus.Desc)
	Collect(ch chan<- prometheus.Metric)

	doPoll() net.Conn // Polls the base methods and returns the established connection object

	log() *zap.Logger // Provide common logging for pollers
}
