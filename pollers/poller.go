package pollers

import (

	"github.com/prometheus/client_golang/prometheus"
	"net"
	"math"
)

const Namespace = "poller"

type Status float64

var UNKNOWN = Status(math.NaN())
const SUCCESS = Status(float64(1))
const FAILED = Status(float64(0))

const LBL_SUCCESS = "successful"
const LBL_FAIL = "failed"

type Poller interface {
	// Causes the service to update its internal state.
	Poll()

	Name() string // Returns the name of the poller
	Proto() string // Returns the protocol of the poller
	Port() uint64 // Returns the port of the poller
	Status() Status // Returns the overall status of the service
	Host() *Host // Returns the attached host of the service

	Describe(ch chan <- *prometheus.Desc)
	Collect(ch chan <- prometheus.Metric)

	doPoll() net.Conn	// Polls the base methods and returns the established connection object
}
