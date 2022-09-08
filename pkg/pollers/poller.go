package pollers

import (
	"context"
	"math"
	"net"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"golang.org/x/net/proxy"
)

const Namespace = "poller"

type Status float64

var PollStatusUnknown = Status(math.NaN()) //nolint:gochecknoglobals

const PollStatusSuccess = Status(float64(1))
const PollStatusFailed = Status(float64(0))

const MetricLabelSuccess = "successful"
const MetricLabelFailed = "failed"

const (
	PollerTypeBasic             = "basic"
	PollerTypeChallengeResponse = "challenge-response"
	PollerTypeHTTP              = "http"
)

// PollConnection wraps net.Conn and carries additional information about the
// service poll.
//nolint:containedctx
type PollConnection struct {
	net.Conn
	dialer   proxy.ContextDialer // dialer is the dialer instance used to make the original outbound connection
	deadline time.Time           // deadline is the timeout set when the connection was originally opened
	ctx      context.Context
}

// Deadline is the timeout set when the connection was originally opened.
func (p *PollConnection) Deadline() time.Time {
	return p.deadline
}

func (p *PollConnection) Context() context.Context {
	return p.ctx
}

func (p *PollConnection) Dialer() proxy.ContextDialer {
	return p.dialer
}

// BasePoller implements the doPoll method which returns the net.Conn so
// a higher level Poller can use it. Poller's which functionally cannot
// release the connection cannot be BasePollers.
type BasePoller interface {
	doPoll() *PollConnection // Polls the base methods and returns the established connection object
	Poller
}

type Poller interface {
	// Poll causes the service to update it's internal state.
	// Every Poll implementation should call any nested Poll implementations
	// *first* before running it's own functionality.
	Poll()

	Name() string   // Returns the name of the poller
	Proto() string  // Returns the protocol of the poller
	Port() uint64   // Returns the port of the poller
	Status() Status // Returns the overall status of the service
	Host() *Host    // Returns the attached host of the service

	Labels() prometheus.Labels
	Describe(ch chan<- *prometheus.Desc)
	Collect(ch chan<- prometheus.Metric)

	LogFields() []zap.Field // Return a description of this poller in zap fields

	log() *zap.Logger // Provide common logging for pollers
}
