package pollers

import (
	"net"
	"time"

	"github.com/wrouesnel/poller_exporter/pkg/config"

	"go.uber.org/zap"

	"math"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/wrouesnel/poller_exporter/pkg/pollers/ping"
)

// Hosts are the top of a service hierarchy and contain a number of pollers.
// If the host fails to be resolvable or routable, then all pollers beneath it
// stop returning data (specifically they return NaN).
type Host struct {
	IP string // Resolved IP address (from last poll)

	Pollers []Poller // List of services to poll

	// Instantaneous metrics (easy to alert against)
	NumPolls      prometheus.Counter // Number of times polls have been attempted
	LastPollTime  prometheus.Gauge   // Time of last poll
	Resolvable    prometheus.Gauge   // Is the hostname resolvable (IP is always true)
	PathReachable prometheus.Gauge   // Is the host IP routable?
	PingLatency   prometheus.Gauge   // Latency to contact host - NaN if unavailable

	// Tally metrics (more accurate but harder)
	ResolvableCount *prometheus.CounterVec // success/failure count
	ReachableCount  *prometheus.CounterVec // success/failure count
	PingResultCount *prometheus.CounterVec // cumulative count of pings
	LatencyCount    prometheus.Counter     // cumulative latency from successful polls

	lastPoll    time.Time     // Time we last polled
	pingStatus  Status        // Last known ping result
	pingLatency time.Duration // Last known ping time

	config.HostConfig
}

//nolint:funlen
func NewHost(opts config.HostConfig) *Host {
	// Setup the host
	newHost := Host{
		IP: "", // Initially unresolved
		NumPolls: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace:   Namespace,
			Subsystem:   "host",
			Name:        "polls_total",
			Help:        "Number of times this host has been polled by the exporter",
			ConstLabels: prometheus.Labels{"hostname": opts.Hostname},
		}),
		LastPollTime: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   Namespace,
			Subsystem:   "host",
			Name:        "last_poll_time",
			Help:        "Last time this host was polled by the exporter",
			ConstLabels: prometheus.Labels{"hostname": opts.Hostname},
		}),
		Resolvable: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   Namespace,
			Subsystem:   "host",
			Name:        "resolvable_boolean",
			Help:        "Did the last attempt to DNS resolve this host succeed?",
			ConstLabels: prometheus.Labels{"hostname": opts.Hostname},
		}),
		PathReachable: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   Namespace,
			Subsystem:   "host",
			Name:        "routable_boolean",
			Help:        "Is the resolved IP address routable on this hosts network",
			ConstLabels: prometheus.Labels{"hostname": opts.Hostname},
		}),
		PingLatency: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   Namespace,
			Subsystem:   "host",
			Name:        "latency_microseconds",
			Help:        "service latency in microseconds",
			ConstLabels: prometheus.Labels{"hostname": opts.Hostname},
		}),
		// Cumulative counters
		ResolvableCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace:   Namespace,
				Subsystem:   "host",
				Name:        "resolvable_total",
				Help:        "cumulative successful DNS resolutions",
				ConstLabels: prometheus.Labels{"hostname": opts.Hostname},
			},
			[]string{"result"},
		),
		ReachableCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace:   Namespace,
				Subsystem:   "host",
				Name:        "routable_total",
				Help:        "cumulative successful network route resolutions",
				ConstLabels: prometheus.Labels{"hostname": opts.Hostname},
			},
			[]string{"result"},
		),
		PingResultCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace:   Namespace,
				Subsystem:   "host",
				Name:        "ping_count_total",
				Help:        "cumulative number of pings sent to the host",
				ConstLabels: prometheus.Labels{"hostname": opts.Hostname},
			},
			[]string{"result"},
		),
		LatencyCount: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace:   Namespace,
				Subsystem:   "host",
				Name:        "latency_seconds_total",
				Help:        "cumulative service latency in seconds",
				ConstLabels: prometheus.Labels{"hostname": opts.Hostname},
			},
		),

		lastPoll:    time.Time{},
		pingStatus:  PollStatusUnknown,
		pingLatency: time.Duration(math.MaxInt64),

		HostConfig: opts,
		Pollers:    make([]Poller, 0, len(opts.BasicChecks)+len(opts.ChallengeResponseChecks)+len(opts.HTTPChecks)),
	}

	// Default everything to NaN since we don't know them
	// newHost.NumPolls.Set(0) // Don't need to reset the counter
	newHost.Resolvable.Set(math.NaN())
	newHost.PathReachable.Set(math.NaN())
	newHost.PingLatency.Set(math.NaN())
	newHost.LastPollTime.Set(math.NaN())

	// Setup it's services
	for _, basicCfg := range opts.BasicChecks {
		newHost.Pollers = append(newHost.Pollers, Poller(NewBasicService(&newHost, *basicCfg))) //nolint:unconvert
	}

	for _, crCfg := range opts.ChallengeResponseChecks {
		newHost.Pollers = append(newHost.Pollers, Poller(NewChallengeResponseService(&newHost, *crCfg)))
	}

	for _, httpCfg := range opts.HTTPChecks {
		newHost.Pollers = append(newHost.Pollers, Poller(NewHTTPService(&newHost, *httpCfg)))
	}

	return &newHost
}

func (s *Host) Status() Status {
	return s.pingStatus
}

func (s *Host) Latency() time.Duration {
	return s.pingLatency
}

func (s *Host) LastPoll() time.Time {
	return s.lastPoll
}

func (s *Host) SincePoll() time.Duration {
	return time.Since(s.lastPoll)
}

// Return the expected time till the next poll is attempted.
func (s *Host) NextPoll() time.Duration {
	return time.Until(s.lastPoll.Add(time.Duration(s.PollFrequency)))
}

func (s *Host) Describe(ch chan<- *prometheus.Desc) {
	s.NumPolls.Describe(ch)
	s.LastPollTime.Describe(ch)
	s.Resolvable.Describe(ch)
	s.PathReachable.Describe(ch)
	s.PingLatency.Describe(ch)
	s.NumPolls.Describe(ch)

	s.ResolvableCount.Describe(ch)
	s.ReachableCount.Describe(ch)
	s.PingResultCount.Describe(ch)
	s.LatencyCount.Describe(ch)

	for _, poller := range s.Pollers {
		poller.Describe(ch)
	}
}

func (s *Host) Collect(ch chan<- prometheus.Metric) {
	s.NumPolls.Collect(ch)
	s.LastPollTime.Collect(ch)
	s.Resolvable.Collect(ch)

	// Reachable?
	s.PathReachable.Set(float64(s.pingStatus))
	s.PathReachable.Collect(ch)

	//Latency
	switch s.pingStatus {
	case PollStatusUnknown:
		s.PingLatency.Set(math.NaN())
	case PollStatusFailed:
		s.PingLatency.Set(math.Inf(1))
	case PollStatusSuccess:
		s.PingLatency.Set(float64(s.pingLatency / time.Microsecond))
	default:
		s.log().Warn("Unknown PollStatus value returned")
		s.PingLatency.Set(float64(s.pingLatency / time.Microsecond))
	}
	s.PingLatency.Collect(ch)

	s.NumPolls.Collect(ch)

	s.ResolvableCount.Collect(ch)
	s.ReachableCount.Collect(ch)
	s.PingResultCount.Collect(ch)
	s.LatencyCount.Collect(ch)

	for _, poller := range s.Pollers {
		poller.Collect(ch)
	}
}

// Polls this host, and queues up the next poll.
func (s *Host) Poll(limiter *Limiter, hostQueue chan<- *Host) {
	// Mark the start of the poller and increment the count
	s.lastPoll = time.Now()
	s.LastPollTime.Set(float64(s.lastPoll.Unix()))
	s.NumPolls.Inc()

	// Use the connection limiter in this closure so we can ensure an unlock
	func() {
		limiter.Lock()
		defer limiter.Unlock()

		var err error

		// Is host resolvable ?
		ipAddrs, err := net.LookupHost(s.Hostname)
		if err != nil {
			s.Resolvable.Set(0)
			s.ResolvableCount.WithLabelValues(MetricLabelFailed).Inc()
			return
		}
		s.IP = ipAddrs[0]
		s.Resolvable.Set(1)
		s.ResolvableCount.WithLabelValues(MetricLabelSuccess).Inc()
		s.log().Debug("Resolved hostname")

		// Can the host be reached by ICMP?
		if !s.PingDisable {
			s.doPing()
		}

		// Call poller methods
		for _, poller := range s.Pollers {
			s.log().Debug("Invoking Poller", zap.String("poller_name", poller.Name()))
			poller.Poll()
		}
	}()

	// Schedule a requeue of ourselves
	if hostQueue != nil {
		timeToNext := s.NextPoll()
		if timeToNext <= 0 {
			s.log().Debug("Host overdue, queuing immediately", zap.Duration("time_to_next", timeToNext))
		} else {
			s.log().Debug("Host pending, waiting to requeue", zap.Duration("time_to_next", timeToNext))
			<-time.After(timeToNext)
			s.log().Debug("Poll time finished, requeuing")
		}
		hostQueue <- s
	}
}

// Do an ICMP ping.
func (s *Host) doPing() {
	// Try pinging the host up to PingCount times till it responds.
	// possibly we should calculate dropped packets, but there's lots of
	// reasons it could happen and better ways to do it too.
	var pingSuccess bool
	for i := uint64(0); i < s.PingCount; i++ {
		s.log().Debug("Pinging")
		ok, latency := ping.Ping(net.ParseIP(s.IP), time.Duration(s.PingTimeout))

		if ok {
			pingSuccess = ok
			s.pingLatency = latency
			s.LatencyCount.Add(float64(latency) / float64(time.Second))
			s.PingResultCount.WithLabelValues(MetricLabelSuccess).Inc()
			break
		}
		s.PingResultCount.WithLabelValues(MetricLabelFailed).Inc()
	}

	if pingSuccess {
		s.log().Info("PollStatusSuccess ICMP ECHO", zap.Duration("pingLatency", s.pingLatency))
		s.pingStatus = PollStatusSuccess
		s.ReachableCount.WithLabelValues(MetricLabelSuccess).Inc()
	} else {
		s.log().Info("PollStatusFailed ICMP ECHO", zap.Uint64("pings", s.PingCount))
		s.pingStatus = PollStatusFailed
		s.ReachableCount.WithLabelValues(MetricLabelFailed).Inc()
	}
}

func (s *Host) log() *zap.Logger {
	return zap.L().With(zap.String("host", s.Hostname), zap.String("ip", s.IP))
}
