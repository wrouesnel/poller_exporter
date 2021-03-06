package pollers

import (
	"net"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"github.com/wrouesnel/poller_exporter/pollers/ping"
	config "github.com/wrouesnel/poller_exporter/config"
	"math"
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
	PingLatency       prometheus.Gauge   // Latency to contact host - NaN if unavailable

	// Tally metrics (more accurate but harder)
	ResolvableCount *prometheus.CounterVec	// success/failure count
	ReachableCount *prometheus.CounterVec	// success/failure count
	PingResultCount *prometheus.CounterVec		// cumulative count of pings
	LatencyCount  prometheus.Counter		// cumulative latency from successful polls

	lastPoll time.Time     // Time we last polled
	ping_status Status	// Last known ping result
	ping_latency     time.Duration // Last known ping time

	config.HostConfig
}

func NewHost(opts config.HostConfig) *Host {
	// Setup the host
	newHost := Host{
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
			Name:        "resolveable_boolean",
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
				Name:        "resolveable_total",
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
		PingResultCount : prometheus.NewCounterVec(
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

		ping_status: UNKNOWN,
		ping_latency: time.Duration(math.MaxInt64),
	}
	newHost.HostConfig = opts

	// Default everything to NaN since we don't know them
	newHost.NumPolls.Set(0) // Except this one.
	newHost.Resolvable.Set(math.NaN())
	newHost.PathReachable.Set(math.NaN())
	newHost.PingLatency.Set(math.NaN())
	newHost.LastPollTime.Set(math.NaN())

	// Setup it's services
	for _, basicCfg := range opts.BasicChecks {
		newHost.Pollers = append(newHost.Pollers, Poller(NewBasicService(&newHost, *basicCfg)))
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
	return s.ping_status
}

func (s *Host) Latency() time.Duration {
	return s.ping_latency
}

func (s *Host) LastPoll() time.Time {
	return s.lastPoll
}

func (s *Host) SincePoll() time.Duration {
	return time.Since(s.lastPoll)
}

// Return the expected time till the next poll is attempted
func (s *Host) NextPoll() time.Duration {
	return s.lastPoll.Add(time.Duration(s.PollFrequency)).Sub(time.Now())
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
	s.PathReachable.Set(float64(s.ping_status))
	s.PathReachable.Collect(ch)

	//Latency
	if s.ping_status == UNKNOWN {
		s.PingLatency.Set(math.NaN())
	} else if s.ping_status == FAILED {
		s.PingLatency.Set(math.Inf(1))
	} else {
		s.PingLatency.Set(float64(s.ping_latency / time.Microsecond))
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

// Polls this host, and queues up the next poll
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
			s.ResolvableCount.WithLabelValues(LBL_FAIL).Inc()
			return
		}
		s.IP = ipAddrs[0]
		s.Resolvable.Set(1)
		s.ResolvableCount.WithLabelValues(LBL_SUCCESS).Inc()
		s.log().Debugln("Resolved hostname")

		// Can the host be reached by ICMP?
		if !s.PingDisable {
			s.doPing()
		}

		// Call poller methods
		for _, poller := range s.Pollers {
			s.log().Debugln("Invoking Poller:", poller.Name())
			poller.Poll()
		}
	}()

	// Schedule a requeue of ourselves
	if hostQueue != nil {
		timeToNext := s.NextPoll()
		if timeToNext <= 0 {
			s.log().Debugln("Host overdue, queuing immediately:", timeToNext)
		} else {
			s.log().Debugln("Host pending, waiting to requeue:", timeToNext)
			<- time.After(timeToNext)
			s.log().Debugln("Poll time finished, requeuing")
		}
		hostQueue <- s
	}
}

// Do an ICMP ping.
func (s *Host) doPing() {
	// Try pinging the host up to PingCount times till it responds.
	// TODO: possibly we should calculate dropped packets, but there's lots of
	// reasons it could happen and better ways to do it too.
	var ping_success bool
	for i := uint64(0); i < s.PingCount; i++ {
		s.log().Debugln("Pinging", s.Hostname)
		ok, latency := ping.Ping(net.ParseIP(s.IP), time.Duration(s.PingTimeout))

		if ok == true {
			ping_success = ok
			s.ping_latency = latency
			s.LatencyCount.Add(float64(latency) / float64(time.Second))
			s.PingResultCount.WithLabelValues(LBL_SUCCESS).Inc()
			break
		}
		s.PingResultCount.WithLabelValues(LBL_FAIL).Inc()
	}

	if ping_success {
		s.log().Infoln("SUCCESS ICMP ECHO", s.ping_latency)
		s.ping_status = SUCCESS
		s.ReachableCount.WithLabelValues(LBL_SUCCESS).Inc()
	} else {
		s.log().Infoln("FAILED ICMP ECHO", s.PingCount, "pings")
		s.ping_status = FAILED
		s.ReachableCount.WithLabelValues(LBL_FAIL).Inc()
	}
}

func (s *Host) log() log.Logger {
	return log.With("host", s.Hostname).With("ip", s.IP)
}