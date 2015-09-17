package pollers

import (
	"net"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/log"
	"github.com/tatsushid/go-fastping"
	config "github.com/wrouesnel/poller_exporter/config"
	"math"
	"math/rand"
)

// Hosts are the top of a service hierarchy and contain a number of pollers.
// If the host fails to be resolvable or routable, then all pollers beneath it
// stop returning data (specifically they return NaN).
type Host struct {
	IP       string // Resolved IP address (from last poll)

	Pollers []Poller // List of services to poll

	NumPolls	  prometheus.Counter // Number of times polls have been attempted
	LastPollTime  prometheus.Gauge // Time of last poll
	Resolvable    prometheus.Gauge // Is the hostname resolvable (IP is always true)
	PathReachable prometheus.Gauge // Is the host IP routable?
	Latency		  prometheus.Gauge // Latency to contact host - NaN if unavailable

	lastPoll	time.Time	// Time we last polled
	ping		time.Duration // Last known ping time

	config.HostConfig
}

func NewHost(opts config.HostConfig) *Host {
	// Setup the host
	newHost := Host{
		NumPolls : prometheus.NewCounter(prometheus.CounterOpts{
			Namespace:	Namespace,
			Subsystem:	"host",
			Name: 		"polls_total",
			Help:		"Number of times this host has been polled by the exporter",
			ConstLabels: prometheus.Labels{"hostname" : opts.Hostname },
		}),
		LastPollTime : prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:	Namespace,
			Subsystem:	"host",
			Name: 		"last_poll_time",
			Help:		"Last time this host was polled by the exporter",
			ConstLabels: prometheus.Labels{"hostname" : opts.Hostname },
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
		Latency: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   Namespace,
			Subsystem:   "host",
			Name:        "latency_milliseconds",
			Help:        "service latency in milliseconds",
			ConstLabels: prometheus.Labels{"hostname": opts.Hostname},
		}),

		ping: time.Duration(math.MaxInt64),
	}
	newHost.HostConfig = opts

	// Default everything to NaN since we don't know them
	newHost.NumPolls.Set(0)	// Except this one.
	newHost.Resolvable.Set(math.NaN())
	newHost.PathReachable.Set(math.NaN())
	newHost.Latency.Set(math.NaN())
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

func (s *Host) Ping() time.Duration {
	return s.ping
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
	s.Latency.Describe(ch)
	s.Resolvable.Describe(ch)
	s.PathReachable.Describe(ch)
	s.NumPolls.Describe(ch)

	for _, poller := range s.Pollers {
		poller.Describe(ch)
	}
}

func (s *Host) Collect(ch chan<- prometheus.Metric) {
	s.NumPolls.Collect(ch)
	s.LastPollTime.Collect(ch)
	s.Latency.Collect(ch)
	s.Resolvable.Collect(ch)
	s.PathReachable.Collect(ch)
	s.NumPolls.Collect(ch)

	for _, poller := range s.Pollers {
		poller.Collect(ch)
	}
}

func (s *Host) StartPolling(delayStart bool) {
	go func() {
		log.Infoln("Polling", s.Hostname,
			"poll_frequency", time.Duration(s.PollFrequency).String(),
			"ping_timeout", time.Duration(s.PingTimeout).String())

		// Delay the poll start by a random amount of the frequency
		if delayStart {
			startDelay := time.Duration(rand.Float64() * float64(s.PollFrequency))
			startTimer := time.NewTimer(startDelay)
			log.Debugln("Waiting", startDelay.String(), "to start", s.Hostname)
			<-startTimer.C
		}

		pollTimer := time.NewTimer(time.Duration(s.PollFrequency))
		for {
			s.Poll()	// Do the Poll

			// Wait for the timer for next poll.
			log.Debugln("Waiting for poll timer", s.Hostname)
			<- pollTimer.C
			pollTimer.Reset(s.NextPoll())
		}
	}()
}

func (s *Host) Poll() {
	var err error
	s.lastPoll = time.Now()	// Mark poll start
	s.LastPollTime.Set(float64(s.lastPoll.Unix()))
	s.NumPolls.Inc()

	// Is host resolvable ?
	ipAddrs, err := net.LookupHost(s.Hostname)
	if err != nil {
		s.Resolvable.Set(0)
		return
	}
	s.IP = ipAddrs[0]
	s.Resolvable.Set(1)
	log.Debugln("Resolved", s.Hostname, s.IP)

	// Can the host be reached by ICMP?
	if !s.PingDisable {
		s.doPing()
	}

	// Call poller methods
	for _, poller := range s.Pollers {
		poller.Poll()
	}
}

// Do an ICMP ping. Borrowed from bbrazil's blackbox exporter.
func (s *Host) doPing() {
	pinger := fastping.NewPinger()
	pinger.AddIP(s.IP)
	pinger.MaxRTT = time.Duration(s.PingTimeout)
	pinger.Size = 1500

	pinger.OnRecv = func(ip *net.IPAddr, latency time.Duration) {
		log.Infoln(s.Hostname, "latency", latency.String())
		s.ping = latency
		s.Latency.Set(float64(latency) / float64(time.Millisecond))
		s.PathReachable.Set(1)
	}
	log.Debugln("Pinging", s.Hostname)
	err := pinger.Run()
	if err != nil {
		log.Infoln(s.Hostname, "ping timeout!")
		s.ping = math.MaxInt64
		s.Latency.Set(float64(math.NaN()))
		s.PathReachable.Set(0)
	}

	log.Debugln(s.Hostname, "is reachable!")
}

