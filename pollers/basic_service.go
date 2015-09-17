package pollers

import (
	config "github.com/wrouesnel/poller_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	"net"
	"time"
	"fmt"
	"github.com/prometheus/log"
	"math"
)

type BasicService struct {
	PortOpen	prometheus.Gauge	// Is the port reachable?

	succeeding	bool // Indicates if the poller's last check succeeded overall
	host *Host	// The host this service is attached to

	config.BasicServiceConfig
}

func (s *BasicService) Name() string {
	return s.BasicServiceConfig.Name
}

func (s *BasicService) Port() uint64 {
	return s.BasicServiceConfig.Port
}

func (s *BasicService) Status() bool {
	return s.succeeding
}

func (s *BasicService) Host() *Host {
	return s.host
}

func (s *BasicService) Describe(ch chan <- *prometheus.Desc) {
	//	s.LastPoll.Describe(ch)
	s.PortOpen.Describe(ch)
}

func (s *BasicService) Collect(ch chan <- prometheus.Metric) {
	s.PortOpen.Collect(ch)
}

func NewBasicService(host *Host, opts config.BasicServiceConfig) Poller {
	var poller Poller

	clabels := prometheus.Labels{
		"hostname" : host.Hostname,
		"name" : opts.Name,
		"protocol" : opts.Protocol,
		"port" : fmt.Sprintf("%d", opts.Port),
	}

	newBasicService := &BasicService{
		PortOpen: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: "service",
				Name: "port_open_boolean",
				Help: "whether the targeted port by the service is open (i.e. can be connected to)",
				ConstLabels: clabels,
			},
		),

	}
	newBasicService.PortOpen.Set(math.NaN())
	newBasicService.BasicServiceConfig = opts
	newBasicService.host = host

	poller = Poller(newBasicService)

	// If SSL, then return an SSL service instead
	if opts.UseSSL {
		newSSLservice := SSLService{
			SSLNotBefore : prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: "service",
				Name: "ssl_validity_notbefore",
				Help: "SSL certificate valid from",
				ConstLabels: clabels,
			}, []string{"commonName"}),
			SSLNotAfter : prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: "service",
				Name: "ssl_validity_notafter",
				Help: "SSL certificate expiry",
				ConstLabels: clabels,
			}, []string{"commonName"}),
			SSLValid : prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: "service",
				Name: "ssl_validity_valid",
				Help: "SSL certificate can be validated by the scraper process",
				ConstLabels: clabels,
			}, []string{"commonName"}),
		}

		newSSLservice.Poller = poller
		poller = Poller(&newSSLservice)	// Turn the SSL service into a Poller
	}

	return poller
}

// Poll implements the actual polling functionality of the service. It is distinct
// to the prometheus scrapers because we only ever want to run polls on *our*
// schedule.
func (s *BasicService) Poll() {
	conn := s.doPoll()
	if conn == nil {
		return
	}
	defer conn.Close()
}

// Implements the real polling functionality, but returns the connection object
// so other classes can inherit it.
func (s *BasicService) doPoll() net.Conn {
	log.Debugln("Dialing basic service", s.Host().Hostname, s.Port(), s.Name(),)
	conn, err := s.dialAndScrape()
	if err != nil {
		log.Infoln("Error", s.Host().Hostname, s.Port(), s.Name(), err)
		return nil
	}

	log.Infoln("Success", s.Host().Hostname, s.Port(), s.Name())
	s.succeeding = true

	return conn
}

// Dial and scrape the basic service parameters
func (s *BasicService) dialAndScrape() (net.Conn, error) {
	dialer := net.Dialer{
		Deadline: time.Now().Add(time.Duration(s.Timeout)),
	}

	var err error
	var conn net.Conn

	conn, err = dialer.Dial(s.Protocol, fmt.Sprintf("%s:%d", s.Host().Hostname, s.Port()))
	if err != nil {
		s.PortOpen.Set(0)
		return conn, err
	}
	s.PortOpen.Set(1)

	return conn, err
}