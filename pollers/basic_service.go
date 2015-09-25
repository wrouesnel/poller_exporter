package pollers

import (
	config "github.com/wrouesnel/poller_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	"net"
	"time"
	"fmt"
	"github.com/prometheus/log"
)

type BasicService struct {
	portOpen Status // Was the port successfully accessed?

	PortOpen	prometheus.Gauge	// Port open metric

	host *Host	// The host this service is attached to
	config.BasicServiceConfig
}

func (s *BasicService) Name() string {
	return s.BasicServiceConfig.Name
}

func (s *BasicService) Port() uint64 {
	return s.BasicServiceConfig.Port
}

func (s *BasicService) Status() Status {
	return s.portOpen
}

func (s *BasicService) Host() *Host {
	return s.host
}

func (s *BasicService) Proto() string {
	return s.Protocol
}

func (s *BasicService) Describe(ch chan <- *prometheus.Desc) {
	s.PortOpen.Describe(ch)
}

func (s *BasicService) Collect(ch chan <- prometheus.Metric) {
	s.PortOpen.Set(float64(s.portOpen))
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
		host: host,
		portOpen: UNKNOWN,
		PortOpen: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: "service",
				Name: "port_open_boolean",
				Help: "whether the targeted port by the service is open (i.e. can be connected to)",
				ConstLabels: clabels,
			},
		),
		BasicServiceConfig: opts,
	}

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
			Poller: poller,
		}
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
		s.portOpen = FAILED
	} else {
		log.Infoln("Success", s.Host().Hostname, s.Port(), s.Name())
		s.portOpen = SUCCESS
	}

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
		s.portOpen = FAILED
	} else {
		s.portOpen = SUCCESS
	}

	return conn, err
}