package pollers

import (
	"fmt"
	"net"
	"time"

	"github.com/pkg/errors"

	"github.com/wrouesnel/poller_exporter/pkg/config"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

type BasicService struct {
	portOpen Status // Was the port successfully accessed?

	PortOpen      prometheus.Gauge       // Port open metric
	PortOpenCount *prometheus.CounterVec // Cumulative number of port open checks

	host *Host // The host this service is attached to
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

func (s *BasicService) Describe(ch chan<- *prometheus.Desc) {
	s.PortOpen.Describe(ch)
}

func (s *BasicService) Collect(ch chan<- prometheus.Metric) {
	s.PortOpen.Set(float64(s.portOpen))
	s.PortOpen.Collect(ch)
}

//nolint:funlen
func NewBasicService(host *Host, opts config.BasicServiceConfig) Poller {
	var poller Poller

	clabels := prometheus.Labels{
		"hostname": host.Hostname,
		"name":     opts.Name,
		"protocol": opts.Protocol,
		"port":     fmt.Sprintf("%d", opts.Port),
	}

	newBasicService := &BasicService{
		host:     host,
		portOpen: PollStatusUnknown,
		PortOpen: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "port_open_boolean",
				Help:        "whether the targeted port by the service is open (i.e. can be connected to)",
				ConstLabels: clabels,
			},
		),
		PortOpenCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "port_open_count",
				Help:        "cumulative count of checks for if the port is open",
				ConstLabels: clabels,
			},
			[]string{"result"},
		),
		BasicServiceConfig: opts,
	}

	poller = Poller(newBasicService)

	// If SSL, then return an SSL service instead
	if opts.TLSEnable {
		newSSLservice := TLSService{
			CertificateNotBefore: prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "tls_certificate_validity_notbefore",
				Help:        "TLS certificate valid from",
				ConstLabels: clabels,
			}, []string{"commonName"}),
			CertificateNotAfter: prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "tls_certificate_validity_notafter",
				Help:        "TLS certificate expiry",
				ConstLabels: clabels,
			}, []string{"commonName"}),
			CertificateValid: prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "tls_certificate_validity_valid",
				Help:        "TLS certificate can be validated by the scraper process",
				ConstLabels: clabels,
			}, []string{"commonName"}),
			CertificateValidCount: prometheus.NewCounterVec(
				prometheus.CounterOpts{
					Namespace:   Namespace,
					Subsystem:   "service",
					Name:        "tls_certificate_validity_valid_total",
					Help:        "cumulative count of TLS certificate validations",
					ConstLabels: clabels,
				},
				[]string{"result"},
			),
			tlsRootCAs: opts.TLSCACerts.CertPool,
			Poller:     poller,
		}
		poller = Poller(&newSSLservice) // Turn the SSL service into a Poller
	}

	return poller
}

// Poll implements the actual polling functionality of the service. It is distinct
// to the prometheus scrapers because we only ever want to run polls on *our*
// schedule.
func (s *BasicService) Poll() {
	//nolint:revive
	if conn := s.doPoll(); conn == nil {
		return
	} else {
		defer conn.Close()
	}
}

// doPoll Implements the real polling functionality, but returns the connection object so other classes can inherit it.
func (s *BasicService) doPoll() net.Conn {
	l := s.log().With(zap.String("hostname", s.Host().Hostname),
		zap.Uint64("port", s.Port()),
		zap.String("name", s.Name()))
	l.Debug("Dialing basic service")
	conn, err := s.dialAndScrape()
	if err != nil {
		l.Info("Error", zap.String("error", err.Error()))
		s.portOpen = PollStatusFailed
	} else {
		l.Info("Success")
		s.portOpen = PollStatusSuccess
	}

	return conn
}

// dialAndScrape connects to the service and collects parameters.
func (s *BasicService) dialAndScrape() (net.Conn, error) {
	l := s.log()
	if s.Timeout == 0 {
		l.Warn("0 deadline set for service. This is probably not what you want as services will flap.")
	}

	// Set absolute deadline
	deadline := time.Now().Add(time.Duration(s.Timeout))

	// Dialer deadline
	dialer := net.Dialer{
		Deadline: deadline,
	}

	var err error
	var conn net.Conn

	conn, err = dialer.Dial(s.Protocol, fmt.Sprintf("%s:%d", s.Host().Hostname, s.Port()))
	if err != nil {
		s.portOpen = PollStatusFailed
	} else {
		s.portOpen = PollStatusSuccess
	}

	if conn != nil {
		// Connection deadline
		if err := conn.SetDeadline(deadline); err != nil {
			l.Error("Error setting deadline for connection", zap.Error(err))
		}
	}

	return conn, errors.Wrap(err, "dialAndScrape failed")
}

func (s *BasicService) log() *zap.Logger {
	l := zap.L()
	if s.host != nil {
		return s.host.log()
	}
	return l.With(zap.String("logger_note", "no host"))
}
