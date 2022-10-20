package pollers

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"

	connect_proxy_scheme "github.com/wrouesnel/go.connect-proxy-scheme"

	"github.com/samber/lo"
	"golang.org/x/net/proxy"

	"github.com/pkg/errors"

	"github.com/wrouesnel/poller_exporter/pkg/config"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

//nolint:gochecknoinits
func init() {
	proxy.RegisterDialerType("http", connect_proxy_scheme.ConnectProxy)
}

type BasicService struct {
	labels prometheus.Labels

	portOpen Status // Was the port successfully accessed?

	PortOpen      prometheus.Gauge       // Port open metric
	PortOpenCount *prometheus.CounterVec // Cumulative number of port open checks

	host   *Host // The host this service is attached to
	config config.BasicServiceConfig
}

func (s *BasicService) Name() string {
	return s.config.Name
}

func (s *BasicService) Port() uint64 {
	return s.config.Port
}

func (s *BasicService) Status() Status {
	return s.portOpen
}

func (s *BasicService) Host() *Host {
	return s.host
}

func (s *BasicService) Proto() string {
	return s.config.Protocol
}

func (s *BasicService) Describe(ch chan<- *prometheus.Desc) {
	s.PortOpen.Describe(ch)
}

func (s *BasicService) Collect(ch chan<- prometheus.Metric) {
	s.PortOpen.Set(float64(s.portOpen))
	s.PortOpen.Collect(ch)
}

func (s *BasicService) Labels() prometheus.Labels {
	return s.labels
}

//nolint:funlen
func NewBasicService(host *Host, opts config.BasicServiceConfig, constantLabels prometheus.Labels) BasePoller {
	var poller BasePoller

	if constantLabels == nil {
		constantLabels = prometheus.Labels{
			"poller_type": PollerTypeBasic,
			"hostname":    host.Hostname,
			"name":        opts.Name,
			"protocol":    opts.Protocol,
			"port":        fmt.Sprintf("%d", opts.Port),
		}
	}

	// Append additional labels from host and service
	if host.ExtraLabels != nil {
		for labelKey, labelValue := range host.ExtraLabels {
			constantLabels[labelKey] = labelValue
		}
	}

	if opts.ExtraLabels != nil {
		for labelKey, labelValue := range opts.ExtraLabels {
			constantLabels[labelKey] = labelValue
		}
	}

	newBasicService := &BasicService{
		labels:   constantLabels,
		host:     host,
		portOpen: PollStatusUnknown,
		PortOpen: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "port_open_boolean",
				Help:        "whether the targeted port by the service is open (i.e. can be connected to)",
				ConstLabels: constantLabels,
			},
		),
		PortOpenCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "port_open_count",
				Help:        "cumulative count of checks for if the port is open",
				ConstLabels: constantLabels,
			},
			[]string{"result"},
		),
		config: opts,
	}

	poller = BasePoller(newBasicService)

	// If SSL, then return an SSL service instead
	if opts.TLSEnable {
		tlsSniName := ""
		if opts.TLSServerNameIndication != nil {
			tlsSniName = *opts.TLSServerNameIndication
		} else {
			// Check if the hostname is an IP address
			if net.ParseIP(host.Hostname) == nil {
				// This is a hostname and we don't have an explicit SNI set -
				// use that.
				tlsSniName = host.Hostname
			}
		}

		newSSLservice := TLSService{
			CertificateNotBefore: prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "tls_certificate_validity_notbefore",
				Help:        "TLS certificate valid from",
				ConstLabels: constantLabels,
			}, []string{"commonName"}),
			CertificateNotAfter: prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "tls_certificate_validity_notafter",
				Help:        "TLS certificate expiry",
				ConstLabels: constantLabels,
			}, []string{"commonName"}),
			CertificateValid: prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "tls_certificate_validity_valid",
				Help:        "TLS certificate can be validated by the scraper process",
				ConstLabels: constantLabels,
			}, []string{"commonName"}),
			CertificateValidCount: prometheus.NewCounterVec(
				prometheus.CounterOpts{
					Namespace:   Namespace,
					Subsystem:   "service",
					Name:        "tls_certificate_validity_valid_total",
					Help:        "cumulative count of TLS certificate validations",
					ConstLabels: constantLabels,
				},
				[]string{"result"},
			),
			CertificateMatchesPin: prometheus.NewGauge(prometheus.GaugeOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "tls_certificate_matches_pin_bool",
				Help:        "TLS certificate matches one of the specified pinned certificates (1 for true, 0 for false)",
				ConstLabels: constantLabels}),
			tlsVerifyFailOk: opts.TLSVerifyFailOk,
			tlsSniName:      tlsSniName,
			tlsRootCAs:      opts.TLSCACerts.CertPool,
			tlsPinMap:       opts.TLSCertificatePin,
			BasePoller:      poller,
		}
		poller = BasePoller(&newSSLservice) // Turn the SSL service into a Poller
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
func (s *BasicService) doPoll() *PollConnection {
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
func (s *BasicService) dialAndScrape() (*PollConnection, error) {
	l := s.log()
	if s.config.Timeout == 0 {
		l.Warn("0 deadline set for service. This is probably not what you want as services will flap.")
	}

	// Set absolute deadline
	deadline := time.Now().Add(time.Duration(s.config.Timeout))
	// Build context for deadline
	//nolint:govet
	ctx, ctxCancel := context.WithDeadline(context.Background(), deadline)

	var err error
	var proxyDialer proxy.Dialer
	switch s.config.Proxy {
	case config.ProxyEnvironment:
		l.Debug("Using proxy settings from the environment")
		proxyDialer = proxy.FromEnvironment()
	case config.ProxyDirect:
		l.Debug("Direct connection")
		proxyDialer = proxy.Direct
	default:
		l.Debug("Explicit proxy configured", zap.String("proxy", s.config.Proxy))
		// config has already checked this URL and we don't want to overdesign it
		proxyURL := lo.Must(url.Parse(s.config.Proxy))
		// proxy package handles default specification
		proxyDialer = lo.Must(proxy.FromURL(proxyURL, proxy.Direct))
	}

	dialer := proxyDialer.(proxy.ContextDialer) //nolint: forcetypeassert

	var conn net.Conn
	conn, err = dialer.DialContext(ctx, s.config.Protocol, fmt.Sprintf("%s:%d", s.Host().Hostname, s.Port()))
	if err != nil {
		s.portOpen = PollStatusFailed
	} else {
		s.portOpen = PollStatusSuccess
	}

	if conn == nil {
		ctxCancel() // Pre-cancel the context
		return nil, errors.Wrap(err, "dialAndScrape failed")
	}

	// Set connection deadline
	if err := conn.SetDeadline(deadline); err != nil {
		l.Error("Error setting deadline for connection", zap.Error(err))
	}

	// govet will flag this as a lost context, but this is just how poller_exporter works.
	//nolint:govet,containedctx,nolintlint
	return &PollConnection{
		Conn:     conn,
		dialer:   dialer,
		deadline: deadline,
		ctx:      ctx,
	}, nil
}

func (s *BasicService) log() *zap.Logger {
	l := zap.L()
	if s.host != nil {
		return s.host.log()
	}
	return l.With(zap.String("logger_note", "no host"))
}

// LogFields returns a description of this poller as zap logging fields.
func (s *BasicService) LogFields() []zap.Field {
	return []zap.Field{
		zap.String("name", s.Name()),
		zap.String("proto", s.Proto()),
		zap.Uint64("port", s.Port()),
		zap.String("hostname", s.host.Hostname),
	}
}
