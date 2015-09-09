package pollers

import (
	config "github.com/wrouesnel/poller_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	"net"
	"time"
	"fmt"
	"crypto/tls"
	"crypto/x509"
)

type BasicService struct {
	PortOpen	prometheus.Gauge	// Is the port reachable?

	Host *Host	// The host this service is attached to

	config.BasicServiceConfig
}

func (s BasicService) Describe(ch chan <- *prometheus.Desc) {
	//	s.LastPoll.Describe(ch)
	s.PortOpen.Describe(ch)
}

func (s BasicService) Collect(ch chan <- prometheus.Metric) {
	s.PortOpen.Collect(ch)
}

func NewBasicService(host *Host, opts config.BasicServiceConfig) Poller {
	var poller Poller

	newBasicService := &BasicService{
		PortOpen: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: "service",
				Name: "port_open_boolean",
				Help: "whether the targeted port by the service is open (i.e. can be connected to)",
				ConstLabels: prometheus.Labels{
					"name" : opts.Name,
					"protocol" : opts.Protocol,
					"port" : fmt.Sprintf("%d", opts.Port),
				},
			},
		),

	}
	newBasicService.BasicServiceConfig = opts

	poller = Poller(newBasicService)

	// If SSL, then return an SSL service instead
	if opts.UseSSL {
		newSSLservice := SSLService{
			SSLNotBefore : prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: "service",
				Name: "ssl_validity_notbefore",
				Help: "SSL certificate valid from",
			}, []string{"commonName"}),
			SSLNotAfter : prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: "service",
				Name: "ssl_validity_notafter",
				Help: "SSL certificate expiry",
			}, []string{"commonName"}),
			SSLValid : prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: "service",
				Name: "ssl_validity_valid",
				Help: "SSL certificate can be validated by the scraper process",
			}, []string{"commonName"}),
		}

		newSSLservice.BasicService = *newBasicService
		poller = Poller(newSSLservice)
	}

	return poller
}

// Poll implements the actual polling functionality of the service. It is distinct
// to the prometheus scrapers because we only ever want to run polls on *our*
// schedule.
func (s BasicService) Poll() {
	conn, err := s.dialAndScrape()
	if err != nil {
		return
	}
	defer conn.Close()
}

// Poll but for the SSL service.
func (s SSLService) Poll() {
	conn, err := s.dialAndScrape()
	if err != nil {
		return
	}
	defer conn.Close()

	// Pass the connection to the TLS handler
	if s.UseSSL {
		s.scrapeTLS(conn)
	}
}

// Scrape TLS data from a dialed connection
func (s SSLService) scrapeTLS(conn net.Conn) {
	tlsConfig := &tls.Config{ InsecureSkipVerify: true }
	tlsConn := tls.Client(conn, tlsConfig)

	hostcert := tlsConn.ConnectionState().PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, cert := range tlsConn.ConnectionState().PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		DNSName: s.Host.Hostname,
		Intermediates: intermediates,
	}

	if _, err := hostcert.Verify(opts); err != nil {
		s.SSLValid.WithLabelValues(hostcert.Subject.CommonName).Set(0)
	} else {
		s.SSLValid.WithLabelValues(hostcert.Subject.CommonName).Set(1)
	}

	s.SSLNotAfter.WithLabelValues(hostcert.Subject.CommonName).Set(float64(hostcert.NotAfter.Unix()))
	s.SSLNotBefore.WithLabelValues(hostcert.Subject.CommonName).Set(float64(hostcert.NotBefore.Unix()))
}

// Dial and scrape the basic servive parameters
func (s BasicService) dialAndScrape() (net.Conn, error) {
	dialer := net.Dialer{
		Deadline: time.Now().Add(time.Duration(s.Timeout) * time.Second),
	}

	var err error
	var conn net.Conn

	conn, err = dialer.Dial(s.Protocol, fmt.Sprintf("%s:%s", s.Host, s.Port))
	if err != nil {
		s.PortOpen.Set(0)
		return conn, err
	}
	s.PortOpen.Set(1)

	return conn, err
}

// An SSL protected service. This can be any type of service, and simply adds
// certificate metrics to the base service.
type SSLService struct {
	SSLNotAfter		*prometheus.GaugeVec	// Epoch time the SSL certificate expires
	SSLNotBefore	*prometheus.GaugeVec	// Epoch time the SSL certificate is not valid before
	SSLValid		*prometheus.GaugeVec	// Whether the certificate validates to this host
	BasicService
}