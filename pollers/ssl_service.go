package pollers

import (
	"crypto/tls"
	"crypto/x509"
	"go.uber.org/zap"
	"net"

	"github.com/prometheus/client_golang/prometheus"
)

// An SSL protected service. This can be any type of service, and simply adds
// certificate metrics to the base service. As a result it is not directly
// instantiated.
type SSLService struct {
	SSLNotAfter   *prometheus.GaugeVec   // Epoch time the SSL certificate expires
	SSLNotBefore  *prometheus.GaugeVec   // Epoch time the SSL certificate is not valid before
	SSLValid      *prometheus.GaugeVec   // Whether the certificate validates to this host
	SSLValidCount *prometheus.CounterVec // Cumulative count of SSL validations
	Poller
}

func (s *SSLService) Describe(ch chan<- *prometheus.Desc) {
	s.SSLNotAfter.Describe(ch)
	s.SSLNotBefore.Describe(ch)
	s.SSLValid.Describe(ch)

	s.SSLValidCount.Describe(ch)

	// Do basic service collection
	s.Poller.Describe(ch)
}

func (s *SSLService) Collect(ch chan<- prometheus.Metric) {
	s.SSLNotAfter.Collect(ch)
	s.SSLNotBefore.Collect(ch)
	s.SSLValid.Collect(ch)

	s.SSLValidCount.Collect(ch)

	// Do basic service collection
	s.Poller.Collect(ch)
}

// Poll but for the SSL service.
func (s *SSLService) Poll() {
	conn := s.doPoll()
	if conn != nil {
		s.log().Info("Success")
		if err := conn.Close(); err != nil {
			s.log().Info("Error closing connection", zap.String("error", err.Error()))
		}
	}

}

func (s *SSLService) doPoll() net.Conn {
	conn := s.Poller.doPoll()
	if conn == nil {
		return nil
	}

	// Upgrade to TLS connection
	conn = s.scrapeTLS(conn)
	return conn
}

// Scrape TLS data from a dialed connection
func (s *SSLService) scrapeTLS(conn net.Conn) net.Conn {
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil
	}

	hostcert := tlsConn.ConnectionState().PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, cert := range tlsConn.ConnectionState().PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		DNSName:       s.Host().Hostname,
		Intermediates: intermediates,
	}

	if _, err := hostcert.Verify(opts); err != nil {
		s.SSLValid.WithLabelValues(hostcert.Subject.CommonName).Set(0)
		s.SSLValidCount.WithLabelValues(MetricLabelFailed).Inc()
	} else {
		s.SSLValid.WithLabelValues(hostcert.Subject.CommonName).Set(1)
		s.SSLValidCount.WithLabelValues(MetricLabelSuccess).Inc()
	}

	s.SSLNotAfter.WithLabelValues(hostcert.Subject.CommonName).Set(float64(hostcert.NotAfter.Unix()))
	s.SSLNotBefore.WithLabelValues(hostcert.Subject.CommonName).Set(float64(hostcert.NotBefore.Unix()))

	return tlsConn
}
