package pollers

import (
	"crypto/tls"
	"crypto/x509"
	"net"

	"go.uber.org/zap"

	"github.com/prometheus/client_golang/prometheus"
)

// A TLS protected service. This can be any type of service, and simply adds
// certificate metrics to the base service. As a result it is not directly
// instantiated.
type TLSService struct {
	CertificateNotAfter   *prometheus.GaugeVec   // Epoch time the SSL certificate expires
	CertificateNotBefore  *prometheus.GaugeVec   // Epoch time the SSL certificate is not valid before
	CertificateValid      *prometheus.GaugeVec   // Whether the certificate validates to this host
	CertificateValidCount *prometheus.CounterVec // Cumulative count of SSL validations

	tlsRootCAs *x509.CertPool // Certificate pool to validate the service with

	Poller
}

func (s *TLSService) Describe(ch chan<- *prometheus.Desc) {
	s.CertificateNotAfter.Describe(ch)
	s.CertificateNotBefore.Describe(ch)
	s.CertificateValid.Describe(ch)

	s.CertificateValidCount.Describe(ch)

	// Do basic service collection
	s.Poller.Describe(ch)
}

func (s *TLSService) Collect(ch chan<- prometheus.Metric) {
	s.CertificateNotAfter.Collect(ch)
	s.CertificateNotBefore.Collect(ch)
	s.CertificateValid.Collect(ch)

	s.CertificateValidCount.Collect(ch)

	// Do basic service collection
	s.Poller.Collect(ch)
}

// Poll but for the SSL service.
func (s *TLSService) Poll() {
	conn := s.doPoll()
	if conn != nil {
		s.log().Info("Success")
		if err := conn.Close(); err != nil {
			s.log().Info("Error closing connection", zap.String("error", err.Error()))
		}
	}
}

func (s *TLSService) doPoll() net.Conn {
	conn := s.Poller.doPoll()
	if conn == nil {
		return nil
	}

	// Upgrade to TLS connection
	conn = s.scrapeTLS(conn)
	return conn
}

// Scrape TLS data from a dialed connection.
func (s *TLSService) scrapeTLS(conn net.Conn) net.Conn {
	tlsConfig := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
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
		s.CertificateValid.WithLabelValues(hostcert.Subject.CommonName).Set(0)
		s.CertificateValidCount.WithLabelValues(MetricLabelFailed).Inc()
	} else {
		s.CertificateValid.WithLabelValues(hostcert.Subject.CommonName).Set(1)
		s.CertificateValidCount.WithLabelValues(MetricLabelSuccess).Inc()
	}

	s.CertificateNotAfter.WithLabelValues(hostcert.Subject.CommonName).Set(float64(hostcert.NotAfter.Unix()))
	s.CertificateNotBefore.WithLabelValues(hostcert.Subject.CommonName).Set(float64(hostcert.NotBefore.Unix()))

	return tlsConn
}
