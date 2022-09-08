package pollers

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/wrouesnel/poller_exporter/pkg/config"

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

	CertificateMatchesPin prometheus.Gauge // Whether the certificate matches the pinned certificate list

	tlsVerifyFailOk bool                      // Status can be OK if TLS verify fails.
	tlsSniName      string                    // SNI name if status is not okay
	tlsRootCAs      *x509.CertPool            // Certificate pool to validate the service with
	tlsPinMap       *config.TLSCertificateMap // TLS certificates which are considered pinned

	statusTLS Status // tracks whether the current TLS status is verified

	BasePoller
}

func (s *TLSService) Status() Status {
	if s.BasePoller.Status() == PollStatusSuccess {
		// Port is Open. Check if certificate verified.
		return s.statusTLS
	}
	return s.BasePoller.Status()
}

func (s *TLSService) Describe(ch chan<- *prometheus.Desc) {
	s.CertificateNotAfter.Describe(ch)
	s.CertificateNotBefore.Describe(ch)
	s.CertificateValid.Describe(ch)
	s.CertificateValidCount.Describe(ch)

	s.CertificateMatchesPin.Describe(ch)

	// Do basic service collection
	s.BasePoller.Describe(ch)
}

func (s *TLSService) Collect(ch chan<- prometheus.Metric) {
	s.CertificateNotAfter.Collect(ch)
	s.CertificateNotBefore.Collect(ch)
	s.CertificateValid.Collect(ch)
	s.CertificateValidCount.Collect(ch)

	s.CertificateMatchesPin.Collect(ch)

	// Do basic service collection
	s.BasePoller.Collect(ch)
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

func (s *TLSService) doPoll() *PollConnection {
	conn := s.BasePoller.doPoll()
	if conn == nil {
		return nil
	}

	// Upgrade to TLS connection
	conn = s.scrapeTLS(conn)
	return conn
}

// Scrape TLS data from a dialed connection.
func (s *TLSService) scrapeTLS(conn *PollConnection) *PollConnection {
	tlsConfig := &tls.Config{
		ServerName:         s.tlsSniName,
		InsecureSkipVerify: true, //nolint:gosec
	}
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		s.statusTLS = PollStatusFailed
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
		if s.tlsVerifyFailOk {
			s.statusTLS = PollStatusSuccess
		} else {
			s.statusTLS = PollStatusFailed
		}
	} else {
		s.CertificateValid.WithLabelValues(hostcert.Subject.CommonName).Set(1)
		s.CertificateValidCount.WithLabelValues(MetricLabelSuccess).Inc()
		s.statusTLS = PollStatusSuccess
	}

	s.CertificateNotAfter.WithLabelValues(hostcert.Subject.CommonName).Set(float64(hostcert.NotAfter.Unix()))
	s.CertificateNotBefore.WithLabelValues(hostcert.Subject.CommonName).Set(float64(hostcert.NotBefore.Unix()))

	if s.tlsPinMap != nil {
		if s.tlsPinMap.HasCert(hostcert) {
			s.CertificateMatchesPin.Set(1)
			s.statusTLS = PollStatusSuccess
		} else {
			s.CertificateMatchesPin.Set(0)
			s.statusTLS = PollStatusFailed
		}
	}

	return &PollConnection{
		Conn:     tlsConn,
		dialer:   conn.dialer,
		deadline: conn.deadline,
		ctx:      conn.ctx,
	}
}
