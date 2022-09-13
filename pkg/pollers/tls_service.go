package pollers

import (
	"crypto/tls"
	"crypto/x509"
	"math"
	"net"

	"github.com/samber/lo"

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
	s.log().Debug("Establish TLS connnection",
		zap.String("tls_sni_name", s.tlsSniName),
		zap.Bool("tls_verify_fail_ok", s.tlsVerifyFailOk))
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
	s.log().Debug("Host certificate",
		zap.Int("chain_idx", 0),
		zap.String("x509_subject", hostcert.Subject.CommonName),
		zap.Strings("x509_dns_names", hostcert.DNSNames),
		zap.Strings("x509_ip_addrs", lo.Map(hostcert.IPAddresses, func(ip net.IP, _ int) string { return ip.String() })))

	intermediates := x509.NewCertPool()
	for idx, cert := range tlsConn.ConnectionState().PeerCertificates[1:] {
		s.log().Debug("Intermediate Certificate",
			zap.Int("chain_idx", idx+1),
			zap.String("x509_subject", hostcert.Subject.CommonName),
			zap.Strings("x509_dns_names", hostcert.DNSNames),
			zap.Strings("x509_ip_addrs", lo.Map(hostcert.IPAddresses, func(ip net.IP, _ int) string { return ip.String() })))

		intermediates.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		DNSName:       s.tlsSniName,
		Intermediates: intermediates,
		Roots:         s.tlsRootCAs,
	}

	if _, err := hostcert.Verify(opts); err != nil {
		s.log().Debug("TLS verify failure", zap.Error(err))
		s.CertificateValid.WithLabelValues(hostcert.Subject.CommonName).Set(0)
		s.CertificateValidCount.WithLabelValues(MetricLabelFailed).Inc()
		if s.tlsVerifyFailOk {
			s.statusTLS = PollStatusSuccess
		} else {
			s.statusTLS = PollStatusFailed
		}
	} else {
		s.log().Debug("TLS verify success")
		s.CertificateValid.WithLabelValues(hostcert.Subject.CommonName).Set(1)
		s.CertificateValidCount.WithLabelValues(MetricLabelSuccess).Inc()
		s.statusTLS = PollStatusSuccess
	}

	s.CertificateNotAfter.WithLabelValues(hostcert.Subject.CommonName).Set(float64(hostcert.NotAfter.Unix()))
	s.CertificateNotBefore.WithLabelValues(hostcert.Subject.CommonName).Set(float64(hostcert.NotBefore.Unix()))

	if s.tlsPinMap != nil {
		if s.tlsPinMap.HasCert(hostcert) {
			s.log().Debug("Set status okay due to pinned certificate matching")
			s.CertificateMatchesPin.Set(1)
			s.statusTLS = PollStatusSuccess
		} else {
			s.log().Debug("Set status failed due to pinned certificate NOT matching")
			s.CertificateMatchesPin.Set(0)
			s.statusTLS = PollStatusFailed
		}
	} else {
		s.CertificateMatchesPin.Set(math.NaN())
	}

	return &PollConnection{
		Conn:     tlsConn,
		dialer:   conn.dialer,
		deadline: conn.deadline,
		ctx:      conn.ctx,
	}
}
