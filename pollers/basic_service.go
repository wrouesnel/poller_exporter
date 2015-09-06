package pollers

import (
	config "github.com/wrouesnel/poller_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	"net"
	"time"
)

const Namespace = "poller"

type BasicService struct {
	PortOpen	prometheus.Gauge	// Is the port reachable?
	Latency		prometheus.Gauge	// Service latency in milliseconds

	Host *Host	// The host this service is attached to

	config.BasicServiceConfig
}

func (s *BasicService) Describe(ch chan <- *prometheus.Desc) {
	//	s.LastPoll.Describe(ch)
	s.PortOpen.Describe(ch)
	s.ServiceResponsive.Describe(ch)
	s.Latency.Describe(ch)
}

func (s* BasicService) Collect(ch chan <- *prometheus.Metric) {
	s.PortOpen.Collect(ch)
	s.ServiceResponsive.Collect(ch)
	s.Latency.Collect(ch)
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
					"port" : opts.Port,
				},
			},
		),
		Latency: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: "service",
				Name: "responsive_boolean",
				Help: "indicates if the service responds with data",
				ConstLabels: prometheus.Labels{
					"name" : opts.Name,
					"protocol" : opts.Protocol,
					"port" : opts.Port,
				},
			},
		),
	}
	newBasicService.BasicServiceConfig = opts

	poller = &newBasicService

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

		newSSLservice.BasicService = newBasicService
		poller = &newSSLservice
	}

	return poller
}

// Poll implements the actual polling functionality of the service. It is distinct
// to the prometheus scrapers because we only ever want to run polls on *our*
// schedule.
func (s* BasicService) Poll() {
	// For a basic service we dial the connection and store it.
}

// Dial a TCP port with a hard timeout to ensure we don't block forever.
func (s* BasicService) dialDeadline() (net.Conn, error) {
	dialer := net.Dialer{
		Deadline: time.Now().Add(s.Timeout * time.Second)
	}

	return Dial(s.Protocol, s.)
}

// An SSL protected service. This can be any type of service, and simply adds
// certificate metrics to the base service.
type SSLService struct {
	SSLNotAfter		*prometheus.GaugeVec	// Epoch time the SSL certificate expires
	SSLNotBefore	*prometheus.GaugeVec	// Epoch time the SSL certificate is not valid before
	SSLValid		*prometheus.GaugeVec	// Whether the certificate validates to this host
	BasicService
}