package pollers

import (
	config "github.com/wrouesnel/poller_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	"net"
	"time"
)

const subsystem = "poller"

type BasicService struct {
	PortOpen	prometheus.Gauge	// Is the port reachable?
	ServiceResponsive prometheus.Gauge	// Is the service responding with data?
	Latency		prometheus.Gauge	// Service latency in milliseconds

	Host string	// The host this service
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

func NewBasicService(host Host, opts config.BasicServiceConfig) {
	return &BasicService{
		Name: name,
		Protocol : protocol,
		Port: port,
		PortOpen: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: subsystem,
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
		ServiceReponsive: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: subsystem,
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
		Latency: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: subsystem,
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
}

// Poll implements the actual polling functionality of the service. It is distinct
// to the prometheus scrapers because we only ever want to run polls on *our*
// schedule.
func (s* BasicService) Poll() {
	// For a basic service we dial the connection and store it.
}

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

// SSL services are always TCP, for now.
func NewSSLService(opts config.SSLServiceConfig) {
	return &SSLService{
		NewBasicService()
	}
}