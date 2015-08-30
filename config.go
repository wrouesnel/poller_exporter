package main
import (
	"github.com/prometheus/client_golang/prometheus"
	"sync"
	"time"
)

type HostConfigs struct {
	Hosts []Host	// List of hosts which are to be polled
}

// Defines a host which we want to find service information about.
// Hosts export DNS checks.
type Host struct {
	Hostname string		// Host or IP to contact

	Resolvable *prometheus.GaugeVec	// Is the hostname resolvable (IP is always true)
	PathReachable	*prometheus.GaugeVec	// Is the host IP routable?

	Services []Service	// List of services to poll
}

// A basic network service.
type BaseService struct {
	Name		string					// Name of the service
	Protocol	string					// TCP or UDP
	Port		uint64					// Port number of the service

	PortOpen	prometheus.Gauge	// Is the port reachable?
	ServiceResponsive prometheus.Gauge	// Is the service responding with data?
	Latency		prometheus.Gauge	// Service latency in milliseconds
}

func (s *BaseService) Describe(ch chan <- *prometheus.Desc) {
	//	s.LastPoll.Describe(ch)
	s.Port.Describe(ch)
	s.PortOpen.Describe(ch)
	s.ServiceResponsive.Describe(ch)
	s.Latency.Describe(ch)
}

func (s* BaseService) Collect(ch chan <- *prometheus.Metric) {
	s.Port.Collect(ch)
	s.PortOpen.Collect(ch)
	s.ServiceResponsive.Collect(ch)
	s.Latency.Collect(ch)
}

// Poll implements the actual polling functionality of the service. It is distinct
// to the prometheus scrapers because we only ever want to run polls on *our*
// schedule.
func (s* BaseService) Poll() {

}

func NewService(name string, protocol string, port uint64) {
	return &Service{
		Name: name,
		Protocol : protocol,
		Port: port,
		PortOpen: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: subsystem,
				Subsystem: "service",
				Name: "port_open_boolean",
				Help: "whether the targeted port by the service is open (i.e. can be connected to)"
			},
			[]string{"name"}
		),
		ServiceReponsive: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: subsystem,
				Subsystem: "service",
				Name: "responsive_boolean",
				Help: "indicates if the service responds with data",
			},
			[]string{"name"}
		),
	}
}

// An SSL protected service. This can be any type of service, and simply adds
// certificate metrics to the base service.
type SSLService struct {
	SSLNotAfter		*prometheus.GaugeVec	// Epoch time the SSL certificate expires
	SSLNotBefore	*prometheus.GaugeVec	// Epoch time the SSL certificate is not valid before
	SSLValid		*prometheus.GaugeVec	// Whether the certificate validates to this host
	BaseService
}

// SSL services are always TCP, for now.
func NewSSLService(name string, port uint64) {

}