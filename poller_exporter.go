// Prometheus remote-endpoint poller exporter.
// Implements asynchronous remote polling for many protocols.
//
// Support protocols:
// - SSL
// - HTTP
// - MySQL
// - Postgres
// - POP3
// - IMAP
// - SMTP
// - FTP
// - SSH
// - ICMP

package main 

import (
    "fmt"
    "net"
    "os"
    "os/signal"
    "syscall"
    "time"
    "sync"
    
    "flag"
    //"github.com/vharitonsky/iniflags"
    
	log "github.com/prometheus/log"
	"github.com/prometheus/client_golang/prometheus"
	
	// SSL
	"crypto/tls"
    "crypto/x509"
    
    // HTTP
	"net/http"
	"github.com/mxk/go-imap/imap"

	// MYSQL
	// Posgres
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"

	"database/sql"
	
	// IMAP
	"github.com/mxk/go-imap"
	"github.com/taknb2nch/go-pop3"
	
	// SMTP
	"net/smtp"
	
	// FTP
	"github.com/dutchcoders/goftp"
	
	// SSH
	"golang.org/x/crypto/ssh"
	
	// ICMP Ping
	"golang.org/x/net/icmp"
)

const subsystem = "poller"

type hostsSlice []string

func (hosts *hostsSlice) String() string {
	return fmt.Sprintf("%s", *hosts)
}

func (hosts *hostsSlice) Set(value string) error {
	*hosts = append(*hosts, value)
	return nil
}

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

// Base-type from which service definitions are inherited.
type BaseService struct {
	Name		string					// Name of the service
	Protocol	string					// TCP or UDP
	Port		uint64					// Port number of the service
//	LastPoll	*prometheus.CounterVec	// Time this service was last polled

	PortOpen	*prometheus.GaugeVec	// Is the port reachable?
	ServiceResponsive *prometheus.GaugeVec	// Is the service responding with data?
	
	mtx	sync.Mutex	// Protects the metrics during collection
}

func (s *BaseService) Describe(ch chan <- *prometheus.Desc) {
//	s.LastPoll.Describe(ch)
	s.Port.Describe(ch)
	s.PortOpen.Describe(ch)
	s.ServiceResponsive.Describe(ch)
}

func (s* BaseService) Collect(ch chan <- *prometheus.Metric) {
//	s.LastPoll.Collect(ch)
	s.Port.Collect(ch)
	s.PortOpen.Collect(ch)
	s.ServiceResponsive.Collect(ch)	
}

func NewService(name string, protocol string, port uint64) {
	return &Service{
		Name: name,
		Protocol : protocol,
		Port: port,
		PortOpen: prometheus.NewGaugeVec(
			Namespace: subsystem,
			Subsystem: "service",
			Name: "port_open_boolean",
		),
		ServiceReponsive: prometheus.NewGaugeVec(
			Namespace: subsystem,
			Subsystem: "service",
			Name: "responsive_boolean",
		)
	}
}

var (
	Version = "0.0.0.dev"
	
	listenAddress     = flag.String("web.listen-address", ":9551", "Address on which to expose metrics and web interface.")
	metricsPath       = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")
	
	pollTime = flag.Duration("collector.poll-time", time.Minute * 30, "How frequently to poll the SSL services")
	connectionTimeout = flag.Duration("collector.connection-timeout", time.Second * 60, "How long to wait for connection to succeed")
	
	monitoredHosts hostsSlice
	
	lastCollection = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ssl_collection_lasttimestamp",
			Help: "Timestamp of last SSL poll by the exporter",
			})
	
	hostContactable = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "target_connection_reachable",
			Help: "Target host connection can be established",
			},
		[]string{"instance"})
	
	sslNotBefore = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ssl_validity_notbefore",
			Help: "SSL certificate valid from",
			},
		[]string{"instance", "commonName"})
	sslNotAfter = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ssl_validity_notafter",
			Help: "SSL certificate expiry",
			},
		[]string{"instance", "commonName"})
	sslIsValid = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ssl_validity_valid",
			Help: "SSL certificate can be validated by the scraper process",
			},
		[]string{"instance", "commonName"})
)

func init() {
	prometheus.MustRegister(hostContactable)
	prometheus.MustRegister(sslIsValid)
	prometheus.MustRegister(sslNotBefore)
	prometheus.MustRegister(sslNotAfter)
}

// Poll a specific target and update it's prometheus statistics
func poll_target(target string) {
	// Pre-validate that there's a sensible input
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		log.Errorf("Failed to get host from string. %s", err.Error())
		hostContactable.WithLabelValues(target).Set(0)
		return
	}
	
	// Dial the TLS connection
	tlsConfig := &tls.Config{ InsecureSkipVerify : true }
	
	dialer := new(net.Dialer)
	dialer.Timeout = *connectionTimeout
	conn, err := tls.DialWithDialer(dialer, "tcp", target, tlsConfig)
	
	if err != nil {
		log.Warnf("Failed to connect to %s. Error: %s\n", target, err.Error())
		hostContactable.WithLabelValues(target).Set(0)
		return
	}
	hostContactable.WithLabelValues(target).Set(1)
	defer conn.Close()
	
	hostcert := conn.ConnectionState().PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, cert := range conn.ConnectionState().PeerCertificates[1:] { 
		intermediates.AddCert(cert)
	} 

	opts := x509.VerifyOptions{
		DNSName: host,
		Intermediates: intermediates,
		}
	
	var validityResult float64
	if _, err := hostcert.Verify(opts); err != nil {
		validityResult = 0
	} else {
		validityResult = 1
	}
	
	log.Debugf("Poll Success! Cert: %s |Not Before: %d |Not After: %d | Is Valid: %d",
		hostcert.Subject.CommonName,
		hostcert.NotBefore.Unix(),
		hostcert.NotAfter.Unix(),
		validityResult)
	
	sslNotAfter.WithLabelValues(target,hostcert.Subject.CommonName).Set(float64(hostcert.NotAfter.Unix()))
	sslNotBefore.WithLabelValues(target,hostcert.Subject.CommonName).Set(float64(hostcert.NotBefore.Unix()))
	sslIsValid.WithLabelValues(target,hostcert.Subject.CommonName).Set(float64(validityResult))
}

// Periodically runs a go routine to poll all our targets
func poller(monitoredHosts []string) {
	var tlast time.Time
	
	for {
		tSince := time.Since(tlast)
		if *pollTime >= tSince {
			timer := time.NewTimer(*pollTime - tSince)
			<- timer.C
			continue
		}
		tlast = time.Now()
		for _, target := range monitoredHosts {
			go poll_target(target)
		}
	}
}

func main() {
	flag.Var(&monitoredHosts, "service", "Specify multiple times for each host that should be monitored")
	iniflags.Parse()
	
	for _, host := range monitoredHosts {
		log.Infof("Monitoring SSL for: %s\n", host)
		monitoredHosts = append(monitoredHosts, host)
	} 
	
	// This doesn't strictly seem to be used?
	sigUsr1 := make(chan os.Signal)
	signal.Notify(sigUsr1, syscall.SIGUSR1)
	
	go poller(monitoredHosts)	// Start the poller
	
	handler := prometheus.Handler()
    http.Handle(*metricsPath, handler)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
			<head><title>Remote Poller Exporter</title></head>
			<body>
			<h1>Remote Poller Exporter</h1>
			<p><a href="` + *metricsPath + `">Metrics</a></p>
			</body>
			</html>`))
	})
	
    err := http.ListenAndServe(*listenAddress, nil)
    log.Infof("Listening on %s", *listenAddress)
	if err != nil {
		log.Fatal(err)
	}
}

