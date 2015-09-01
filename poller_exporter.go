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
	//"net/http"
	//"github.com/mxk/go-imap/imap"

	// MYSQL
	// Posgres
	//_ "github.com/go-sql-driver/mysql"
	//_ "github.com/lib/pq"

	//"database/sql"
	
	// IMAP
	//"github.com/mxk/go-imap"
	//"github.com/taknb2nch/go-pop3"
	
	// SMTP
	//"net/smtp"
	
	// FTP
	//"github.com/dutchcoders/goftp"
	
	// SSH
	//"golang.org/x/crypto/ssh"
	
	// ICMP Ping
	//"golang.org/x/net/icmp"
)

type hostsSlice []string

func (hosts *hostsSlice) String() string {
	return fmt.Sprintf("%s", *hosts)
}

func (hosts *hostsSlice) Set(value string) error {
	*hosts = append(*hosts, value)
	return nil
}



var (
	Version = "0.0.0.dev"
	
	listenAddress     = flag.String("web.listen-address", ":9551", "Address on which to expose metrics and web interface.")
	metricsPath       = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")
	
	pollTime = flag.Duration("collector.poll-frequency", time.Minute * 30, "How frequently to poll services")
)

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

