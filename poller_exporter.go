// Prometheus remote-endpoint poller exporter.
// Implements asynchronous remote polling for network endpoints.

package main 

import (
    "flag"
	"net/http"
	"html/template"
	"path"
	"math/rand"

	log "github.com/prometheus/log"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/julienschmidt/httprouter"
	"github.com/eknkc/amber"

	"github.com/wrouesnel/poller_exporter/config"
	"github.com/kardianos/osext"
	"github.com/wrouesnel/poller_exporter/pollers"
	"time"
)

var (
	Version = "0.0.0.dev"

	listenAddress     = flag.String("web.listen-address", ":9115", "Address on which to expose metrics and web interface.")
	metricsPath       = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")
	configFile		  = flag.String("collector.config", "poller_exporter.yml", "File to load poller config from")
	skipPing		  = flag.Bool("collector.icmp.disable", false, "Ignore ICMP ping checks of host status (useful if not running as root)")
)

// Debug-related parameters
var (
	 rootDir		  	  = ""	// DEVELOPMENT USE ONLY
)

// Compile amber templates out of assetfs
func MustCompile(filename string) (*template.Template) {
	amberTmpl, err := Asset(filename)
	if err != nil {
		panic(err)
	}
	return amber.MustCompile(string(amberTmpl), amber.Options{})
}

func main() {
	rand.Seed(time.Now().Unix())
	flag.Parse()

	// This is only used when we're running in -dev mode with bindata
	rootDir, _ = osext.ExecutableFolder()
	rootDir = path.Join(rootDir, "web")

	// Parse configuration
	cfg, err := config.LoadFromFile(*configFile)
	if err != nil {
		log.Fatalln("Error loading config", err)
	}

	// Templates
	amberTmpl, err := Asset("templates/index.amber")
	if err != nil {
		log.Fatalln("Could not load index template:", err)
	}
	tmpl := amber.MustCompile(string(amberTmpl), amber.Options{})

	// Setup the web UI
	router := httprouter.New()
	router.Handler("GET", *metricsPath, prometheus.Handler())	// Prometheus
	// Static asset handling
	router.GET("/static/*filepath", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		reqpath := ps.ByName("filepath")
		realpath := path.Join("static", reqpath)
		b, err := Asset(realpath)
		if err != nil {
			log.Debugln("Could not find asset: ", err)
			return
		} else {
			w.Write(b)
		}

	})

	var monitoredHosts []*pollers.Host

	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		data := struct{
			Cfg *config.Config
			Hosts *[]*pollers.Host
		}{
			Cfg : cfg,
			Hosts : &monitoredHosts,
		}
		err := tmpl.Execute(w, &data)
		if err != nil {
			log.Errorln("Error rendering template", err)
		}
	})

	// Initialize the host pollers
	monitoredHosts = make([]*pollers.Host, len(cfg.Hosts))
	for idx, hostCfg := range cfg.Hosts {
		log.Debugln("Setting up poller for: ", hostCfg.Hostname)
		if *skipPing {
			hostCfg.PingDisable = true
		}
		host := pollers.NewHost(hostCfg)
		monitoredHosts[idx] = host
		prometheus.MustRegister(host)
	}

	// Start the poller services
	for _, host := range monitoredHosts {
		host.StartPolling()
	}

	log.Infof("Listening on %s", *listenAddress)
    err = http.ListenAndServe(*listenAddress, router)
	if err != nil {
		log.Fatal(err)
	}
}

