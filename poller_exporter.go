// Prometheus remote-endpoint poller exporter.
// Implements asynchronous remote polling for network endpoints.

package main 

import (
    "flag"
	"net/http"
	"text/template"

	log "github.com/prometheus/log"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/julienschmidt/httprouter"
	"github.com/eknkc/amber"

	"github.com/wrouesnel/poller_exporter/config"
)

var (
	Version = "0.0.0.dev"
	
	listenAddress     = flag.String("web.listen-address", ":9551", "Address on which to expose metrics and web interface.")
	metricsPath       = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")
	configFile		  = flag.String("collector.config", "poller_exporter.yml", "File to load poller config from")
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
	// Parse configuration
	cfg, err := config.LoadFromFile(*configFile)
	if err != nil {
		log.Fatalln("Error loading config", err)
	}

	router := httprouter.New()
	router.Handler("GET", *metricsPath, prometheus.Handler())

	// Static assets
	router.GET("/static", assetFS())

	// Templates
	amberTmpl, err := Asset("templates/index.amber")
	tmpl := amber.MustCompile(string(amberTmpl), amber.Options{})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data := struct{
			Config string
		}{
			Config : cfg.OriginalConfig
		}
		tmpl.Execute(w, &data)
	})
	
    err = http.ListenAndServe(*listenAddress, router)
    log.Infof("Listening on %s", *listenAddress)
	if err != nil {
		log.Fatal(err)
	}
}

