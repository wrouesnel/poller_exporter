// Prometheus remote-endpoint poller exporter.
// Implements asynchronous remote polling for network endpoints.

package main 

import (
    "flag"
	"net/http"
	"text/template"

	log "github.com/prometheus/log"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/elazarl/go-bindata-assetfs"
	"github.com/eknkc/amber"
)

var (
	Version = "0.0.0.dev"
	
	listenAddress     = flag.String("web.listen-address", ":9551", "Address on which to expose metrics and web interface.")
	metricsPath       = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")
	configFile		  = flag.String("collector.config", "poller_exporter.yml", "File to load poller config from")
)

func main() {
	handler := prometheus.Handler()
    http.Handle(*metricsPath, handler)
	http.Handle("/static", &assetfs.AssetFS{Asset: Asset, AssetDir: AssetDir, Prefix: "web"})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		
	})
	
    err := http.ListenAndServe(*listenAddress, nil)
    log.Infof("Listening on %s", *listenAddress)
	if err != nil {
		log.Fatal(err)
	}
}

