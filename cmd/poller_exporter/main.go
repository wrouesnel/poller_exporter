// Prometheus remote-endpoint poller exporter.
// Implements asynchronous remote polling for network endpoints.

package main

import (
	"context"
	"html/template"
	"io/fs"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/wrouesnel/poller_exporter/pkg/errutils"

	"github.com/wrouesnel/poller_exporter/pkg/config"

	"github.com/alecthomas/kong"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap/zapcore"

	"github.com/eknkc/amber"
	"github.com/julienschmidt/httprouter"
	"github.com/prometheus/client_golang/prometheus"

	"time"

	"github.com/goji/httpauth"
	"github.com/wrouesnel/poller_exporter/assets"
	"github.com/wrouesnel/poller_exporter/pkg/pollers"
	"go.uber.org/zap"
)

var version = "0.0.0"

//nolint:gochecknoglobals
var CLI struct {
	Version   kong.VersionFlag `help:"Show version number"`
	LogLevel  string           `help:"Logging Level" enum:"debug,info,warning,error" default:"info"`
	LogFormat string           `help:"Logging format" enum:"console,json" default:"console"`

	Web struct {
		TelemetryPath     string        `help:"Path under which to expose metrics" default:"/metrics"`
		ListenAddress     string        `help:"Address on which to expose metrics and web interface" default:":9115"`
		ReadHeaderTimeout time.Duration `help:"Timeout for header read to the server" default:"1s"`
	} `embed:"" prefix:"web."`

	Collector struct {
		Config string `help:"File to load poller config from" default:"poller_exporter.yml"`
		Icmp   struct {
			Disable bool `help:"Ignore ICMP pings checks of host status (useful if not running as root/CAP_SYS_ADMIN)"`
		} `embed:"" prefix:"icmp"`
		MaxConnections int `help:"Maximum number of hosts to poll simultaneously (-1 for no limit)" default:"50"`
	} `embed:"" prefix:"collector."`
}

// MustCompile compiles the templates out of embed.FS.
func MustCompile(filename string) *template.Template {
	amberTmpl, err := assets.Assets.ReadFile(strings.Join([]string{"web", filename}, "/"))
	if err != nil {
		panic(err)
	}
	return amber.MustCompile(string(amberTmpl), amber.Options{
		PrettyPrint:       true,
		LineNumbers:       false,
		VirtualFilesystem: nil,
	})
}

//nolint:funlen,cyclop
func main() {
	vars := kong.Vars{}
	vars["version"] = version
	kongParser, err := kong.New(&CLI, vars)
	if err != nil {
		panic(err)
	}

	_, err = kongParser.Parse(os.Args[1:])
	kongParser.FatalIfErrorf(err)

	// Configure logging
	logConfig := zap.NewProductionConfig()
	logConfig.Encoding = CLI.LogFormat
	var logLevel zapcore.Level
	if err := logLevel.UnmarshalText([]byte(CLI.LogLevel)); err != nil {
		panic(err)
	}
	logConfig.Level = zap.NewAtomicLevelAt(logLevel)

	log, err := logConfig.Build()
	if err != nil {
		panic(err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	ctx, cancelFn := context.WithCancel(context.Background())
	go func() {
		sig := <-sigCh
		log.Info("Caught signal - exiting", zap.String("signal", sig.String()))
		cancelFn()
	}()

	appLog := log.With(zap.String("config_file", CLI.Collector.Config))

	appLog.Debug("Initialize random number generator (used to randomize check frequency)")
	rand.Seed(time.Now().Unix())

	log.Info("Parsing configuration")
	cfg, err := config.LoadFromFile(CLI.Collector.Config)
	if err != nil {
		log.Fatal("Error loading config", zap.Error(err))
	}

	appLog.Debug("Compiling index template")
	tmpl := MustCompile("templates/index.amber")

	appLog.Debug("Setup web UI")
	router := httprouter.New()
	router.Handler("GET", CLI.Web.TelemetryPath,
		promhttp.HandlerFor(
			prometheus.DefaultGatherer,
			promhttp.HandlerOpts{
				// Opt into OpenMetrics to support exemplars.
				EnableOpenMetrics: true,
			},
		)) // Prometheus
	// Static asset handling

	router.Handler("GET", "/static/*filepath", http.FileServer(http.FS(errutils.Must[fs.FS](fs.Sub(assets.Assets, "web")))))

	monitoredHosts := make([]*pollers.Host, 0, len(cfg.Hosts))
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		data := struct {
			Cfg   *config.Config
			Hosts *[]*pollers.Host
		}{
			Cfg:   cfg,
			Hosts: &monitoredHosts,
		}
		err := tmpl.Execute(w, &data)
		if err != nil {
			log.Error("Error rendering template", zap.Error(err))
		}
	})

	appLog.Info("Initialize the host pollers")

	// We don't allow duplicate hosts, but also don't want to panic just due
	// to a typo, so keep track and skip duplicates here.
	seenHosts := make(map[string]bool)

	realIdx := 0
	for _, hostCfg := range cfg.Hosts {
		hostLog := log.With(zap.String("hostname", hostCfg.Hostname))
		hostLog.Debug("Setting up poller for hostname")
		if CLI.Collector.Icmp.Disable {
			hostCfg.PingDisable = true
		}
		if _, ok := seenHosts[hostCfg.Hostname]; ok {
			hostLog.Warn("Discarding repeat configuration of same hostname")
			continue
		}
		host := pollers.NewHost(hostCfg)
		monitoredHosts = append(monitoredHosts, host)
		prometheus.MustRegister(host)

		seenHosts[hostCfg.Hostname] = true
		realIdx++
	}

	// This is the dispatcher. It is responsible for invoking the doPoll method
	// of hosts.
	connectionLimiter := pollers.NewLimiter(CLI.Collector.MaxConnections)
	hostQueue := make(chan *pollers.Host)

	appLog.Info("Starting host dispatcher")
	go func() {
		for host := range hostQueue {
			go host.Poll(connectionLimiter, hostQueue)
		}
	}()

	appLog.Info("Doing initial host dispatch")
	go func() {
		for _, host := range monitoredHosts {
			log.Debug("Starting polling for hosts")
			hostQueue <- host
		}
	}()

	var handler http.Handler
	// If basic auth is requested, enable it for the interface.
	if cfg.BasicAuthUsername != "" && cfg.BasicAuthPassword != "" {
		appLog.Info("Enabling basic auth")
		basicauth := httpauth.SimpleBasicAuth(cfg.BasicAuthUsername,
			cfg.BasicAuthPassword)
		handler = basicauth(router)
	} else {
		handler = router
	}

	srv := &http.Server{Addr: CLI.Web.ListenAddress, Handler: handler, ReadHeaderTimeout: CLI.Web.ReadHeaderTimeout}
	webCtx, webCancel := context.WithCancel(ctx)

	go func() {
		// If TLS certificates are specified, use TLS
		if cfg.TLSCertificatePath != "" && cfg.TLSKeyPath != "" {
			appLog.Info("Listening on (TLS-enabled) interface", zap.String("listen_address", CLI.Web.ListenAddress))
			err = srv.ListenAndServeTLS(cfg.TLSCertificatePath, cfg.TLSKeyPath)
		} else {
			appLog.Info("Listening on unsecured interface", zap.String("listen_address", CLI.Web.ListenAddress))
			err = srv.ListenAndServe()
		}
		if err != nil {
			appLog.Error("Exiting with error from HTTP server")
		}
		webCancel()
	}()
	<-webCtx.Done()

	appLog.Info("Exiting normally")
}
