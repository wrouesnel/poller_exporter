package pollers

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/wrouesnel/poller_exporter/config"
	"fmt"
	"math"
	"time"
	"net/http"
	"net"
	"net/url"
	"github.com/prometheus/log"
)

type HTTPService struct {
	requestDuration prometheus.Gauge
	responseSize prometheus.Gauge
	responseSuccess prometheus.Gauge

	lastStatus int					// last status code

	Poller
	config.HTTPServiceConfig
}

func NewHTTPService(host *Host, opts config.HTTPServiceConfig) Poller {
	clabels := prometheus.Labels{
		"hostname" : host.Hostname,
		"name" : opts.Name,
		"protocol" : opts.Protocol,
		"port" : fmt.Sprintf("%d", opts.Port),
	}

	basePoller := NewBasicService(host, opts.BasicServiceConfig)

	newService := HTTPService{
		requestDuration: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: "service",
			Name: "http_request_duration_microseconds",
			Help: "The HTTP request latencies in microseconds.",
			ConstLabels: clabels,
		}),
		responseSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: "service",
			Name: "http_response_size_bytes",
			Help: "The HTTP request sizes in bytes.",
			ConstLabels: clabels,
		}),
		responseSuccess: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: "service",
			Name: "http_response_success_bool",
			Help: "Was the last response in the allowed list?",
			ConstLabels: clabels,
		}),
	}

	newService.Poller = basePoller
	newService.HTTPServiceConfig = opts

	return Poller(&newService)
}

// Return true if the last polled status was one of the allowed statuses
func (this *HTTPService) Status() bool {
	// TODO: use a map?
	for _, status := range this.SuccessStatuses {
		if status == this.lastStatus {
			return true
		}
	}
	return false
}

func (this *HTTPService) Describe(ch chan <- *prometheus.Desc) {
	this.responseSuccess.Describe(ch)
	this.requestDuration.Describe(ch)
	this.responseSize.Describe(ch)

	this.Poller.Describe(ch)	// Call base describe
}

func (this *HTTPService) Collect( ch chan <- prometheus.Metric) {
	if this.Status() {
		this.responseSuccess.Set(1)
	} else {
		this.responseSuccess.Set(0)
	}

	this.responseSuccess.Collect(ch)

	this.requestDuration.Collect(ch)
	this.responseSize.Collect(ch)

	this.Poller.Collect(ch)
}

func (this *HTTPService) Poll() {
	requestStartTime := time.Now()	// Start timing how long the request takes

	conn := this.doPoll()
	if conn == nil {
		this.lastStatus = 0
		this.responseSize.Set(math.NaN())

		// Request end time is a number even if rejected.
		requestDuration := float64(time.Now().Sub(requestStartTime) * time.Microsecond)
		this.requestDuration.Set(requestDuration)
	}

	client := NewDeadlineClient(conn, time.Duration(this.Timeout))

	httpreq := &http.Request{
		Method:     this.Verb,
		URL:        this.Url,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       nil,
		Host:       this.Url.URL.Host,
	}

	resp, err := client.Do(httpreq)
	if err != nil {
		log.Infoln("Error making HTTP request to ", this.Host(), ": ", err)
	}

	// Get the status
	this.lastStatus = resp.StatusCode

	// Read the response up to max bytes and look for a match
}

// NewClient returns a http.Client using the specified http.RoundTripper.
func NewClient(rt http.RoundTripper) *http.Client {
	return &http.Client{Transport: rt}
}

// NewDeadlineConnClient returns a net.http client that inherits the supplied
// net.Conn. This can be a TLS client.
func NewDeadlineClient(conn net.Conn, timeout time.Duration) *http.Client {
	return NewClient(NewDeadlineRoundTripper(conn, timeout))
}

// Returns an http.Roundtripper which wraps the passed in net.Conn to reuse an
// established connection.
func NewDeadlineRoundTripper(conn net.Conn, timeout time.Duration) http.RoundTripper {
	return &http.Transport{
		// We need to disable keepalive, because we set a deadline on the
		// underlying connection.
		DisableKeepAlives: true,
		// Fake dial function returns the supplied net.Conn but sticks a deadline
		// on it.
		Dial: func(netw, addr string) (c net.Conn, err error) {
			start := time.Now()

			if err = conn.SetDeadline(start.Add(timeout)); err != nil {
				conn.Close()
				return nil, err
			}

			return conn, nil
		},
	}
}