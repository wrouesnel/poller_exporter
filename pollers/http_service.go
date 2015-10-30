package pollers

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/log"
	"github.com/wrouesnel/poller_exporter/config"
	"net/url"
)

// An HTTP service is a degenerate ChallengeResponse service which does specific
// status code checking and always reads all the bytes it's sent.
type HTTPService struct {
	successMap map[int]bool	// Map of success code

	// Metrics
	responseSuccess prometheus.Gauge	// Returns 1 if the HTTP status code was successful
	responseCount *prometheus.CounterVec // Cumulative count of success and failed responses

	lastResponseStatus int // last status code

	ChallengeResponseService
	config.HTTPServiceConfig
}

func NewHTTPService(host *Host, opts config.HTTPServiceConfig) *HTTPService {
	clabels := prometheus.Labels{
		"hostname": host.Hostname,
		"name":     opts.Name,
		"protocol": opts.Protocol,
		"port":     fmt.Sprintf("%d", opts.Port),
	}

	basePoller := NewChallengeResponseService(host, opts.ChallengeResponseConfig)

	newService := HTTPService{
		lastResponseStatus : -1,

		responseSuccess: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   Namespace,
			Subsystem:   "service",
			Name:        "http_response_success_bool",
			Help:        "Was the HTTP response code successful",
			ConstLabels: clabels,
		}),
	}

	newService.ChallengeResponseService = *basePoller
	newService.HTTPServiceConfig = opts

	return &newService
}

// Return true if the last polled status was one of the allowed statuses
func (this *HTTPService) Status() Status {
	// Check underlying connection succeeeded
	if this.Poller.Status() == FAILED || this.Poller.Status() == UNKNOWN {
		return this.Poller.Status()
	}

	if _, ok := this.SuccessStatuses[this.lastResponseStatus]; ok {
		return SUCCESS
	}
	if this.lastResponseStatus == -1 {
		return UNKNOWN
	}
	// Anything that's not 0 is also allowed if not defined
	if len(this.SuccessStatuses) == 0 && this.lastResponseStatus != 0 {
		return SUCCESS
	}

	return FAILED
}

func (this *HTTPService) Describe(ch chan<- *prometheus.Desc) {
	this.responseSuccess.Describe(ch)

	this.Poller.Describe(ch) // Call base describe
}

func (this *HTTPService) Collect(ch chan<- prometheus.Metric) {
	// HTTP status
	this.responseSuccess.Set(float64(this.Status()))
	this.responseSuccess.Collect(ch)

	// Parent status (challenge response metrics)
	this.Poller.Collect(ch)
}

func (this *HTTPService) Poll() {
	conn := this.doPoll()
	if conn == nil {
		this.lastResponseStatus = 0
		return
	}
	defer conn.Close()

	client := NewDeadlineClient(conn, time.Duration(this.ChallengeResponseService.Timeout))

	var url url.URL
	if this.Url.URL != nil {
		url = *this.Url.URL
	} else {
		// Build a default URL from the hostname.
		url.Host = this.Host().Hostname
		//if this.HTTPServiceConfig.UseSSL {
		//	url.Scheme = "https"
		//} else {
		//	url.Scheme = "http"
		//}
		url.Scheme = "http"
	}

	log.Debugln("HTTP", this.Verb, this.Host().Hostname, this.Port(), "for", url.String())

	httpreq := &http.Request{
		Method:     this.Verb,
		URL:        &url,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       nil,
		Host:       url.Host,
	}

	resp, err := client.Do(httpreq)
	if err != nil {
		log.Infoln("Error making HTTP request to ", this.Host(), ": ", err)
		this.lastResponseStatus = 0
		return
	}
	defer resp.Body.Close()

	// Get the status
	this.lastResponseStatus = resp.StatusCode
	log.Debugln("HTTP response", this.Host().Hostname, this.Port(), resp.StatusCode, resp.Status)

	// Call the underlying ChallengeResponse to match on output if an output
	// matcher is specified
	if this.isReader() {
		this.ChallengeResponseService.TryReadMatch(resp.Body)
	}

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
