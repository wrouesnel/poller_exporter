package pollers

import (
	"fmt"
	"go.uber.org/zap"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/wrouesnel/poller_exporter/config"
	"math"
	"net/url"
)

// An HTTP service is a degenerate ChallengeResponse service which does specific
// status code checking and always reads all the bytes it's sent.
type HTTPService struct {
	successMap map[int]bool // Map of success code

	// Metrics
	responseSuccess prometheus.Gauge       // Returns 1 if the HTTP status code was successful
	responseCount   *prometheus.CounterVec // Cumulative count of success and failed responses

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
		lastResponseStatus: -1,

		responseSuccess: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   Namespace,
			Subsystem:   "service",
			Name:        "http_response_success_bool",
			Help:        "Was the HTTP response code successful",
			ConstLabels: clabels,
		}),

		responseCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "http_response_result_total",
				Help:        "Cumulative count of HTTP response checks",
				ConstLabels: clabels,
			},
			[]string{"result"},
		),
	}

	newService.ChallengeResponseService = *basePoller
	newService.HTTPServiceConfig = opts

	return &newService
}

func (this *HTTPService) checkResponse() Status {
	if _, ok := this.SuccessStatuses[this.lastResponseStatus]; ok {
		return PollStatusSuccess
	}
	if this.lastResponseStatus == -1 {
		return PollStatusUnknown
	}
	// Anything that's not 0 is also allowed if not defined
	if len(this.SuccessStatuses) == 0 && this.lastResponseStatus != 0 {
		return PollStatusSuccess
	}

	return PollStatusFailed
}

// Return true if the last polled status was one of the allowed statuses
func (this *HTTPService) Status() Status {
	// Check underlying connection succeeeded
	if this.Poller.Status() == PollStatusFailed || this.Poller.Status() == PollStatusUnknown {
		return this.Poller.Status()
	}
	return this.checkResponse()
}

func (this *HTTPService) Describe(ch chan<- *prometheus.Desc) {
	this.responseSuccess.Describe(ch)

	this.responseCount.Describe(ch)

	this.Poller.Describe(ch) // Call base describe
}

func (this *HTTPService) Collect(ch chan<- prometheus.Metric) {
	// HTTP status
	this.responseSuccess.Set(float64(this.Status()))
	this.responseSuccess.Collect(ch)

	this.responseCount.Collect(ch)

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

	client := NewHTTPClient(conn)

	var url url.URL
	if this.Url.URL != nil {
		url = *this.Url.URL
	} else {
		this.log().Debug("Using default URL for HTTP poller")
		// Build a default URL from the hostname.
		url.Host = this.Host().Hostname
		url.Scheme = "http"
	}

	this.log().Debug("HTTP",
		zap.String("verb", this.Verb),
		zap.String("hostname", this.Host().Hostname),
		zap.Uint64("verb", this.Port()),
		zap.String("uri", url.String()))

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

	startTime := time.Now() // Start time from initial request
	resp, err := client.Do(httpreq)
	if err != nil {
		this.log().Info("Error making HTTP request host ", zap.String("hostname", this.Host().Hostname), zap.Error(err))
		this.lastResponseStatus = 0
		return
	}
	defer resp.Body.Close()

	// Get the status
	this.lastResponseStatus = resp.StatusCode
	this.log().Debug("HTTP response",
		zap.String("hostname", this.Host().Hostname),
		zap.Uint64("hostname", this.Port()),
		zap.Int("http_status_code", resp.StatusCode),
		zap.String("http_status", resp.Status))

	// Check the response for anything
	if this.lastResponseStatus == -1 {
		this.serviceChallengeable = PollStatusFailed
		this.serviceChallengeTime = 0
	} else {
		this.serviceChallengeable = PollStatusSuccess
		// Challenge size is NAN for HTTP at the moment
		this.serviceChallengeTime = time.Now().Sub(startTime)
	}

	// Check the HTTP response for validity
	if this.checkResponse() == PollStatusSuccess {
		this.responseCount.WithLabelValues(MetricLabelSuccess).Inc()
	} else {
		this.responseCount.WithLabelValues(MetricLabelFailed).Inc()
	}

	// Call the underlying ChallengeResponse to match on output if an output
	if this.isReader() {
		this.serviceResponsive, this.serviceResponseSize, this.serviceResponseTTB = this.ChallengeResponseService.TryReadMatch(resp.Body)
		this.serviceResponseTime = time.Now().Sub(startTime)
	} else {
		this.serviceResponsive = PollStatusUnknown
		this.serviceResponseSize = math.NaN()
		this.serviceResponseTime = 0
		this.serviceResponseTTB = 0
	}

	// Do cumulative counters
	if this.serviceChallengeable == PollStatusSuccess {
		this.ServiceRequestCount.WithLabelValues(MetricLabelSuccess).Inc()
	} else {
		this.ServiceRequestCount.WithLabelValues(MetricLabelFailed).Inc()
	}

	if this.serviceResponsive == PollStatusSuccess {
		this.ServiceRespondedCount.WithLabelValues(MetricLabelSuccess).Inc()
	} else {
		this.ServiceRespondedCount.WithLabelValues(MetricLabelFailed).Inc()
	}

	if this.serviceResponseTTB != 0 {
		this.ServiceResponseTimeToFirstByteCount.Add(float64(this.serviceResponseTTB / time.Second))
	}

	this.log().Debug("Finished http poll")
}

// NewHTTPClient returns an HTTP client which talks over the already established
// connection
func NewHTTPClient(conn net.Conn) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			Dial: func(netw, addr string) (c net.Conn, err error) {
				return conn, nil
			},
		},
	}
}
