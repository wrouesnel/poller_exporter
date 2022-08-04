package pollers

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/wrouesnel/poller_exporter/pkg/config"

	"go.uber.org/zap"

	"math"
	"net/url"

	"github.com/prometheus/client_golang/prometheus"
)

// An HTTP service is a degenerate ChallengeResponse service which does specific
// status code checking and always reads all the bytes it's sent.
type HTTPService struct {
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

		ChallengeResponseService: *basePoller,
		HTTPServiceConfig:        opts,
	}

	return &newService
}

func (hs *HTTPService) checkResponse() Status {
	if _, ok := hs.SuccessStatuses[hs.lastResponseStatus]; ok {
		return PollStatusSuccess
	}
	if hs.lastResponseStatus == -1 {
		return PollStatusUnknown
	}
	// Anything that's not 0 is also allowed if not defined
	if len(hs.SuccessStatuses) == 0 && hs.lastResponseStatus != 0 {
		return PollStatusSuccess
	}

	return PollStatusFailed
}

// Return true if the last polled status was one of the allowed statuses.
func (hs *HTTPService) Status() Status {
	// Check underlying connection succeeeded
	if hs.Poller.Status() == PollStatusFailed || hs.Poller.Status() == PollStatusUnknown {
		return hs.Poller.Status()
	}
	return hs.checkResponse()
}

func (hs *HTTPService) Describe(ch chan<- *prometheus.Desc) {
	hs.responseSuccess.Describe(ch)

	hs.responseCount.Describe(ch)

	hs.Poller.Describe(ch) // Call base describe
}

func (hs *HTTPService) Collect(ch chan<- prometheus.Metric) {
	// HTTP status
	hs.responseSuccess.Set(float64(hs.Status()))
	hs.responseSuccess.Collect(ch)

	hs.responseCount.Collect(ch)

	// Parent status (challenge response metrics)
	hs.Poller.Collect(ch)
}

//nolint:funlen
func (hs *HTTPService) Poll() {
	conn := hs.doPoll()
	if conn == nil {
		hs.lastResponseStatus = 0
		return
	}
	defer conn.Close()

	client := NewHTTPClient(conn)

	var url url.URL
	if hs.URL.URL != nil {
		url = *hs.URL.URL
	} else {
		hs.log().Debug("Using default URL for HTTP poller")
		// Build a default URL from the hostname.
		url.Host = hs.Host().Hostname
		url.Scheme = "http"
	}

	hs.log().Debug("HTTP",
		zap.String("verb", hs.Verb),
		zap.String("hostname", hs.Host().Hostname),
		zap.Uint64("verb", hs.Port()),
		zap.String("uri", url.String()))

	httpreq := &http.Request{
		Method:     hs.Verb,
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
		hs.log().Info("Error making HTTP request host ", zap.String("hostname", hs.Host().Hostname), zap.Error(err))
		hs.lastResponseStatus = 0
		return
	}
	defer resp.Body.Close()

	// Get the status
	hs.lastResponseStatus = resp.StatusCode
	hs.log().Debug("HTTP response",
		zap.String("hostname", hs.Host().Hostname),
		zap.Uint64("hostname", hs.Port()),
		zap.Int("http_status_code", resp.StatusCode),
		zap.String("http_status", resp.Status))

	// Check the response for anything
	if hs.lastResponseStatus == -1 {
		hs.serviceChallengeable = PollStatusFailed
		hs.serviceChallengeTime = 0
	} else {
		hs.serviceChallengeable = PollStatusSuccess
		// Challenge size is NAN for HTTP at the moment
		hs.serviceChallengeTime = time.Since(startTime)
	}

	// Check the HTTP response for validity
	if hs.checkResponse() == PollStatusSuccess {
		hs.responseCount.WithLabelValues(MetricLabelSuccess).Inc()
	} else {
		hs.responseCount.WithLabelValues(MetricLabelFailed).Inc()
	}

	// Call the underlying ChallengeResponse to match on output if an output
	if hs.isReader() {
		hs.serviceResponsive, hs.serviceResponseSize, hs.serviceResponseTTB = hs.ChallengeResponseService.TryReadMatch(resp.Body)
		hs.serviceResponseTime = time.Since(startTime)
	} else {
		hs.serviceResponsive = PollStatusUnknown
		hs.serviceResponseSize = math.NaN()
		hs.serviceResponseTime = 0
		hs.serviceResponseTTB = 0
	}

	// Do cumulative counters
	if hs.serviceChallengeable == PollStatusSuccess {
		hs.ServiceRequestCount.WithLabelValues(MetricLabelSuccess).Inc()
	} else {
		hs.ServiceRequestCount.WithLabelValues(MetricLabelFailed).Inc()
	}

	if hs.serviceResponsive == PollStatusSuccess {
		hs.ServiceRespondedCount.WithLabelValues(MetricLabelSuccess).Inc()
	} else {
		hs.ServiceRespondedCount.WithLabelValues(MetricLabelFailed).Inc()
	}

	if hs.serviceResponseTTB != 0 {
		hs.ServiceResponseTimeToFirstByteCount.Add(float64(hs.serviceResponseTTB / time.Second))
	}

	hs.log().Debug("Finished http poll")
}

// NewHTTPClient returns an HTTP client which talks over the already established
// connection.
func NewHTTPClient(conn net.Conn) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			Dial: func(netw, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
	}
}
