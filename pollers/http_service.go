package pollers

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"github.com/wrouesnel/poller_exporter/config"
	"net/url"
	"math"
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

// Return true if the last polled status was one of the allowed statuses
func (this *HTTPService) Status() Status {
	// Check underlying connection succeeeded
	if this.Poller.Status() == FAILED || this.Poller.Status() == UNKNOWN {
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
		// Build a default URL from the hostname.
		url.Host = this.Host().Hostname
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

	startTime := time.Now()	// Start time from initial request
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

	// Check the response for anything
	if this.lastResponseStatus == -1 {
		this.serviceChallengeable = FAILED
		this.serviceChallengeTime = 0
	} else {
		this.serviceChallengeable = SUCCESS
		// Challenge size is NAN for HTTP at the moment
		this.serviceChallengeTime = time.Now().Sub(startTime)
	}

	// Check the HTTP response for validity
	if this.checkResponse() == SUCCESS {
		this.responseCount.WithLabelValues(LBL_SUCCESS).Inc()
	} else {
		this.responseCount.WithLabelValues(LBL_FAIL).Inc()
	}

	// Call the underlying ChallengeResponse to match on output if an output
	if this.isReader() {
		this.serviceResponsive, this.serviceResponseSize, this.serviceResponseTTB = this.ChallengeResponseService.TryReadMatch(resp.Body)
		this.serviceResponseTime = time.Now().Sub(startTime)
	} else {
		this.serviceResponsive = UNKNOWN
		this.serviceResponseSize = math.NaN()
		this.serviceResponseTime = 0
		this.serviceResponseTTB = 0
	}

	// Do cumulative counters
	if this.serviceChallengeable == SUCCESS {
		this.ServiceRequestCount.WithLabelValues(LBL_SUCCESS).Inc()
	} else {
		this.ServiceRequestCount.WithLabelValues(LBL_FAIL).Inc()
	}

	if this.serviceResponsive == SUCCESS {
		this.ServiceRespondedCount.WithLabelValues(LBL_SUCCESS).Inc()
	} else {
		this.ServiceRespondedCount.WithLabelValues(LBL_FAIL).Inc()
	}

	if this.serviceResponseTTB != 0 {
		this.ServiceResponseTimeToFirstByteCount.Add(float64(this.serviceResponseTTB / time.Second ))
	}

	log.Debugln("Finished http poll.")
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
