package pollers

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/atomic"
	"shanhu.io/virgo/counting"

	"github.com/wrouesnel/poller_exporter/pkg/config"

	"go.uber.org/zap"

	"math"
	"net/url"

	"github.com/prometheus/client_golang/prometheus"
)

// HTTPService is a degenerate ChallengeResponse service which does specific
// status code checking and always reads all the bytes it's sent. However a
// challenge response poller is quite different to using the HTTP client library
// so an HTTPService only inherits challenge-response configuration, and a basic
// poller for connections - it does not actually a challenge-response service.
type HTTPService struct {
	ChallengeResponseMetricSet
	// Metrics
	responseReceived prometheus.Gauge       // Returns 1 if some type of HTTP response was received
	responseSuccess  prometheus.Gauge       // Returns 1 if the HTTP status code was successful
	responseCount    *prometheus.CounterVec // Cumulative count of success and failed responses
	redirectCount    prometheus.Gauge       // Number of redirects before receiving a response body

	serviceChallengeable     Status        // Service can be successfully challenged
	serviceChallengeSize     float64       // Number of bytes sent to the service
	serviceChallengeStart    time.Time     // Time the service challenge began
	serviceChallengeDuration time.Duration // Time service took to receive challenge

	serviceResponseTTB time.Duration // Duration from end-of-challenge to first byte of response

	serviceResponsive       Status        // Service responds when challenged
	serviceResponseSize     float64       // Number of bytes service responded with
	serviceResponseDuration time.Duration // Duration to receive total response (upto MaxBytes)

	lastResponseStatus int   // last status code
	lastRedirectCount  int64 // last redirect count

	config config.HTTPServiceConfig

	basePoller BasePoller // HTTP service *is not* a base poller but needs to be able to call it.
	Poller                // but it is a Poller
}

//nolint:funlen
func NewHTTPService(host *Host, opts config.HTTPServiceConfig) *HTTPService {
	if opts.Verb == "" {
		opts.Verb = "GET"
	}

	constantLabels := prometheus.Labels{
		"poller_type": PollyerTypeHTTP,
		"hostname":    host.Hostname,
		"name":        opts.Name,
		"protocol":    opts.Protocol,
		"port":        fmt.Sprintf("%d", opts.Port),
	}

	basePoller := NewBasicService(host, opts.BasicServiceConfig, constantLabels)

	newService := HTTPService{
		ChallengeResponseMetricSet: NewChallengeResponseMetricSet(constantLabels),

		responseReceived: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   Namespace,
			Subsystem:   "service",
			Name:        "http_response_rceived_bool",
			Help:        "Was an HTTP response received?",
			ConstLabels: constantLabels,
		}),

		responseSuccess: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   Namespace,
			Subsystem:   "service",
			Name:        "http_response_success_bool",
			Help:        "Was the HTTP response code successful",
			ConstLabels: constantLabels,
		}),

		responseCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "http_response_result_total",
				Help:        "Cumulative count of HTTP response checks",
				ConstLabels: constantLabels,
			},
			[]string{"result"},
		),

		redirectCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   Namespace,
			Subsystem:   "service",
			Name:        "http_redirects_count",
			Help:        "Number of redirects from the last request",
			ConstLabels: constantLabels,
		}),

		lastResponseStatus: -1,
		lastRedirectCount:  -1,

		config:     opts,
		basePoller: basePoller,
		Poller:     basePoller,
	}

	return &newService
}

func (hs *HTTPService) checkResponse() Status {
	if _, ok := hs.config.SuccessStatuses[hs.lastResponseStatus]; ok {
		return PollStatusSuccess
	}
	if hs.lastResponseStatus == -1 {
		return PollStatusUnknown
	}
	// Anything that's not 0 is also allowed if not defined
	if len(hs.config.SuccessStatuses) == 0 && hs.lastResponseStatus != 0 {
		return PollStatusSuccess
	}

	return PollStatusFailed
}

// Return true if the last polled status was one of the allowed statuses.
func (hs *HTTPService) Status() Status {
	// Check underlying connection succeeeded
	if hs.basePoller.Status() == PollStatusFailed || hs.basePoller.Status() == PollStatusUnknown {
		return hs.basePoller.Status()
	}
	return hs.checkResponse()
}

func (hs *HTTPService) Describe(ch chan<- *prometheus.Desc) {
	hs.responseSuccess.Describe(ch)
	hs.responseCount.Describe(ch)
	hs.redirectCount.Describe(ch)

	// Collect the challenge response metrics
	hs.ChallengeResponseMetricSet.Describe(ch)

	hs.basePoller.Describe(ch) // Call base describe
}

func (hs *HTTPService) Collect(ch chan<- prometheus.Metric) {
	// Check if we got *any* response
	if hs.lastResponseStatus > 0 {
		hs.responseReceived.Set(1)
	}
	// Check if the response was a success code
	hs.responseSuccess.Set(float64(hs.Status()))
	// Set the redirect count
	hs.redirectCount.Set(float64(hs.lastRedirectCount))

	// Request Start
	hs.ServiceChallengeStartTimeStamp.Set(float64(hs.serviceChallengeStart.Unix()))

	// Request metrics
	hs.ServiceRequestSuccessful.Set(float64(hs.serviceChallengeable))
	hs.ServiceRequestSize.Set(hs.serviceChallengeSize)
	if hs.serviceChallengeDuration != 0 { // Nothing should take 0 nanoseconds
		hs.ServiceChallengeTime.Set(float64(hs.serviceChallengeDuration / time.Microsecond))
	} else {
		hs.ServiceChallengeTime.Set(math.NaN())
	}

	// Response
	if hs.serviceResponseTTB != 0 { // Nothing should take 0 nanoseconds
		hs.ServiceResponseTimeToFirstByte.Set(float64(hs.serviceResponseTTB / time.Microsecond))
	} else {
		hs.ServiceResponseTimeToFirstByte.Set(math.NaN())
	}

	// Counters
	hs.ServiceRespondedSuccessfully.Set(float64(hs.serviceResponsive))
	hs.ServiceResponseSize.Set(hs.serviceResponseSize)
	if hs.serviceResponseDuration != 0 { // Nothing should take 0 nanoseconds
		hs.ServiceResponseDuration.Set(float64(hs.serviceResponseDuration / time.Microsecond))
	} else {
		hs.ServiceResponseDuration.Set(math.NaN())
	}

	hs.responseSuccess.Collect(ch)
	hs.responseCount.Collect(ch)
	hs.redirectCount.Collect(ch)

	// Collect the challenge response metrics
	hs.ChallengeResponseMetricSet.Collect(ch)

	// Parent status (challenge response metrics)
	hs.basePoller.Collect(ch)
}

// isReader Returns true if challenger is setup to read responses.
func (hs *HTTPService) isReader() bool {
	return (hs.config.ResponseRegex != nil || hs.config.ResponseBinary != nil || hs.config.ResponseLiteral != nil)
}

// isWriter returns true if the challenger is setup to write requests.
func (hs *HTTPService) isWriter() bool {
	return (hs.config.ChallengeString != nil || hs.config.ChallengeBinary != nil)
}

//nolint:funlen,cyclop
func (hs *HTTPService) Poll() {
	l := hs.log().With(zap.String("verb", hs.config.Verb.String()),
		zap.String("hostname", hs.Host().Hostname),
		zap.Uint64("verb", hs.Port()),
	)

	l.Debug("Getting network connection from base poller")
	conn := hs.basePoller.doPoll()
	if conn == nil {
		// If no connection after poll, set metrics to fail statuses and exit.
		if conn == nil {
			hs.serviceChallengeable = PollStatusUnknown
			hs.serviceChallengeSize = math.NaN()
			hs.serviceChallengeDuration = 0
			hs.serviceResponsive = PollStatusUnknown
			hs.serviceResponseSize = math.NaN()
			hs.serviceResponseDuration = 0
			return
		}
	}
	defer func() {
		if err := conn.Close(); err != nil {
			// This happens normally, ignore it.
			if !errors.Is(err, net.ErrClosed) {
				l.Info("Error closing connection", zap.String("error", err.Error()))
			}
		}
	}()

	// HTTP is hard to trace - use the counting conn so we can get request size.
	connCounters := counting.NewConnCounters()
	countingConn := &PollConnection{
		Conn:     counting.NewConn(conn, connCounters),
		dialer:   conn.dialer,
		deadline: conn.deadline,
		ctx:      conn.ctx,
	}

	l.Debug("Creating new HTTP client for request")
	client, redirectCount := NewHTTPClient(countingConn, hs.config.EnableRedirects, hs.config.HTTPMaxRedirects)

	// Get the URL
	var url url.URL
	if hs.config.URL.URL != nil {
		url = *hs.config.URL.URL
		// This is deliberate - the Go library will "helpfully" re-establish
		// the connection if TLS wasn't already on the connection - which we don't want.
		url.Scheme = "http"
	} else {
		l.Debug("Using default URL for HTTP poller")
		// Build a default URL from the hostname.
		url.Host = hs.Host().Hostname
		url.Scheme = "http"
	}

	l = l.With(zap.String("uri", url.String()))

	// Get the challenge
	var bodyWriter io.ReadCloser
	bodyWriter = nil
	if hs.isWriter() {
		var challenge []byte
		switch {
		case hs.config.ChallengeBinary != nil:
			challenge = hs.config.ChallengeBinary
		case hs.config.ChallengeString != nil:
			challenge = []byte(*hs.config.ChallengeString)
		default:
			// this normally shouldn't happen, but this function cannot return an
			// error so we must send something.
			challenge = []byte("")
		}
		bodyWriter = io.NopCloser(bytes.NewBuffer(challenge))
	}

	// Get the headers
	headers := make(http.Header)
	for _, headerMap := range hs.config.Headers {
		for name, value := range headerMap {
			headers.Add(name, value)
		}
	}

	// Construct the request
	httpRequest := &http.Request{
		Method: hs.config.Verb.String(),
		URL:    &url,
		Header: headers,
		Body:   bodyWriter,
		Host:   url.Host,
	}

	if authCfg := hs.config.RequestAuth.BasicAuth; authCfg != nil {
		l.Debug("Request configured with BasicAuth")
		httpRequest.SetBasicAuth(authCfg.Username, authCfg.Password)
	}

	hs.serviceChallengeStart = time.Now() // Start time from initial request
	l.Debug("Executing HTTP request")
	resp, err := client.Do(httpRequest)
	hs.serviceChallengeSize = float64(connCounters.Write.Count())
	hs.serviceChallengeDuration = time.Since(hs.serviceChallengeStart)
	if err != nil {
		l.Info("Error making HTTP request to host ", zap.String("hostname", hs.Host().Hostname), zap.Error(err))
		hs.lastResponseStatus = 0
		hs.lastRedirectCount = 0
		// Challenge size on error is considered obtained here
		hs.serviceChallengeable = PollStatusFailed

		hs.serviceResponsive = PollStatusFailed
		hs.serviceResponseDuration = 0
		hs.serviceResponseSize = 0
		hs.serviceResponseTTB = 0
		return
	}

	defer resp.Body.Close()
	l.Debug("HTTP response",
		zap.String("hostname", hs.Host().Hostname),
		zap.Uint64("hostname", hs.Port()),
		zap.Int("http_status_code", resp.StatusCode),
		zap.String("http_status", resp.Status))
	// Service responded - set status code
	hs.lastResponseStatus = resp.StatusCode
	// Get the redirect count after the request
	hs.lastRedirectCount = redirectCount.Load()

	// If response status is -1 then service didn't respond with HTTP == not challengeable
	if hs.lastResponseStatus == -1 {
		hs.serviceChallengeable = PollStatusFailed

		// We haven't actually matched anything from the part we query, so responsive == unknown
		hs.serviceResponsive = PollStatusUnknown
		hs.serviceResponseDuration = 0
		hs.serviceResponseSize = 0
		hs.serviceResponseTTB = 0
	} else {
		hs.serviceChallengeable = PollStatusSuccess
		hs.serviceChallengeDuration = time.Since(hs.serviceChallengeStart)
	}

	// Determine success code
	httpResponseStatus := hs.checkResponse()

	// Handle counters
	if httpResponseStatus == PollStatusSuccess {
		hs.responseCount.WithLabelValues(MetricLabelSuccess).Inc()
	} else {
		hs.responseCount.WithLabelValues(MetricLabelFailed).Inc()
	}

	// Do response body matching
	if hs.isReader() {
		hs.serviceResponsive, hs.serviceResponseSize, hs.serviceResponseTTB = TryReadMatch(resp.Body, &hs.config.ChallengeResponseConfig)
		hs.serviceResponseDuration = time.Since(hs.serviceChallengeStart)
	} else {
		// If we're not a reader, then responsiveNess is unknown again.
		hs.serviceResponsive = PollStatusUnknown
		hs.serviceResponseSize = math.NaN()
		hs.serviceResponseDuration = 0
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

	l.Debug("Finished HTTP poll")
}

var ErrTooManyRedirects = errors.New("Too many redirects")

// NewHTTPClient returns an HTTP client which talks over the already established
// connection.
func NewHTTPClient(conn *PollConnection, enableRedirects bool, maxRedirects int64) (*http.Client, *atomic.Int64) {
	redirectCount := atomic.NewInt64(0)
	connectionUsed := atomic.NewBool(false)
	clientDialer := conn.Dialer()
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 1 {
				// Reset redirect count
				redirectCount.Store(0)
			}
			// Increment the redirect count
			redirectCount.Add(1)
			if !enableRedirects {
				// But then terminate the loop
				return http.ErrUseLastResponse
			}
			// Redirects allowed, let's continue
			redirectsCount := redirectCount.Load()
			if redirectsCount > maxRedirects {
				return errors.Wrapf(ErrTooManyRedirects, "Stopped after %v redirects", redirectsCount)
			}
			return nil
		},
		Transport: &http.Transport{
			DisableKeepAlives: true,
			MaxConnsPerHost:   1,
			DialContext: func(ctx context.Context, netw, addr string) (net.Conn, error) {
				if connectionUsed.Load() {
					// If the connection was already used then the HTTP client will close it.
					// Our contract with the user is if they want redirects they want to see
					// if the HTTP winds up somewhere sensible - but for that we need to
					// allow connections to other locations while still respecting the
					// deadline on the poll as it was originally established.
					// PollConnection implements net.Conn but carries a deadline through
					// for us to dial new connections with.
					newConn, err := clientDialer.DialContext(ctx, netw, addr)
					if newConn != nil {
						if derr := newConn.SetDeadline(conn.deadline); derr != nil {
							zap.L().Error("Error setting deadling on new connction for HTTP transport", zap.Error(err))
						}
					}
					return newConn, err //nolint:wrapcheck
				}
				connectionUsed.Store(true)
				return conn, nil
			},
		},
	}, redirectCount
}
