package pollers

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"net"
	"time"

	"github.com/wrouesnel/poller_exporter/pkg/cachedconstants"

	"github.com/wrouesnel/poller_exporter/pkg/config"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

// ChallengeResponseMetricSet implements the actual challenge-response metrics.
type ChallengeResponseMetricSet struct {
	ServiceRequestSuccessful       prometheus.Gauge // Indicates if the service could be successfully sent data
	ServiceRequestSize             prometheus.Gauge // Number of bytes sent to the service
	ServiceChallengeStartTimeStamp prometheus.Gauge // Timestamp when the most recent service challenge started
	ServiceChallengeTime           prometheus.Gauge // Time it took to send the challenge

	ServiceResponseTimeToFirstByte prometheus.Gauge // Time it took the service to send anything

	ServiceRespondedSuccessfully prometheus.Gauge // Indicates if the service responded with expected data
	ServiceResponseSize          prometheus.Gauge // Number of bytes read before response match
	ServiceResponseDuration      prometheus.Gauge // Time in microseconds to read the response bytes

	ServiceRequestCount                 *prometheus.CounterVec // Cumulative count of service requests
	ServiceRespondedCount               *prometheus.CounterVec // Cumulative count of service responses
	ServiceResponseTimeToFirstByteCount prometheus.Counter     // Cumulative count of service responses
}

func (crms *ChallengeResponseMetricSet) Describe(ch chan<- *prometheus.Desc) {
	crms.ServiceRequestSuccessful.Describe(ch)
	crms.ServiceRequestSize.Describe(ch)
	crms.ServiceChallengeStartTimeStamp.Describe(ch)
	crms.ServiceChallengeTime.Describe(ch)
	crms.ServiceResponseTimeToFirstByte.Describe(ch)
	crms.ServiceRespondedSuccessfully.Describe(ch)
	crms.ServiceResponseSize.Describe(ch)
	crms.ServiceResponseDuration.Describe(ch)
	crms.ServiceRequestCount.Describe(ch)
	crms.ServiceRespondedCount.Describe(ch)
	crms.ServiceResponseTimeToFirstByteCount.Describe(ch)
}
func (crms *ChallengeResponseMetricSet) Collect(ch chan<- prometheus.Metric) {
	crms.ServiceRequestSuccessful.Collect(ch)
	crms.ServiceRequestSize.Collect(ch)
	crms.ServiceChallengeStartTimeStamp.Collect(ch)
	crms.ServiceChallengeTime.Collect(ch)
	crms.ServiceResponseTimeToFirstByte.Collect(ch)
	crms.ServiceRespondedSuccessfully.Collect(ch)
	crms.ServiceResponseSize.Collect(ch)
	crms.ServiceResponseDuration.Collect(ch)
	crms.ServiceRequestCount.Collect(ch)
	crms.ServiceRespondedCount.Collect(ch)
	crms.ServiceResponseTimeToFirstByteCount.Collect(ch)
}

// NewChallengeResponseMetricSet initializes a new set of metrics with the given constant labels.
//
//nolint:funlen
func NewChallengeResponseMetricSet(constantLabels prometheus.Labels) ChallengeResponseMetricSet {
	metricSet := ChallengeResponseMetricSet{
		ServiceRequestSuccessful: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "writeable_boolean",
				Help:        "true (1) if the service could be sent data, 0 for failed, NaN for unknown",
				ConstLabels: constantLabels,
			},
		),
		ServiceRequestSize: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "request_size_bytes",
				Help:        "Number of bytes sent to the service",
				ConstLabels: constantLabels,
			},
		),
		ServiceChallengeStartTimeStamp: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "request_timestamp_seconds",
				Help:        "Timestamp when the service challenge was initiated",
				ConstLabels: constantLabels,
			},
		),
		ServiceChallengeTime: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "request_time_microseconds",
				Help:        "Time it took to send the request to the service",
				ConstLabels: constantLabels,
			},
		),
		ServiceResponseTimeToFirstByte: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "response_time_to_first_byte_microseconds",
				Help:        "Time it took for the first response byte to arrive",
				ConstLabels: constantLabels,
			},
		),
		ServiceRespondedSuccessfully: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "response_success_boolean",
				Help:        "true (1) if the target port responded with expected data, 0 for failed, NaN for unknown",
				ConstLabels: constantLabels,
			},
		),
		ServiceResponseSize: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "response_size_bytes",
				Help:        "Number of bytes the service responded with before request was satisified",
				ConstLabels: constantLabels,
			},
		),
		ServiceResponseDuration: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "response_time_microseconds",
				Help:        "Time the response took to be received in microseconds.",
				ConstLabels: constantLabels,
			},
		),
		ServiceRequestCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "writeable_total",
				Help:        "cumulative count of service request success and failures",
				ConstLabels: constantLabels,
			},
			[]string{"result"},
		),
		ServiceRespondedCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "response_total",
				Help:        "cumulative count of service response successes and failures",
				ConstLabels: constantLabels,
			},
			[]string{"result"},
		),
		ServiceResponseTimeToFirstByteCount: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "request_time_to_first_byte_seconds_total",
				Help:        "cumulative count of time the service has taken to send its first byte",
				ConstLabels: constantLabels,
			},
		),
	}
	return metricSet
}

// ChallengeResponseService implements a bare challenge-response service.
type ChallengeResponseService struct {
	ChallengeResponseMetricSet

	serviceChallengeable     Status        // Service can be successfully challenged
	serviceChallengeSize     float64       // Number of bytes sent to the service
	serviceChallengeStart    time.Time     // Time the service challenge began
	serviceChallengeDuration time.Duration // Time service took to receive challenge

	serviceResponseTTB time.Duration // Duration from end-of-challenge to first byte of response

	serviceResponsive       Status        // Service responds when challenged
	serviceResponseSize     float64       // Number of bytes service responded with
	serviceResponseDuration time.Duration // Duration to receive total response (upto MaxBytes)

	config config.ChallengeResponseConfig
	BasePoller
}

func NewChallengeResponseService(host *Host, opts config.ChallengeResponseConfig) *ChallengeResponseService {
	constantLabels := prometheus.Labels{
		"poller_type": PollerTypeChallengeResponse,
		"hostname":    host.Hostname,
		"name":        opts.Name,
		"protocol":    opts.Protocol,
		"port":        fmt.Sprintf("%d", opts.Port),
	}

	basePoller := NewBasicService(host, opts.BasicServiceConfig, constantLabels)

	newService := ChallengeResponseService{
		ChallengeResponseMetricSet: NewChallengeResponseMetricSet(constantLabels),

		serviceChallengeable: PollStatusUnknown,
		serviceResponsive:    PollStatusUnknown,

		BasePoller: basePoller,
		config:     opts,

		serviceChallengeSize:     0,
		serviceChallengeDuration: 0,
		serviceResponseTTB:       0,
		serviceResponseSize:      0,
		serviceResponseDuration:  0,
	}

	return &newService
}

// isReader Returns true if challenger is setup to read responses.
func (crs *ChallengeResponseService) isReader() bool {
	return (crs.config.ResponseRegex != nil || crs.config.ResponseBinary != nil || crs.config.ResponseLiteral != nil)
}

// isWriter returns true if the challenger is setup to write requests.
func (crs *ChallengeResponseService) isWriter() bool {
	return (crs.config.ChallengeString != nil || crs.config.ChallengeBinary != nil)
}

// Status is used by the web-UI for quick inspections.
func (crs *ChallengeResponseService) Status() Status {
	if crs.BasePoller.Status() == PollStatusFailed || crs.BasePoller.Status() == PollStatusUnknown {
		return crs.BasePoller.Status()
	}

	if crs.isReader() {
		return crs.serviceResponsive
	}

	if crs.isWriter() {
		return crs.serviceChallengeable
	}

	return crs.BasePoller.Status()
}

func (crs *ChallengeResponseService) PollerType() string {
	return PollerTypeChallengeResponse
}

// Describe returns the Prometheus metrics description.
func (crs *ChallengeResponseService) Describe(ch chan<- *prometheus.Desc) {
	crs.ChallengeResponseMetricSet.Describe(ch)
	// Parent collectors
	crs.BasePoller.Describe(ch)
}

func (crs *ChallengeResponseService) Collect(ch chan<- prometheus.Metric) {
	// Request Start
	crs.ServiceChallengeStartTimeStamp.Set(float64(crs.serviceChallengeStart.Unix()))

	// Request metrics
	crs.ServiceRequestSuccessful.Set(float64(crs.serviceChallengeable))
	crs.ServiceRequestSize.Set(crs.serviceChallengeSize)
	if crs.serviceChallengeDuration != 0 { // Nothing should take 0 nanoseconds
		crs.ServiceChallengeTime.Set(float64(crs.serviceChallengeDuration / time.Microsecond))
	} else {
		crs.ServiceChallengeTime.Set(math.NaN())
	}

	// Response
	if crs.serviceResponseTTB != 0 { // Nothing should take 0 nanoseconds
		crs.ServiceResponseTimeToFirstByte.Set(float64(crs.serviceResponseTTB / time.Microsecond))
	} else {
		crs.ServiceResponseTimeToFirstByte.Set(math.NaN())
	}

	// Counters
	crs.ServiceRespondedSuccessfully.Set(float64(crs.serviceResponsive))
	crs.ServiceResponseSize.Set(crs.serviceResponseSize)
	if crs.serviceResponseDuration != 0 { // Nothing should take 0 nanoseconds
		crs.ServiceResponseDuration.Set(float64(crs.serviceResponseDuration / time.Microsecond))
	} else {
		crs.ServiceResponseDuration.Set(math.NaN())
	}

	// Collect metric set
	crs.ChallengeResponseMetricSet.Collect(ch)
	// Parent collectors
	crs.BasePoller.Collect(ch)
}

//nolint:funlen
func (crs *ChallengeResponseService) doPoll() net.Conn {
	// Call the parent poller (TLS or basic service)
	conn := crs.BasePoller.doPoll()

	// If no connection after poll, set metrics to fail statuses and exit.
	if conn == nil {
		crs.serviceChallengeable = PollStatusUnknown
		crs.serviceChallengeSize = math.NaN()
		crs.serviceChallengeDuration = 0

		crs.serviceResponsive = PollStatusUnknown
		crs.serviceResponseSize = math.NaN()
		crs.serviceResponseDuration = 0
		return nil
	}

	crs.serviceChallengeStart = time.Now()
	switch {
	case crs.isWriter():
		crs.serviceChallengeSize, crs.serviceChallengeable = crs.Challenge(conn) // Sets crs.serviceChallengeSize
		crs.serviceChallengeDuration = time.Since(crs.serviceChallengeStart)
		if crs.isReader() {
			if crs.serviceChallengeable == PollStatusSuccess {
				crs.serviceResponsive, crs.serviceResponseSize, crs.serviceResponseTTB = TryReadMatch(conn, &crs.config)
				crs.serviceResponseDuration = time.Since(crs.serviceChallengeStart)
			} else {
				crs.serviceResponsive = PollStatusFailed
				crs.serviceResponseDuration = 0
				crs.serviceResponseSize = 0
				crs.serviceResponseTTB = 0
			}
		} else {
			crs.serviceResponsive = PollStatusUnknown
			crs.serviceResponseSize = math.NaN()
			crs.serviceResponseDuration = 0
			crs.serviceResponseTTB = 0
		}
	case crs.isReader():
		crs.serviceChallengeable = PollStatusUnknown
		crs.serviceChallengeSize = math.NaN()
		crs.serviceChallengeDuration = 0

		crs.serviceResponsive, crs.serviceResponseSize, crs.serviceResponseTTB = TryReadMatch(conn, &crs.config)
		crs.serviceResponseDuration = time.Since(crs.serviceChallengeStart)
	default:
		crs.serviceChallengeable = PollStatusUnknown
		crs.serviceChallengeSize = math.NaN()
		crs.serviceChallengeDuration = 0

		crs.serviceResponseTTB = 0

		crs.serviceResponsive = PollStatusUnknown
		crs.serviceResponseSize = math.NaN()
		crs.serviceResponseDuration = 0
	}

	// Do cumulative counters
	if crs.serviceChallengeable == PollStatusSuccess {
		crs.ServiceRequestCount.WithLabelValues(MetricLabelSuccess).Inc()
	} else {
		crs.ServiceRequestCount.WithLabelValues(MetricLabelFailed).Inc()
	}

	if crs.serviceResponsive == PollStatusSuccess {
		crs.ServiceRespondedCount.WithLabelValues(MetricLabelSuccess).Inc()
	} else {
		crs.ServiceRespondedCount.WithLabelValues(MetricLabelFailed).Inc()
	}

	if crs.serviceResponseTTB != 0 {
		crs.ServiceResponseTimeToFirstByteCount.Add(float64(crs.serviceResponseTTB / time.Second))
	}

	crs.log().Debug("Finished challenge_response poll.")
	return conn
}

func (crs *ChallengeResponseService) Poll() {
	conn := crs.doPoll()
	if conn != nil {
		crs.log().Info("Success")
		if err := conn.Close(); err != nil {
			crs.log().Info("Error closing connection", zap.String("error", err.Error()))
		}
	}
}

// Challenge sends the challenge to the service connection, and returns in
// Prometheus form the number of bytes and result.
func (crs *ChallengeResponseService) Challenge(conn io.Writer) (float64, Status) {
	var challenge []byte
	switch {
	case crs.config.ChallengeBinary != nil:
		challenge = crs.config.ChallengeBinary
	case crs.config.ChallengeString != nil:
		challenge = []byte(*crs.config.ChallengeString)
	default:
		// this normally shouldn't happen, but this function cannot return an
		// error so we must send something.
		challenge = []byte("")
	}

	challengeBytes, err := conn.Write(challenge)
	if err != nil {
		crs.log().Info("Connection error doing ChallengeResponse check", zap.Error(err))
		return float64(challengeBytes), PollStatusFailed
	}
	return float64(challengeBytes), PollStatusSuccess
}

//nolint:funlen
func TryReadMatch(conn io.Reader, config *config.ChallengeResponseConfig) (Status, float64, time.Duration) {
	l := zap.L()
	// Read the response literal
	var nTotalBytes uint64
	var nbytes int
	var err error
	var allBytes []byte
	currentBytes := make([]byte, cachedconstants.PageSize())

	// Read bytes until the response can be matched or timeout.
	serviceResponded := PollStatusFailed

	// Wait for the first byte
	startWaitTFB := time.Now()
	var serviceResponseTTB time.Duration
	firstByte := make([]byte, 1)
	nbytes, err = conn.Read(firstByte)
	nTotalBytes += uint64(nbytes)
	allBytes = append(allBytes, firstByte...)
	if err != nil {
		serviceResponseTTB = 0
		l.Info("Connection error doing ChallengeResponse check", zap.Error(err))
		return serviceResponded, float64(nTotalBytes), serviceResponseTTB
	}
	serviceResponseTTB = time.Since(startWaitTFB)

	for {
		nbytes, err = conn.Read(currentBytes)
		nTotalBytes += uint64(nbytes)
		allBytes = append(allBytes, currentBytes...)

		// Try and match.
		//nolint:nestif
		if config.ResponseRegex != nil {
			if config.ResponseRegex.Match(allBytes) {
				serviceResponded = PollStatusSuccess
				l.Debug("Matched regex", zap.Uint64("bytes_till_match", nTotalBytes))

				break
			}
		} else {
			var bytePrefix []byte
			if config.ResponseBinary != nil {
				bytePrefix = config.ResponseBinary
			} else {
				bytePrefix = []byte(*config.ResponseLiteral)
			}

			if bytes.HasPrefix(allBytes, bytePrefix) {
				serviceResponded = PollStatusSuccess
				l.Debug("Matched byte literal", zap.Uint64("bytes_till_match", nTotalBytes))
				break
			}
		}

		if err != nil {
			l.Info("Connection error doing ChallengeResponse check:", zap.Error(err))
			break
		}

		if nTotalBytes >= config.MaxBytes {
			l.Info("Maximum read bytes exceeded during check: read",
				zap.Uint64("bytes_read_without_match", nTotalBytes),
				zap.Uint64("max_bytes_till_fail", config.MaxBytes))
			break
		}
	}

	return serviceResponded, float64(nTotalBytes), serviceResponseTTB
}
