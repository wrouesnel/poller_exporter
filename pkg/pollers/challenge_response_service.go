package pollers

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/wrouesnel/poller_exporter/pkg/cachedconstants"

	"github.com/wrouesnel/poller_exporter/pkg/config"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

type ChallengeResponseService struct {
	ServiceRequestSuccessful prometheus.Gauge // Indicates if the service could be successfully sent data
	ServiceRequestSize       prometheus.Gauge // Number of bytes sent to the service
	ServiceChallengeTime     prometheus.Gauge // Time it took to send the challenge

	ServiceResponseTimeToFirstByte prometheus.Gauge // Time it took the service to send anything

	ServiceRespondedSuccessfully prometheus.Gauge // Indicates if the service responded with expected data
	ServiceResponseSize          prometheus.Gauge // Number of bytes read before response match
	ServiceResponseDuration      prometheus.Gauge // Time in microseconds to read the response bytes

	ServiceRequestCount                 *prometheus.CounterVec // Cumulative count of service requests
	ServiceRespondedCount               *prometheus.CounterVec // Cumulative count of service responses
	ServiceResponseTimeToFirstByteCount prometheus.Counter     // Cumulative count of service responses

	serviceChallengeable Status        // Service can be successfully challenged
	serviceChallengeSize float64       // Number of bytes sent to the service
	serviceChallengeTime time.Duration // Time service took to receive challenge

	serviceResponseTTB time.Duration // Time to first byte

	serviceResponsive   Status        // Service responds when challenged
	serviceResponseSize float64       // Number of bytes service responded with
	serviceResponseTime time.Duration // Time service took to response

	Poller
	config.ChallengeResponseConfig
}

//nolint:funlen
func NewChallengeResponseService(host *Host, opts config.ChallengeResponseConfig) *ChallengeResponseService {
	clabels := prometheus.Labels{
		"hostname": host.Hostname,
		"name":     opts.Name,
		"protocol": opts.Protocol,
		"port":     fmt.Sprintf("%d", opts.Port),
	}

	basePoller := NewBasicService(host, opts.BasicServiceConfig)

	newService := ChallengeResponseService{
		serviceChallengeable: PollStatusUnknown,
		serviceResponsive:    PollStatusUnknown,

		ServiceRequestSuccessful: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "writeable_boolean",
				Help:        "true (1) if the service could be sent data, 0 for failed, NaN for unknown",
				ConstLabels: clabels,
			},
		),
		ServiceRequestSize: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "request_size_bytes",
				Help:        "Number of bytes sent to the service",
				ConstLabels: clabels,
			},
		),
		ServiceChallengeTime: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "request_time_microseconds",
				Help:        "Time it took to send the request to the service",
				ConstLabels: clabels,
			},
		),
		ServiceResponseTimeToFirstByte: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "request_time_to_first_byte_microseconds",
				Help:        "Time it took for the first response byte to arrive",
				ConstLabels: clabels,
			},
		),
		ServiceRespondedSuccessfully: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "responsive_boolean",
				Help:        "true (1) if the target port responded with expected data, 0 for failed, NaN for unknown",
				ConstLabels: clabels,
			},
		),
		ServiceResponseSize: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "response_size_bytes",
				Help:        "Number of bytes the service responded with before request was satisified",
				ConstLabels: clabels,
			},
		),
		ServiceResponseDuration: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "response_time_microseconds",
				Help:        "Time the response took to be received in microseconds.",
				ConstLabels: clabels,
			},
		),
		ServiceRequestCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "writeable_total",
				Help:        "cumulative count of service request success and failures",
				ConstLabels: clabels,
			},
			[]string{"result"},
		),
		ServiceRespondedCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "responsive_total",
				Help:        "cumulative count of service response successes and failures",
				ConstLabels: clabels,
			},
			[]string{"result"},
		),
		ServiceResponseTimeToFirstByteCount: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace:   Namespace,
				Subsystem:   "service",
				Name:        "request_time_to_first_byte_seconds_total",
				Help:        "cumulative count of time the service has taken to send its first byte",
				ConstLabels: clabels,
			},
		),

		Poller:                  basePoller,
		ChallengeResponseConfig: opts,

		serviceChallengeSize: 0,
		serviceChallengeTime: 0,
		serviceResponseTTB:   0,
		serviceResponseSize:  0,
		serviceResponseTime:  0,
	}

	return &newService
}

// isReader Returns true if challenger is setup to read responses.
func (crs *ChallengeResponseService) isReader() bool {
	return (crs.ResponseRegex != nil || crs.ResponseLiteral != nil)
}

// Status is used by the web-UI for quick inspections.
func (crs *ChallengeResponseService) Status() Status {
	if crs.Poller.Status() == PollStatusFailed || crs.Poller.Status() == PollStatusUnknown {
		return crs.Poller.Status()
	}

	if crs.isReader() {
		return crs.serviceResponsive
	}

	if crs.isWriter() {
		return crs.serviceChallengeable
	}

	return crs.Poller.Status()
}

// Describe returns the Prometheus metrics description.
func (crs *ChallengeResponseService) Describe(ch chan<- *prometheus.Desc) {
	crs.ServiceRequestSuccessful.Describe(ch)
	crs.ServiceRequestSize.Describe(ch)
	crs.ServiceChallengeTime.Describe(ch)
	crs.ServiceResponseTimeToFirstByte.Describe(ch)
	crs.ServiceRespondedSuccessfully.Describe(ch)
	crs.ServiceResponseSize.Describe(ch)
	crs.ServiceResponseDuration.Describe(ch)

	// Cumulative counters
	crs.ServiceRequestCount.Describe(ch)
	crs.ServiceRespondedCount.Describe(ch)
	crs.ServiceResponseTimeToFirstByteCount.Describe(ch)

	// Parent collectors
	crs.Poller.Describe(ch)
}

func (crs *ChallengeResponseService) Collect(ch chan<- prometheus.Metric) {
	// Request
	crs.ServiceRequestSuccessful.Set(float64(crs.serviceChallengeable))
	crs.ServiceRequestSize.Set(crs.serviceChallengeSize)
	if crs.serviceChallengeTime != 0 { // Nothing should take 0 nanoseconds
		crs.ServiceChallengeTime.Set(float64(crs.serviceChallengeTime / time.Microsecond))
	} else {
		crs.ServiceChallengeTime.Set(math.NaN())
	}

	// Response
	if crs.serviceResponseTTB != 0 { // Nothing should take 0 nanoseconds
		crs.ServiceResponseTimeToFirstByte.Set(float64(crs.serviceResponseTTB / time.Microsecond))
	} else {
		crs.ServiceResponseTimeToFirstByte.Set(math.NaN())
	}

	crs.ServiceRespondedSuccessfully.Set(float64(crs.serviceResponsive))
	crs.ServiceResponseSize.Set(crs.serviceResponseSize)
	if crs.serviceResponseTime != 0 { // Nothing should take 0 nanoseconds
		crs.ServiceResponseDuration.Set(float64(crs.serviceResponseTime / time.Microsecond))
	} else {
		crs.ServiceResponseDuration.Set(math.NaN())
	}

	// Actual collection
	crs.ServiceRequestSuccessful.Collect(ch)
	crs.ServiceRequestSize.Collect(ch)
	crs.ServiceChallengeTime.Collect(ch)
	crs.ServiceRespondedSuccessfully.Collect(ch)
	crs.ServiceResponseSize.Collect(ch)
	crs.ServiceResponseDuration.Collect(ch)

	// Cumulative counters
	crs.ServiceRequestCount.Collect(ch)
	crs.ServiceRespondedCount.Collect(ch)
	crs.ServiceResponseTimeToFirstByteCount.Collect(ch)

	// Parent collectors
	crs.Poller.Collect(ch)
}

//nolint:funlen
func (crs *ChallengeResponseService) Poll() {
	conn := crs.doPoll()
	if conn == nil {
		// Zero out all other metrics
		crs.serviceChallengeable = PollStatusUnknown
		crs.serviceChallengeSize = math.NaN()
		crs.serviceChallengeTime = 0

		crs.serviceResponsive = PollStatusUnknown
		crs.serviceResponseSize = math.NaN()
		crs.serviceResponseTime = 0
		return
	}
	defer conn.Close()

	startTime := time.Now()
	switch {
	case crs.isWriter():
		crs.serviceChallengeable = crs.Challenge(conn) // Sets crs.serviceChallengeSize
		crs.serviceChallengeTime = time.Since(startTime)
		if crs.isReader() {
			if crs.serviceChallengeable == PollStatusSuccess {
				crs.serviceResponsive, crs.serviceResponseSize, crs.serviceResponseTTB = crs.TryReadMatch(conn)
				crs.serviceResponseTime = time.Since(startTime)
			} else {
				crs.serviceResponsive = PollStatusFailed
				crs.serviceResponseTime = 0
				crs.serviceResponseSize = 0
				crs.serviceResponseTTB = 0
			}
		} else {
			crs.serviceResponsive = PollStatusUnknown
			crs.serviceResponseSize = math.NaN()
			crs.serviceResponseTime = 0
			crs.serviceResponseTTB = 0
		}
	case crs.isReader():
		crs.serviceChallengeable = PollStatusUnknown
		crs.serviceChallengeSize = math.NaN()
		crs.serviceChallengeTime = 0

		crs.serviceResponsive, crs.serviceResponseSize, crs.serviceResponseTTB = crs.TryReadMatch(conn)
		crs.serviceResponseTime = time.Since(startTime)
	default:
		crs.serviceChallengeable = PollStatusUnknown
		crs.serviceChallengeSize = math.NaN()
		crs.serviceChallengeTime = 0

		crs.serviceResponseTTB = 0

		crs.serviceResponsive = PollStatusUnknown
		crs.serviceResponseSize = math.NaN()
		crs.serviceResponseTime = 0
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
}

func (crs *ChallengeResponseService) isWriter() bool {
	return crs.ChallengeLiteral == nil
}

func (crs *ChallengeResponseService) Challenge(conn io.Writer) Status {
	// Send the challenge literal
	challengeBytes, err := conn.Write([]byte(*crs.ChallengeLiteral))
	crs.serviceChallengeSize = float64(challengeBytes)
	if err != nil {
		crs.log().Info("Connection error doing ChallengeResponse check", zap.Error(err))
		return PollStatusFailed
	}
	return PollStatusSuccess
}

//nolint:funlen
func (crs *ChallengeResponseService) TryReadMatch(conn io.Reader) (Status, float64, time.Duration) {
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
		crs.log().Info("Connection error doing ChallengeResponse check", zap.Error(err))
		return serviceResponded, float64(nTotalBytes), serviceResponseTTB
	}
	serviceResponseTTB = time.Since(startWaitTFB)

	for {
		nbytes, err = conn.Read(currentBytes)
		nTotalBytes += uint64(nbytes)
		allBytes = append(allBytes, currentBytes...)

		// Try and match.
		if crs.ResponseRegex != nil {
			if crs.ResponseRegex.Match(allBytes) {
				serviceResponded = PollStatusSuccess
				crs.log().Debug("Matched regex", zap.Uint64("bytes_till_match", nTotalBytes))

				break
			}
		} else {
			if bytes.HasPrefix(allBytes, []byte(*crs.ResponseLiteral)) {
				serviceResponded = PollStatusSuccess
				crs.log().Debug("Matched byte literal", zap.Uint64("bytes_till_match", nTotalBytes))

				break
			}
		}

		if err != nil {
			crs.log().Info("Connection error doing ChallengeResponse check:", zap.Error(err))

			break
		}

		if nTotalBytes >= crs.MaxBytes {
			crs.log().Info("Maximum read bytes exceeded during check: read",
				zap.Uint64("bytes_read_without_match", nTotalBytes), zap.Uint64("max_bytes_till_fail", crs.MaxBytes))

			break
		}
	}

	return serviceResponded, float64(nTotalBytes), serviceResponseTTB
}
