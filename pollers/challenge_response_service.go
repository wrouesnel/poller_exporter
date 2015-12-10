package pollers

import (
	"github.com/prometheus/common/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/wrouesnel/poller_exporter/config"
	"fmt"
	"bytes"
	"time"
	"io"
	"math"
)

type ChallengeResponseService struct {
	ServiceRequestSuccessful prometheus.Gauge // Indicates if the service could be successfully sent data
	ServiceRequestSize prometheus.Gauge // Number of bytes sent to the service
	ServiceChallengeTime prometheus.Gauge // Time it took to send the challenge

	ServiceResponseTimeToFirstByte prometheus.Gauge // Time it took the service to send anything

	ServiceRespondedSuccessfully prometheus.Gauge	// Indicates if the service responded with expected data
	ServiceResponseSize prometheus.Gauge // Number of bytes read before response match
	ServiceResponseDuration prometheus.Gauge // Time in microseconds to read the response bytes

	ServiceRequestCount *prometheus.CounterVec	// Cumulative count of service requests
	ServiceRespondedCount *prometheus.CounterVec // Cumulative count of service responses
	ServiceResponseTimeToFirstByteCount prometheus.Counter // Cumulative count of service responses

	serviceChallengeable Status	// Service can be successfully challenged
	serviceChallengeSize float64	// Number of bytes sent to the service
	serviceChallengeTime time.Duration // Time service took to receive challenge

	serviceResponseTTB time.Duration	// Time to first byte

	serviceResponsive Status		// Service responds when challenged
	serviceResponseSize float64		// Number of bytes service responded with
	serviceResponseTime time.Duration // Time service took to response

	Poller
	config.ChallengeResponseConfig
}

func NewChallengeResponseService(host *Host, opts config.ChallengeResponseConfig) *ChallengeResponseService {
	clabels := prometheus.Labels{
		"hostname" : host.Hostname,
		"name" : opts.Name,
		"protocol" : opts.Protocol,
		"port" : fmt.Sprintf("%d", opts.Port),
	}

	basePoller := NewBasicService(host, opts.BasicServiceConfig)

	newService := ChallengeResponseService{
		serviceChallengeable: UNKNOWN,
		serviceResponsive: UNKNOWN,

		ServiceRequestSuccessful: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: "service",
				Name: "writeable_boolean",
				Help: "true (1) if the service could be sent data, 0 for failed, NaN for unknown",
				ConstLabels: clabels,
			},
		),
		ServiceRequestSize: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: "service",
				Name: "request_size_bytes",
				Help: "Number of bytes sent to the service",
				ConstLabels: clabels,
			},
		),
		ServiceChallengeTime: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: "service",
				Name: "request_time_microseconds",
				Help: "Time it took to send the request to the service",
				ConstLabels: clabels,
			},
		),
		ServiceResponseTimeToFirstByte: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: "service",
				Name: "request_time_to_first_byte_microseconds",
				Help: "Time it took for the first response byte to arrive",
				ConstLabels: clabels,
			},
		),
		ServiceRespondedSuccessfully: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: "service",
				Name: "responsive_boolean",
				Help: "true (1) if the target port responded with expected data, 0 for failed, NaN for unknown",
				ConstLabels: clabels,
			},
		),
		ServiceResponseSize: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: "service",
				Name: "response_size_bytes",
				Help: "Number of bytes the service responded with before request was satisified",
				ConstLabels: clabels,
			},
		),
		ServiceResponseDuration: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: "service",
				Name: "response_time_microseconds",
				Help: "Time the response took to be received in microseconds.",
				ConstLabels: clabels,
			},
		),
		ServiceRequestCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: Namespace,
				Subsystem: "service",
				Name: "writeable_total",
				Help: "cumulative count of service request success and failures",
				ConstLabels: clabels,
			},
			[]string{"result"},
		),
		ServiceRespondedCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: Namespace,
				Subsystem: "service",
				Name: "responsive_total",
				Help: "cumulative count of service response successes and failures",
				ConstLabels: clabels,
			},
			[]string{"result"},
		),
		ServiceResponseTimeToFirstByteCount: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: Namespace,
				Subsystem: "service",
				Name: "request_time_to_first_byte_seconds_total",
				Help: "cumulative count of time the service has taken to send its first byte",
				ConstLabels: clabels,
			},
		),

	}

	newService.Poller = basePoller
	newService.ChallengeResponseConfig = opts

	return &newService
}

// Return true if challenger is setup to read responses
func (this *ChallengeResponseService) isReader() bool {
	return (this.ResponseRegex != nil || this.ResponseLiteral != nil)
}

// Status is used by the web-UI for quick inspections
func (s *ChallengeResponseService) Status() Status {
	if s.Poller.Status() == FAILED || s.Poller.Status() == UNKNOWN {
		return s.Poller.Status()
	}

	if s.isReader() {
		return s.serviceResponsive
	}

	if s.isWriter() {
		return s.serviceChallengeable
	}

	return s.Poller.Status()
}

func (s *ChallengeResponseService) Describe(ch chan <- *prometheus.Desc) {
	s.ServiceRequestSuccessful.Describe(ch)
	s.ServiceRequestSize.Describe(ch)
	s.ServiceChallengeTime.Describe(ch)
	s.ServiceResponseTimeToFirstByte.Describe(ch)
	s.ServiceRespondedSuccessfully.Describe(ch)
	s.ServiceResponseSize.Describe(ch)
	s.ServiceResponseDuration.Describe(ch)

	// Cumulative counters
	s.ServiceRequestCount.Describe(ch)
	s.ServiceRespondedCount.Describe(ch)
	s.ServiceResponseTimeToFirstByteCount.Describe(ch)


	// Parent collectors
	s.Poller.Describe(ch)
}

func (s *ChallengeResponseService) Collect(ch chan <- prometheus.Metric) {
	// Request
	s.ServiceRequestSuccessful.Set(float64(s.serviceChallengeable))
	s.ServiceRequestSize.Set(s.serviceChallengeSize)
	if s.serviceChallengeTime != 0 { // Nothing should take 0 nanoseconds
		s.ServiceChallengeTime.Set(float64(s.serviceChallengeTime / time.Microsecond))
	} else {
		s.ServiceChallengeTime.Set(math.NaN())
	}

	// Response
	if s.serviceResponseTTB != 0 { // Nothing should take 0 nanoseconds
		s.ServiceResponseTimeToFirstByte.Set(float64(s.serviceResponseTTB / time.Microsecond))
	} else {
		s.ServiceResponseTimeToFirstByte.Set(math.NaN())
	}

	s.ServiceRespondedSuccessfully.Set(float64(s.serviceResponsive))
	s.ServiceResponseSize.Set(s.serviceResponseSize)
	if s.serviceResponseTime != 0 {	// Nothing should take 0 nanoseconds
		s.ServiceResponseDuration.Set(float64(s.serviceResponseTime / time.Microsecond))
	} else {
		s.ServiceResponseDuration.Set(math.NaN())
	}

	// Actual collection
	s.ServiceRequestSuccessful.Collect(ch)
	s.ServiceRequestSize.Collect(ch)
	s.ServiceChallengeTime.Collect(ch)
	s.ServiceRespondedSuccessfully.Collect(ch)
	s.ServiceResponseSize.Collect(ch)
	s.ServiceResponseDuration.Collect(ch)

	// Cumulative counters
	s.ServiceRequestCount.Collect(ch)
	s.ServiceRespondedCount.Collect(ch)
	s.ServiceResponseTimeToFirstByteCount.Collect(ch)

	// Parent collectors
	s.Poller.Collect(ch)
}

func (this *ChallengeResponseService) Poll() {
	conn := this.doPoll()
	if conn == nil {
		// Zero out all other metrics
		this.serviceChallengeable = UNKNOWN
		this.serviceChallengeSize = math.NaN()
		this.serviceChallengeTime = 0

		this.serviceResponsive = UNKNOWN
		this.serviceResponseSize = math.NaN()
		this.serviceResponseTime = 0
		return
	}
	defer conn.Close()

	startTime := time.Now()
	if this.isWriter() {
		this.serviceChallengeable = this.Challenge(conn)	// Sets this.serviceChallengeSize
		this.serviceChallengeTime = time.Now().Sub(startTime)
		if this.isReader() {
			if this.serviceChallengeable == SUCCESS {
				this.serviceResponsive, this.serviceResponseSize, this.serviceResponseTTB = this.TryReadMatch(conn)
				this.serviceResponseTime = time.Now().Sub(startTime)
			} else {
				this.serviceResponsive = FAILED
				this.serviceResponseTime = 0
				this.serviceResponseSize = 0
				this.serviceResponseTTB = 0
			}
		} else {
			this.serviceResponsive = UNKNOWN
			this.serviceResponseSize = math.NaN()
			this.serviceResponseTime = 0
			this.serviceResponseTTB = 0
		}
	} else if this.isReader() {
		this.serviceChallengeable = UNKNOWN
		this.serviceChallengeSize = math.NaN()
		this.serviceChallengeTime = 0

		this.serviceResponsive, this.serviceResponseSize, this.serviceResponseTTB = this.TryReadMatch(conn)
		this.serviceResponseTime = time.Now().Sub(startTime)
	} else {
		this.serviceChallengeable = UNKNOWN
		this.serviceChallengeSize = math.NaN()
		this.serviceChallengeTime = 0

		this.serviceResponseTTB = 0

		this.serviceResponsive = UNKNOWN
		this.serviceResponseSize = math.NaN()
		this.serviceResponseTime = 0
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

	log.Debugln("Finished challenge_response poll.")
}

func (this *ChallengeResponseService) isWriter() bool {
	if this.ChallengeLiteral == nil {
		return false
	}
	return true
}

func (s *ChallengeResponseService) Challenge(conn io.Writer) Status {
	// Send the challenge literal
	challengeBytes, err := conn.Write([]byte(*s.ChallengeLiteral))
	s.serviceChallengeSize = float64(challengeBytes)
	if err != nil {
		log.Infoln("Connection error doing ChallengeResponse check:", err)
		return FAILED
	}
	return SUCCESS
}

func (s *ChallengeResponseService) TryReadMatch(conn io.Reader) (Status, float64, time.Duration) {
	// Read the response literal
	var nTotalBytes uint64
	var nbytes int
	var err error
	var allBytes []byte
	currentBytes := make([]byte, 4096)

	// Read bytes until the response can be matched or timeout.
	serviceResponded := FAILED

	// Wait for the first byte
	startWaitTFB := time.Now()
	var serviceResponseTTB time.Duration
	firstByte := make([]byte,1)
	nbytes, err = conn.Read(firstByte)
	nTotalBytes += uint64(nbytes)
	allBytes = append(allBytes, firstByte...)
	if err != nil {
		serviceResponseTTB = 0
		log.Infoln("Connection error doing ChallengeResponse check:", err)
		return serviceResponded, float64(nTotalBytes), serviceResponseTTB
	} else {
		serviceResponseTTB = time.Now().Sub(startWaitTFB)
	}

	for {
		nbytes, err = conn.Read(currentBytes)
		nTotalBytes += uint64(nbytes)
		allBytes = append(allBytes, currentBytes...)

		// Try and match.
		if s.ResponseRegex != nil {
			if s.ResponseRegex.Match(allBytes) {
				serviceResponded = SUCCESS
				log.Debugln("Matched regex after", nTotalBytes, "bytes")
				break
			}
		} else {
			if bytes.HasPrefix(allBytes, []byte(*s.ResponseLiteral)) {
				serviceResponded = SUCCESS

				log.Debugln("Matched byte literal after", nTotalBytes, "bytes")
				break
			}
		}

		if err != nil {
			log.Infoln("Connection error doing ChallengeResponse check:", err)
			break
		}

		if nTotalBytes >= s.MaxBytes {
			log.Infoln("Maximum read bytes exceeded during check: read", nTotalBytes, ">=", s.MaxBytes)
			break
		}
	}

	return serviceResponded, float64(nTotalBytes), serviceResponseTTB
}