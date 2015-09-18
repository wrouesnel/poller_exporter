package pollers

import (
	"github.com/prometheus/log"
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

	ServiceRespondedSuccessfully prometheus.Gauge	// Indicates if the service responded with expected data
	ServiceResponseSize prometheus.Gauge // Number of bytes read before response match
	ServiceResponseDuration prometheus.Gauge // Time in microseconds to read the response bytes

	serviceChallengeable Status	// Service can be successfully challenged
	serviceChallengeSize float64	// Number of bytes sent to the service
	serviceChallengeTime time.Duration // Time service took to receive challenge

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

	}

	newService.Poller = basePoller
	newService.ChallengeResponseConfig = opts

	return &newService
}

// Return true if challenger is setup to read responses
func (this *ChallengeResponseService) isReader() bool {
	return (this.ResponseRegex == nil && this.ResponseLiteral == nil)
}

// Status is used by the web-UI for quick inspections
func (s *ChallengeResponseService) Status() Status {
	if s.isReader() {
		return s.serviceResponsive
	}
	return s.serviceChallengeable
}

func (s *ChallengeResponseService) Describe(ch chan <- *prometheus.Desc) {
	s.ServiceRequestSuccessful.Describe(ch)
	s.ServiceRequestSize.Describe(ch)
	s.ServiceChallengeTime.Describe(ch)
	s.ServiceRespondedSuccessfully.Describe(ch)
	s.ServiceResponseSize.Describe(ch)
	s.ServiceResponseDuration.Describe(ch)

	// Parent collectors
	s.Poller.Describe(ch)
}

func (s *ChallengeResponseService) Collect(ch chan <- prometheus.Metric) {
	// Request
	s.ServiceRequestSuccessful.Set(float64(s.serviceResponsive))
	if s.serviceResponsive == SUCCESS {
		s.ServiceRequestSize.Set(s.serviceChallengeSize)
		s.ServiceChallengeTime.Set(float64(s.serviceChallengeTime * time.Microsecond))
	} else {
		s.ServiceRequestSize.Set(math.NaN())
		s.ServiceChallengeTime.Set(math.NaN())
	}

	// Response
	s.ServiceRespondedSuccessfully.Set(float64(s.serviceResponsive))
	if s.serviceResponsive == SUCCESS {
		s.ServiceResponseSize.Set(s.serviceChallengeSize)
		s.ServiceResponseDuration.Set(float64(s.serviceResponseTime * time.Microsecond))
	} else {
		s.ServiceResponseSize.Set(math.NaN())
		s.ServiceResponseDuration.Set(math.NaN())
	}

	// Actual collection
	s.ServiceRequestSuccessful.Collect(ch)
	s.ServiceRequestSize.Collect(ch)
	s.ServiceChallengeTime.Collect(ch)
	s.ServiceRespondedSuccessfully.Collect(ch)
	s.ServiceResponseSize.Collect(ch)
	s.ServiceResponseDuration.Collect(ch)

	// Parent collectors
	s.Poller.Collect(ch)
}

func (this *ChallengeResponseService) Poll() {
	conn := this.doPoll()
	if conn == nil {
		// Couldn't connect - service is non-responsive.
		this.serviceResponsive = FAILED
		this.serviceChallengeable = FAILED
		return
	}
	defer conn.Close()

	// Set deadline for all reads/writes to complete
	conn.SetDeadline(time.Now().Add(time.Duration(this.Timeout)))

	startTime := time.Now()
	if this.isWriter() {
		this.serviceChallengeable = this.Challenge(conn)
		this.serviceChallengeTime = time.Now().Sub(startTime)
		if this.isReader() {
			if this.serviceChallengeable == SUCCESS {
				this.serviceResponsive = this.TryReadMatch(conn)
				this.serviceResponseTime = time.Now().Sub(startTime)
			} else {
				this.serviceResponsive = FAILED
				this.serviceResponseTime = time.Duration{}
				this.serviceResponseSize = 0
			}
		} else {
			this.serviceResponsive = UNKNOWN
			this.serviceResponseTime = time.Duration{}
			this.serviceResponseSize = math.NaN()
		}
	} else {
		this.serviceChallengeable = UNKNOWN
		this.serviceChallengeSize = math.NaN()
		this.serviceChallengeTime = time.Duration{}

		this.serviceResponsive = UNKNOWN
		this.serviceResponseSize = math.NaN()
		this.serviceResponseTime = time.Duration{}
	}

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

func (s *ChallengeResponseService) TryReadMatch(conn io.Reader) Status {
	// Read the response literal
	var nTotalBytes uint64
	var allBytes []byte
	currentBytes := make([]byte, 4096)

	// Read bytes until the response can be matched or timeout.
	serviceResponded := FAILED
	for {
		nbytes, err := conn.Read(currentBytes)
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
			log.Infoln("Maximum read bytes exceeded during check.")
			break
		}
	}
	s.serviceResponseSize = float64(nTotalBytes)
	return serviceResponded
}