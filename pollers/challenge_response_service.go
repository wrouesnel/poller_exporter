package pollers

import (
	"github.com/prometheus/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/wrouesnel/poller_exporter/config"
	"fmt"
	"bytes"
	"time"
)

type ChallengeResponseService struct {
	ServiceResponsive prometheus.Gauge	// Indicates if the service responded with expected data
	serviceResponsive bool

	Poller
	config.ChallengeResponseConfig
}

func NewChallengeResponseService(host *Host, opts config.ChallengeResponseConfig) Poller {
	clabels := prometheus.Labels{
		"hostname" : host.Hostname,
		"name" : opts.Name,
		"protocol" : opts.Protocol,
		"port" : fmt.Sprintf("%d", opts.Port),
	}

	basePoller := NewBasicService(host, opts.BasicServiceConfig)

	newService := ChallengeResponseService{
		ServiceResponsive: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: "service",
				Name: "responsive_boolean",
				Help: "true (1) if the target port responded with expected data",
				ConstLabels: clabels,
			},
		),
	}

	newService.Poller = basePoller
	newService.ChallengeResponseConfig = opts

	return Poller(&newService)
}

func (s *ChallengeResponseService) Status() bool {
	return s.serviceResponsive
}

func (s *ChallengeResponseService) Describe(ch chan <- *prometheus.Desc) {
	s.ServiceResponsive.Describe(ch)
	s.Poller.Describe(ch)
}

func (s *ChallengeResponseService) Collect(ch chan <- prometheus.Metric) {
	if s.serviceResponsive {
		s.ServiceResponsive.Set(1)
	} else {
		s.ServiceResponsive.Set(0)
	}

	s.ServiceResponsive.Collect(ch)

	s.Poller.Collect(ch)
}

func (s *ChallengeResponseService) Poll() {
	conn := s.doPoll()
	if conn == nil {
		// Couldn't connect - service is non-responsive.
		s.serviceResponsive = false
		return
	}

	// Set deadline for all reads/writes to complete
	conn.SetDeadline(time.Now().Add(time.Duration(s.Timeout)))

	// Check for a challenge literal
	if len(s.ChallengeLiteral) != 0 {
		// Send the challenge literal
		_, err := conn.Write(s.ChallengeLiteral)
		if err != nil {
			log.Infoln("Connection error doing ChallengeResponse check:", err)
			s.serviceResponsive = false
			return
		}
	}

	// Read the response literal
	var nTotalBytes uint64
	var allBytes []byte
	currentBytes := make([]byte, 4096)

	// Read bytes until the response can be matched or timeout.
	serviceResponded := false
	for {
		nbytes, err := conn.Read(currentBytes)
		nTotalBytes += uint64(nbytes)
		allBytes = append(allBytes, currentBytes...)

		// Try and match.
		if s.ResponseRegex != nil {
			if s.ResponseRegex.Match(allBytes) {
				serviceResponded = true
				log.Debugln("Matched regex after", nTotalBytes, "bytes")
				break
			}
		} else {
			if bytes.HasPrefix(allBytes, s.ResponseLiteral) {
				serviceResponded = true
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
	s.serviceResponsive = serviceResponded
}