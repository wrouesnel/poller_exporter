package pollers

import (

	"github.com/prometheus/client_golang/prometheus"
	"github.com/wrouesnel/poller_exporter/config"
	"fmt"
)

type ChallengeResponseService struct {
	ServiceResponsive prometheus.Gauge	// Indicates if the service responded with expected data

	Poller
}

func NewChallengeResponseService(host *Host, opts config.ChallengeResponseConfig) Poller {
	clabels := prometheus.Labels{
		"hostname" : host.Hostname,
		"name" : opts.Name,
		"protocol" : opts.Protocol,
		"port" : fmt.Sprintf("%d", opts.Port),
	}

	basePoller := NewBasicService(host, opts)

	newService := ChallengeResponseService{
		ServiceResponsive: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: "service",
				Name: "responsive_boolean",
				Help: "true (1) if the targeted port responded with expected data",
				ConstLabels: clabels,
			},
		),
	}

	newService.Poller = basePoller

	return &Poller(newService)
}

func (s *ChallengeResponseService) Describe(ch chan <- *prometheus.Desc) {
	s.ServiceResponsive.Describe(ch)
	Poller.Describe(ch)
}

func (s *ChallengeResponseService) Collect(ch chan <- prometheus.Metric) {
	s.ServiceResponsive.Collect(ch)
	Poller.Collect(ch)
}

func (s *ChallengeResponseService) Poll() {

}