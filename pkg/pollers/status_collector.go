// package status defines a status collector metric which aggregates status
// responses from underlying services.
package pollers

import (
	"sync"

	"github.com/samber/lo"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

type ServiceStatusMetricCollector struct {
	ServiceStatus *prometheus.GaugeVec
	locker        *sync.Mutex
	pollers       []Poller
	l             *zap.Logger
}

// NewServiceStatusMetrics creates a new service status metric collector.
func NewServiceStatusMetrics(labels []string) *ServiceStatusMetricCollector {
	if labels == nil {
		labels = []string{}
	}
	fullLabels := lo.Union([]string{"poller_type", "hostname", "name", "protocol", "port"}, labels)

	return &ServiceStatusMetricCollector{
		ServiceStatus: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: Namespace,
				Subsystem: "service",
				Name:      "status_boolean",
				Help:      "whether the poller succeeded by its current configuration - 1 means true, 0 false, NaN unknown",
			},
			fullLabels,
		),
		locker: &sync.Mutex{},
		l:      zap.L(),
	}
}

// AddPoller ads a poller to the collector.
func (ssm *ServiceStatusMetricCollector) AddPoller(pollers ...Poller) {
	ssm.locker.Lock()
	defer ssm.locker.Unlock()
	ssm.pollers = append(ssm.pollers, pollers...)
	for _, poller := range pollers {
		ssm.l.Debug("Registered poller for status collection",
			poller.LogFields()...)
	}
}

// Describe implements the prometheus metric descriptors interface.
func (ssm *ServiceStatusMetricCollector) Describe(ch chan<- *prometheus.Desc) {
	ssm.ServiceStatus.Describe(ch)
}

// Collect implements the prometheus metric descriptors interface.
func (ssm *ServiceStatusMetricCollector) Collect(ch chan<- prometheus.Metric) {
	ssm.locker.Lock()
	defer ssm.locker.Unlock()
	// Set the metrics right before we're collected
	for _, poller := range ssm.pollers {
		ssm.ServiceStatus.With(poller.Labels()).Set(float64(poller.Status()))
	}
	ssm.ServiceStatus.Collect(ch)
}
