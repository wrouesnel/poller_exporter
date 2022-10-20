// Package config defines the exporter configuration objects
package config

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/prometheus/common/model"
)

const (
	TLSCACertsSystem string = "system"
	ProxyEnvironment string = "environment"
	ProxyDirect      string = "direct"
)

var (
	ErrInvalidPEMFile = errors.New("PEM file could not be added to certificate pool")
)

// Config is the top-level config item the.
type Config struct {
	Web         *WebConfig       `mapstructure:"web,omitempty"`
	Collector   *CollectorConfig `mapstructure:"collector,omitempty"`
	HostDefault *HostSettings    `mapstructure:"host_defaults,omitempty"`
	Hosts       []*HostConfig    `mapstructure:"hosts,omitempty"`
}

// BasicAuthConfig defines basic authentication credentials to accept on the web interface.
// If Password is not set, then the credential set is ignored. The password is plaintext.
type BasicAuthConfig struct {
	Username string `mapstructure:"username,omitempty"` // Username to accept
	Password string `mapstructure:"password,omitempty"` // Plain text password to accept
}

//type JWTTokenAuthConfig struct {
//	Secret    string `mapstructure:"secret"`    // JWT secret suitable for algorithm
//	Algorithm string `mapstructure:"algorithm"` // Algorithm to use
//	ID        string `mapstructure:"id"`        // ID for the token provider
//}

// AuthConfig holds the configuration of any authentication put on the exporter interface.
type AuthConfig struct {
	BasicAuthCredentials []BasicAuthConfig `mapstructure:"basic_auth,omitempty"`
	//JWTToken             []JWTTokenAuthConfig `mapstructure:"jwt_auth,omitempty"`
}

// WebConfig holds global configuration for the exporters webserver.
type WebConfig struct {
	TelemetryPath     string         `mapstructure:"telemetry_path,omitempty"`
	ReadHeaderTimeout model.Duration `mapstructure:"read_header_timeout,omitempty"`
	Listen            []URL          `mapstructure:"listen,omitempty"`
	Auth              *AuthConfig    `mapstructure:"auth,omitempty"`
}

// CollectorConfig configures globals limits on the Prometheus metric collectors.
type CollectorConfig struct {
	MaxConnections int `mapstructure:"max_connections,omitempty"`
}

// HostSettings contains the poller configuration which is applied per hostname
// (as opposed to per service).
type HostSettings struct {
	PollFrequency model.Duration `mapstructure:"poll_frequency,omitempty"` // Frequency to poll this specific host
	PingDisable   bool           `mapstructure:"disable_ping,omitempty"`   // Disable ping checks for this host
	PingTimeout   model.Duration `mapstructure:"ping_timeout,omitempty"`   // Maximum ping timeout
	PingCount     uint64         `mapstructure:"ping_count,omitempty"`     // Number of pings to send each poll

	ExtraLabels map[string]string `mapstructure:"extra_labels,omitempty"` // Extra Prometheus Metrics to add to collected metrics

	ServiceDefaults ServiceSettings `mapstructure:"service_defaults,omitempty"`
}

// HostConfig defines a host which we want to find service information about.
// Hosts export DNS checks.
type HostConfig struct {
	Hostname     string `mapstructure:"hostname"` // Host or IP to contact
	HostSettings `mapstructure:",squash"`

	BasicChecks             []*BasicServiceConfig      `mapstructure:"basic_checks,omitempty"`
	ChallengeResponseChecks []*ChallengeResponseConfig `mapstructure:"challenge_response_checks,omitempty"`
	HTTPChecks              []*HTTPServiceConfig       `mapstructure:"http_checks,omitempty"`
}

// ServiceSettings is used for declaring service defaults.
type ServiceSettings struct {
	BasicServiceSettings             `mapstructure:",squash"`
	ChallengeResponseServiceSettings `mapstructure:",squash"`
	HTTPSettings                     `mapstructure:",squash"`
}

// BasicServiceSettings are the common settings all services share.
type BasicServiceSettings struct {
	Timeout                 model.Duration     `mapstructure:"timeout,omitempty"`             // Number of seconds to wait for response
	TLSEnable               bool               `mapstructure:"tls_enable,omitempty"`          // The service uses TLS
	TLSVerifyFailOk         bool               `mapstructure:"tls_verify_fail_ok,omitempty"`  // The service uses TLS
	TLSServerNameIndication *string            `mapstructure:"tls_sni_name,omitempty"`        // The TLS SNI name to send.
	TLSCertificatePin       *TLSCertificateMap `mapstructure:"tls_certificate_pin,omitempty"` // Map of certificates which *must* be returned by the service. If null, ignored.
	TLSCACerts              TLSCertificatePool `mapstructure:"tls_cacerts,omitempty"`         // Path to CAfile to verify the service TLS with
	Proxy                   string             `mapstructure:"proxy,omitempty"`               // Proxy configuration for the service
	ProxyAuth               *BasicAuthConfig   `mapstructure:"proxy_auth,omitempty"`          // Authentication for the proxy service
	ExtraLabels             map[string]string  `mapstructure:"extra_labels,omitempty"`        // Extra Prometheus Metrics to add to collected metrics
}

type ChallengeResponseServiceSettings struct {
	MaxBytes uint64 `mapstructure:"max_bytes,omitempty"` // Maximum number of bytes to read from connection for response searching
}

// A basic network service.
type BasicServiceConfig struct {
	BasicServiceSettings `mapstructure:",squash"`
	Name                 string `mapstructure:"name"`            // Name of the service
	Protocol             string `mapstructure:"proto,omitempty"` // TCP or UDP
	Port                 uint64 `mapstructure:"port"`            // Port number of the service
}

// Similar to a banner check, but first sends the specified data befoe looking
// for a response.
type ChallengeResponseConfig struct {
	BasicServiceConfig `mapstructure:",squash"`
	ChallengeString    *string `mapstructure:"challenge,omitempty"`
	ChallengeBinary    Bytes   `mapstructure:"challenge_b64,omitempty"` // Supercedes the string
	ResponseRegex      *Regexp `mapstructure:"response_re,omitempty"`   // Regex that must match. It is applied to the binary output.
	ResponseLiteral    *string `mapstructure:"response,omitempty"`      // Literal string that must match
	ResponseBinary     Bytes   `mapstructure:"response_b64,omitempty"`  // Literal bytes which must match - supercedes the string
	MaxBytes           uint64  `mapstructure:"max_bytes,omitempty"`     // Maximum number of bytes to read while looking for the response regex. 0 means read until connection closes.
}

type ChallengeResponseConfigValidationError struct {
	ServiceDescription string
}

func (r ChallengeResponseConfigValidationError) Error() string {
	return fmt.Sprintln("validation: requires at least 1 of response_re or response:", r.ServiceDescription)
}

// HTTPRequestAuth represents configuration for sending HTTP requests.
type HTTPRequestAuth struct {
	BasicAuth *BasicAuthConfig `mapstructure:"basic_auth,omitempty"`
}

// HTTPSettings are inheritable HTTP settings.
type HTTPSettings struct {
	HTTPMaxRedirects int64               `mapstructure:"http_max_redirects,omitempty"`
	EnableRedirects  bool                `mapstructure:"http_enable_redirects,omitempty"` // If set to true, does not follow redirects
	Headers          []map[string]string `mapstructure:"http_headers,omitempty"`          // HTTP request headers to set
	SuccessStatuses  HTTPStatusRange     `mapstructure:"http_success_status,omitempty"`   // List of status codes indicating success
}

// An HTTP speaking service. Does not yet support being a proxy.
// If TLSEnable is not set but you request HTTPS, it'll fail.
type HTTPServiceConfig struct {
	ChallengeResponseConfig `mapstructure:",squash"`
	HTTPSettings            `mapstructure:",squash"`
	Verb                    HTTPVerb        `mapstructure:"verb,omitempty"` // HTTP verb to use
	URL                     URL             `mapstructure:"url,omitempty"`  // HTTP request URL to send
	RequestAuth             HTTPRequestAuth `mapstructure:"auth,omitempty"` // Authentication configuration
}
