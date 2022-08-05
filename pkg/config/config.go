// This is similar to the main Prometheus scheme, because hey, it works pretty well.

//nolint:tagliatelle,exhaustruct,gochecknoglobals,cyclop,varnamelen
package config

import (
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/common/model"
	"github.com/wrouesnel/poller_exporter/pkg/errutils"
)

const DefaultPollFrequency = 30 * time.Second
const TLSCACertsSystem string = "system"

var (
	DefaultConfig Config = Config{
		PollFrequency: model.Duration(DefaultPollFrequency),
		TLSCACerts: TLSCertificatePool{
			CertPool: errutils.Must(x509.SystemCertPool()),
			original: []string{TLSCACertsSystem},
		},
	}

	DefaultHostConfig HostConfig = HostConfig{
		PollFrequency: DefaultConfig.PollFrequency,
	}

	DefaultBasicServiceConfig = BasicServiceConfig{
		Protocol: "tcp",
		//MinimumFailures: 1,
		TLSCACerts: DefaultConfig.TLSCACerts,
	}

	DefaultChallengeResponseServiceConfig = ChallengeResponseConfig{
		BasicServiceConfig: DefaultBasicServiceConfig,
	}

	DefaultHTTPServiceConfig = HTTPServiceConfig{
		ChallengeResponseConfig: DefaultChallengeResponseServiceConfig,
	}
)

var (
	ErrUnknownFields  = errors.New("unknown fields in config map")
	ErrInvalidPEMFile = errors.New("PEM file could not be added to certificate pool")
)

type Config struct {
	BasicAuthUsername string `yaml:"username,omitempty"` // If set, enables basic auth
	BasicAuthPassword string `yaml:"password,omitempty"` // If set, enables basic auth (must have a username)

	TLSCertificatePath string `yaml:"tls_cert,omitempty"` // Path to TLS certificate. Enables TLS if specified.
	TLSKeyPath         string `yaml:"tls_key,omitempty"`  // Path to TLS key file. Enables TLS if specified.

	TLSCACerts TLSCertificatePool `yaml:"tls_cacerts,omitempty"` // Default certificate pool for TLS enabled pollers

	PollFrequency model.Duration `yaml:"poll_frequency,omitempty"` // Default polling frequency for hosts
	PingTimeout   model.Duration `yaml:"ping_timeout,omitempty"`   // Default ping time out for hosts
	Timeout       model.Duration `yaml:"timeout,omitempty"`        // Default service IO timeout
	MaxBytes      uint64         `yaml:"max_bytes,omitempty"`      // Default maximum bytes to read from services
	PingDisable   bool           `yaml:"disable_ping,omitempty"`   // Disable ping checks by default
	PingCount     uint64         `yaml:"ping_count,omitempty"`     // Number of pings to send

	Hosts []HostConfig `yaml:"hosts"` // List of hosts which are to be polled

	XXX map[string]interface{} `yaml:",omitempty"` // Catch any unknown flags.

	OriginalConfig string // Original config file contents
}

func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultConfig

	type plain Config
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}

	// Propagate host defaults
	DefaultHostConfig.PollFrequency = c.PollFrequency
	DefaultHostConfig.PingTimeout = c.PingTimeout
	DefaultHostConfig.PingDisable = c.PingDisable
	DefaultHostConfig.PingCount = c.PingCount

	// Propagate service defaults
	DefaultBasicServiceConfig.Timeout = c.Timeout
	if c.TLSCACerts.CertPool != nil {
		DefaultBasicServiceConfig.TLSCACerts = c.TLSCACerts
	}
	DefaultChallengeResponseServiceConfig.MaxBytes = c.MaxBytes
	if c.TLSCACerts.CertPool != nil {
		DefaultChallengeResponseServiceConfig.TLSCACerts = c.TLSCACerts
	}
	DefaultHTTPServiceConfig.MaxBytes = c.MaxBytes
	if c.TLSCACerts.CertPool != nil {
		DefaultHTTPServiceConfig.TLSCACerts = c.TLSCACerts
	}

	// HACK: Double unmarshal so host config gets set defaults
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	return checkOverflow(c.XXX, "")
}

// IPNetwork is the config wrapper type for an IP Network.
type IPNetwork struct {
	net.IPNet
}

func (ipn *IPNetwork) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}

	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return errors.Wrapf(err, "IPNetwork.UnmarshalYAML failed: %s", s)
	}

	ipn.IPNet = *ipnet
	return nil
}

func (ipn IPNetwork) MarshalYAML() (interface{}, error) {
	return ipn.String(), nil
}

// Defines a host which we want to find service information about.
// Hosts export DNS checks.
type HostConfig struct {
	Hostname      string         `yaml:"hostname"`                 // Host or IP to contact
	PollFrequency model.Duration `yaml:"poll_frequency,omitempty"` // Frequency to poll this specific host
	PingDisable   bool           `yaml:"disable_ping,omitempty"`   // Disable ping checks for this host
	PingTimeout   model.Duration `yaml:"ping_timeout,omitempty"`   // Maximum ping timeout
	PingCount     uint64         `yaml:"ping_count,omitempty"`     // Number of pings to send each poll

	BasicChecks             []*BasicServiceConfig      `yaml:"basic_checks,omitempty"`
	ChallengeResponseChecks []*ChallengeResponseConfig `yaml:"challenge_response_checks,omitempty"`
	HTTPChecks              []*HTTPServiceConfig       `yaml:"http_checks,omitempty"`

	XXX map[string]interface{} `yaml:",omitempty"` // Catch any unknown flags.
}

func (c *HostConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultHostConfig

	type plain HostConfig
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	return checkOverflow(c.XXX, "hosts")
}

// A basic network service.
type BasicServiceConfig struct {
	Name       string             `yaml:"name"`                  // Name of the service
	Protocol   string             `yaml:"proto,omitempty"`       // TCP or UDP
	Port       uint64             `yaml:"port"`                  // Port number of the service
	Timeout    model.Duration     `yaml:"timeout,omitempty"`     // Number of seconds to wait for response
	TLSEnable  bool               `yaml:"tls,omitempty"`         // The service uses TLS
	TLSCACerts TLSCertificatePool `yaml:"tls_cacerts,omitempty"` // Path to CAfile to verify the service TLS with
	// MinimumFailures uint64		`yaml:"minimum_failures,omitempty` // Minimum number of failures before marking servie as down
}

// Ideally we'd use this, but go-yaml has problems with nested structs at the
// moment and I don't have time to debug them.

func (bsc *BasicServiceConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Prevent recursively calling unmarshal
	*bsc = DefaultBasicServiceConfig

	type plain BasicServiceConfig
	if err := unmarshal((*plain)(bsc)); err != nil {
		return err
	}

	return nil
}

// Similar to a banner check, but first sends the specified data befoe looking
// for a response.
type ChallengeResponseConfig struct {
	BasicServiceConfig `yaml:",inline,omitempty"`
	ChallengeLiteral   *Bytes  `yaml:"challenge,omitempty"`
	ResponseRegex      *Regexp `yaml:"response_re,omitempty"` // Regex that must match
	ResponseLiteral    *Bytes  `yaml:"response,omitempty"`    // Literal string that must match
	MaxBytes           uint64  `yaml:"max_bytes,omitempty"`   // Maximum number of bytes to read while looking for the response regex. 0 means read until connection closes.
}

type ChallengeResponseConfigValidationError struct {
	ServiceDescription string
}

func (r ChallengeResponseConfigValidationError) Error() string {
	return fmt.Sprintln("validation: requires at least 1 of response_re or response:", r.ServiceDescription)
}

func (chrc *ChallengeResponseConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Prevent recursively calling unmarshal
	*chrc = DefaultChallengeResponseServiceConfig

	type plain ChallengeResponseConfig
	if err := unmarshal((*plain)(chrc)); err != nil {
		return err
	}

	return nil
}

//nolint:gomnd,cyclop

//nolint:nilnil

//nolint:nilnil

func checkOverflow(m map[string]interface{}, ctx string) error {
	if len(m) > 0 {
		var keys []string
		for k := range m {
			keys = append(keys, k)
		}
		return errors.Wrapf(ErrUnknownFields, "%s: %s", ctx, strings.Join(keys, ", "))
	}
	return nil
}
