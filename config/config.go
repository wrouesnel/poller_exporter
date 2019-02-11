// This is similar to the main Prometheus scheme, because hey, it works pretty well.

package config

import (
	//"github.com/prometheus/client_golang/prometheus"
	"io/ioutil"
	"time"

	. "github.com/prometheus/common/model"
	"gopkg.in/yaml.v2"

	//"errors"
	//"strconv"
	"fmt"
	"strings"
)

var (
	DefaultConfig PollerExporterConfig = PollerExporterConfig{
		PollFrequency: Duration(30 * time.Second),
	}

	DefaultHostConfig HostConfig = HostConfig{
		PollInterval: DefaultConfig.PollFrequency,
	}

	DefaultBasicServiceConfig = BasicServiceConfig{
		Protocol: "tcp",
		//MinimumFailures: 1,
	}

	DefaultChallengeResponseServiceConfig = ChallengeResponseConfig{
		BasicServiceConfig: DefaultBasicServiceConfig,
	}

	DefaultHTTPServiceConfig = HTTPServiceConfig{
		ChallengeResponseConfig: DefaultChallengeResponseServiceConfig,
	}
)

func Load(s string) (*PollerExporterConfig, error) {
	cfg := new(PollerExporterConfig)
	*cfg = DefaultConfig

	// Important: we treat the yaml file as a big list, and unmarshal to our
	// big list here.
	err := yaml.Unmarshal([]byte(s), cfg)
	if err != nil {
		return nil, err
	}
	cfg.OriginalConfig = s
	return cfg, nil
}

func LoadFromFile(filename string) (*PollerExporterConfig, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return Load(string(content))
}

func Save(cfg *PollerExporterConfig) ([]byte, error) {
	out, err := yaml.Marshal(cfg)
	return out, err
}

type PollerExporterConfig struct {
	BasicAuthUsername string `yaml:"username,omitempty"` // If set, enables basic auth
	BasicAuthPassword string `yaml:"password,omitempty"` // If set, enables basic auth (must have a username)

	TLSCertificatePath string `yaml:"tls_cert,omitempty"` // Path to TLS certificate. Enables TLS if specified.
	TLSKeyPath         string `yaml:"tls_key,omitempty"`  // Path to TLS key file. Enables TLS if specified.

	PollFrequency Duration `yaml:"poll_frequency,omitempty"` // Default polling frequency for hosts
	PingTimeout   Duration `yaml:"ping_timeout,omitempty"`   // Default ping time out for hosts
	Timeout       Duration `yaml:"timeout,omitempty"`        // Default service IO timeout
	MaxBytes      uint64   `yaml:"max_bytes,omitempty"`      // Default maximum bytes to read from services
	PingDisable   bool     `yaml:"disable_ping,omitempty"`   // Disable ping checks by default
	PingCount     uint64   `yaml:"ping_count,omitempty"`     // Number of pings to send

	Hosts []HostConfig `yaml:"hosts"` // List of hosts which are to be polled

	XXX map[string]interface{} `yaml:",omitempty"` // Catch any unknown flags.

	OriginalConfig string // Original config file contents
}

func (c *PollerExporterConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultConfig

	type plain PollerExporterConfig
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}

	// Propagate host defaults
	DefaultHostConfig.PollInterval = c.PollFrequency
	DefaultHostConfig.PingTimeout = c.PingTimeout
	DefaultHostConfig.PingDisable = c.PingDisable
	DefaultHostConfig.PingCount = c.PingCount

	// Propagate service defaults
	DefaultBasicServiceConfig.Timeout = c.Timeout
	DefaultChallengeResponseServiceConfig.MaxBytes = c.MaxBytes
	DefaultHTTPServiceConfig.MaxBytes = c.MaxBytes

	// HACK: Double unmarshal so host config gets set defaults
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	return checkOverflow(c.XXX, "")
}

// Defines a host which we want to find service information about.
// Hosts export DNS checks.
type HostConfig struct {
	Hostname     string   `yaml:"hostname"`                 // Host or IP to contact
	PollInterval Duration `yaml:"poll_frequency,omitempty"` // Frequency to poll this specific host
	PingDisable  bool     `yaml:"disable_ping,omitempty"`   // Disable ping checks for this host
	PingTimeout  Duration `yaml:"ping_timeout,omitempty"`   // Maximum ping timeout
	PingCount    uint64   `yaml:"ping_count,omitempty"`     // Number of pings to send each poll

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

// BasicServiceConfig configures a simple port check of a service
type BasicServiceConfig struct {
	Name     string   `yaml:"name"`              // Name of the service
	Protocol string   `yaml:"proto,omitempty"`   // TCP or UDP
	Port     uint64   `yaml:"port"`              // Port number of the service
	Timeout  Duration `yaml:"timeout,omitempty"` // Number of seconds to wait for response
	UseSSL   bool     `yaml:"ssl,omitempty"`     // The service uses SSL
	//MinimumFailures uint64		`yaml:"minimum_failures,omitempty` // Minimum number of failures before marking servie as down
}

// Copy produces a distinct memory copy of the struct
func (this *BasicServiceConfig) Copy() *BasicServiceConfig {
	c := &BasicServiceConfig{}
	c.Name = this.Name
	c.Protocol = this.Protocol
	c.Port = this.Port
	c.Timeout = this.Timeout
	c.UseSSL = this.UseSSL
	return c
}

// UnmarshalYAML implements the yaml.Unmarshaler interface
func (this *BasicServiceConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Prevent recursively calling unmarshal
	*this = *DefaultBasicServiceConfig.Copy()
	type plain BasicServiceConfig
	if err := unmarshal((*plain)(this)); err != nil {
		return err
	}

	return nil
}

// ChallengeResponseConfig implements a check type which sends some data before looking for a response.
type ChallengeResponseConfig struct {
	BasicServiceConfig `yaml:",inline,omitempty"`
	ChallengeLiteral   *Bytes  `yaml:"challenge,omitempty"`
	ResponseRegex      *Regexp `yaml:"response_re,omitempty"` // Regex that must match
	ResponseLiteral    *Bytes  `yaml:"response,omitempty"`    // Literal string that must match
	MaxBytes           uint64  `yaml:"max_bytes,omitempty"`   // Maximum number of bytes to read while looking for the response regex. 0 means read until connection closes.
}

func (this *ChallengeResponseConfig) Copy() *ChallengeResponseConfig {
	c := &ChallengeResponseConfig{}
	c.BasicServiceConfig = *DefaultChallengeResponseServiceConfig.BasicServiceConfig.Copy()
	c.ChallengeLiteral = this.ChallengeLiteral.Copy()
	c.ResponseLiteral = this.ResponseLiteral.Copy()
	c.MaxBytes = this.MaxBytes
	return c
}

// ChallengeResponseConfigValidationError emitted when a service config is invalid
type ChallengeResponseConfigValidationError struct {
	ServiceDescription string
}

func (r ChallengeResponseConfigValidationError) Error() string {
	return fmt.Sprintln("validation: requires at least 1 of response_re or response:", r.ServiceDescription)
}

func (this *ChallengeResponseConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Prevent recursively calling unmarshal
	*this = *DefaultChallengeResponseServiceConfig.Copy()

	type plain ChallengeResponseConfig
	if err := unmarshal((*plain)(this)); err != nil {
		return err
	}

	// Validate the challenge literal
	if this.ResponseLiteral == nil && this.ResponseRegex == nil {
		return &ChallengeResponseConfigValidationError{this.Name}
	}

	return nil
}

// HTTPServiceConfig configures checks for an an HTTP speaking service.
// If UseSSL is not set but you request HTTPS, it'll fail.
type HTTPServiceConfig struct {
	ChallengeResponseConfig `yaml:",inline,omitempty"`
	Verb                    string          `yaml:"verb,omitempty"`           // HTTP verb to use
	Url                     URL             `yaml:"url,omitempty"`            // HTTP request URL to send
	SuccessStatuses         HTTPStatusRange `yaml:"success_status,omitempty"` // List of status codes indicating success
	BasicAuth               bool            `yaml:"auth,omitempty"`           // Use HTTP basic auth
	Username                string          `yaml:"username,omitempty"`       // Username for HTTP basic auth
	Password                string          `yaml:"password,omitempty"`       // Password for HTTP basic auth
}

// UnmarshalYAML implements yaml.Unmarshaler
func (this *HTTPServiceConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*this = DefaultHTTPServiceConfig

	type plain HTTPServiceConfig

	if err := unmarshal((*plain)(this)); err != nil {
		return err
	}

	return nil
}

// checkOverflow checks if unknown keys are specified in a given map.
func checkOverflow(m map[string]interface{}, ctx string) error {
	if len(m) > 0 {
		var keys []string
		for k := range m {
			keys = append(keys, k)
		}
		return fmt.Errorf("unknown fields in %s: %s", ctx, strings.Join(keys, ", "))
	}
	return nil
}
