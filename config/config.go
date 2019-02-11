// This is similar to the main Prometheus scheme, because hey, it works pretty well.

package config

import (
	//"github.com/prometheus/client_golang/prometheus"
	. "github.com/prometheus/common/model"
	"gopkg.in/yaml.v2"
	"io/ioutil"

	//"errors"
	//"strconv"
	"fmt"
	"strings"
)

func Load(s string) (*PollerExporterConfig, error) {
	cfg := new(PollerExporterConfig)
	//*cfg = DefaultConfig

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

// HostCommonConfig encapculates the common host configuration options
type HostCommonConfig struct {
	PollInterval Duration `yaml:"poll_interval,omitempty"` // Default polling frequency for hosts
	PingDisable  bool     `yaml:"disable_ping,omitempty"`  // Disable ping checks by default
	PingTimeout  Duration `yaml:"ping_timeout,omitempty"`  // Default ping time out for hosts
	PingCount    uint64   `yaml:"ping_count,omitempty"`    // Number of pings to send
}

// PollerCommonConfig is the set of configuration which is common to all pollers
type PollerCommonConfig struct {
	Timeout  Duration `yaml:"timeout,omitempty"`   // Default service IO timeout
	MaxBytes uint64   `yaml:"max_bytes,omitempty"` // Default maximum bytes to read from services
}

type PollerExporterConfig struct {
	BasicAuthUsername string `yaml:"username,omitempty"` // If set, enables basic auth
	BasicAuthPassword string `yaml:"password,omitempty"` // If set, enables basic auth (must have a username)

	TLSCertificatePath string `yaml:"tls_cert,omitempty"` // Path to TLS certificate. Enables TLS if specified.
	TLSKeyPath         string `yaml:"tls_key,omitempty"`  // Path to TLS key file. Enables TLS if specified.

	GlobalHostConfig   *HostCommonConfig   `yaml:"global_host_config,omitempty"`
	GlobalPollerConfig *PollerCommonConfig `yaml:"global_poller_config,omitempty"`

	Hosts []HostConfig `yaml:"hosts"` // List of hosts which are to be polled

	XXX map[string]interface{} `yaml:",omitempty"` // Catch any unknown flags.

	OriginalConfig string // Original config file contents
}

// UnmarshalYAML implements the yaml.Unmarshaller interface.
// For a PollerExporterConfig this interface actually handles the entire unmarshalling so that
// global configuration can be correctly propagated.
func (c *PollerExporterConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Do a natural unmarshal first
	type plain PollerExporterConfig
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}

	return checkOverflow(c.XXX, "")
}

// Defines a host which we want to find service information about.
// Hosts export DNS checks.
type HostConfig struct {
	HostConfig   *HostCommonConfig   `yaml:"host_config,omitempty"`
	PollerConfig *PollerCommonConfig `yaml:"poller_config,omitempty"`

	Hostname string `yaml:"hostname"` // Host or IP to contact

	BasicChecks             []*BasicServiceConfig      `yaml:"basic_checks,omitempty"`
	ChallengeResponseChecks []*ChallengeResponseConfig `yaml:"challenge_response_checks,omitempty"`
	HTTPChecks              []*HTTPServiceConfig       `yaml:"http_checks,omitempty"`

	XXX map[string]interface{} `yaml:",omitempty"` // Catch any unknown flags.
}

func (c *HostConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain HostConfig
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	return checkOverflow(c.XXX, "hosts")
}

// BasicServiceConfig configures a simple port check of a service
type BasicServiceConfig struct {
	Name     string   `yaml:"name"`               // Name of the service
	Protocol string   `yaml:"protocol,omitempty"` // TCP or UDP
	Port     uint64   `yaml:"port"`               // Port number of the service
	Timeout  Duration `yaml:"timeout,omitempty"`  // Number of seconds to wait for response
	UseSSL   bool     `yaml:"ssl,omitempty"`      // The service uses SSL
	//MinimumFailures uint64		`yaml:"minimum_failures,omitempty` // Minimum number of failures before marking servie as down
	XXX map[string]interface{} `yaml:",omitempty"` // Catch any unknown flags.
}

// Copy produces a distinct memory copy of the struct
func (bsc *BasicServiceConfig) Copy() *BasicServiceConfig {
	c := &BasicServiceConfig{}
	c.Name = bsc.Name
	c.Protocol = bsc.Protocol
	c.Port = bsc.Port
	c.Timeout = bsc.Timeout
	c.UseSSL = bsc.UseSSL
	return c
}

// UnmarshalYAML implements the yaml.Unmarshaler interface
func (bsc *BasicServiceConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Prevent recursively calling unmarshal
	type plain BasicServiceConfig
	if err := unmarshal((*plain)(bsc)); err != nil {
		return err
	}

	checkOverflow(bsc.XXX, bsc.Name)
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

func (crpc *ChallengeResponseConfig) Copy() *ChallengeResponseConfig {
	c := &ChallengeResponseConfig{}
	c.BasicServiceConfig = *crpc.BasicServiceConfig.Copy()
	c.ChallengeLiteral = crpc.ChallengeLiteral.Copy()
	c.ResponseRegex = crpc.ResponseRegex.Copy()
	c.ResponseLiteral = crpc.ResponseLiteral.Copy()
	c.MaxBytes = crpc.MaxBytes
	return c
}

// ChallengeResponseConfigValidationError emitted when a service config is invalid
type ChallengeResponseConfigValidationError struct {
	ServiceDescription string
}

func (r ChallengeResponseConfigValidationError) Error() string {
	return fmt.Sprintln("validation: requires at least 1 of response_re or response:", r.ServiceDescription)
}

func (crpc *ChallengeResponseConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	bsc := &BasicServiceConfig{}

	type plain1 BasicServiceConfig
	if err := unmarshal((*plain1)(bsc)); err != nil {
		return err
	}

	type plain ChallengeResponseConfig
	if err := unmarshal((*plain)(crpc)); err != nil {
		return err
	}

	// Set the basic service config in
	crpc.BasicServiceConfig = *bsc

	// Validate the challenge literal
	if crpc.ResponseLiteral == nil && crpc.ResponseRegex == nil {
		return &ChallengeResponseConfigValidationError{crpc.Name}
	}

	checkOverflow(crpc.XXX, crpc.Name)

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

// Copy makes a memory independent copy, safe for use with channels
func (hsc *HTTPServiceConfig) Copy() *HTTPServiceConfig {
	c := &HTTPServiceConfig{}
	c.ChallengeResponseConfig = *hsc.ChallengeResponseConfig.Copy()
	c.Verb = hsc.Verb
	c.Url = hsc.Url.Copy()
	c.SuccessStatuses = hsc.SuccessStatuses.Copy()
	c.BasicAuth = hsc.BasicAuth
	c.Username = hsc.Username
	c.Password = hsc.Password
	return c
}

// UnmarshalYAML implements yaml.Unmarshaler
func (hsc *HTTPServiceConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	bsc := &ChallengeResponseConfig{}

	type plain1 ChallengeResponseConfig
	if err := unmarshal((*plain1)(bsc)); err != nil {
		return err
	}

	type plain HTTPServiceConfig

	if err := unmarshal((*plain)(hsc)); err != nil {
		return err
	}

	// Set the challenge response component
	hsc.ChallengeResponseConfig = *bsc

	checkOverflow(hsc.XXX, hsc.Name)

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
