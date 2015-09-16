// This is similar to the main Prometheus scheme, because hey, it works pretty well.

package config
import (
	//"github.com/prometheus/client_golang/prometheus"
	"io/ioutil"
	"gopkg.in/yaml.v2"
	"time"
	"github.com/prometheus/prometheus/util/strutil"
	"regexp"
)

var (
	DefaultConfig Config = Config{
		PollFrequency: Duration(30 * time.Second),
	}

	DefaultHostConfig HostConfig = HostConfig{
		PollFrequency: DefaultConfig.PollFrequency,
	}
)

func Load(s string) (*Config, error) {
	cfg := new(Config)

	// Important: we treat the yaml file as a big list, and unmarshal to our
	// big list here.
	err := yaml.Unmarshal([]byte(s), &cfg)
	if err != nil {
		return nil, err
	}
	cfg.OriginalConfig = s
	return cfg, nil
}

func LoadFromFile(filename string) (*Config, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return Load(string(content))
}

type Config struct {
	PollFrequency Duration `yaml:poll_frequency,omitempty` // Default polling frequency
	Hosts []HostConfig	`yaml:hosts`// List of hosts which are to be polled

	XXX map[string]interface{} `yaml`	// Catch any unknown flags.

	OriginalConfig string	// Original config file contents
}

func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultConfig

	type plain Config
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}

	// Propagate poll frequency
	DefaultHostConfig.PollFrequency = c.PollFrequency
	return nil
}

// Defines a host which we want to find service information about.
// Hosts export DNS checks.
type HostConfig struct {
	Hostname string		`yaml:"hostname"`	// Host or IP to contact
	PollFrequency Duration `yaml:"poll_frequency,omitempty"` // Frequency to poll this specific host
	PingDisable bool `yaml:"no_ping,omitempty"`	// Disable ping checks for this host
	PingTimeout Duration `yaml:"ping_timeout"` // Maximum ping timeout

	BasicChecks []*BasicServiceConfig	`yaml:"basic_checks,omitempty"`
	ChallengeResponseChecks []*ChallengeResponseConfig	`yaml:"challenge_reponse_checks,omitempty"`
	HTTPChecks []*HTTPServiceConfig	`yaml:"http_checks,omitempty"`

	XXX map[string]interface{} `yaml`	// Catch any unknown flags.
}

func (c *HostConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultHostConfig

	type plain HostConfig
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	return nil
}

// A basic network service.
type BasicServiceConfig struct {
	Name		string			`yaml:"name"`		// Name of the service
	Protocol	string			`yaml:"proto"`		// TCP or UDP
	Port		uint64			`yaml:"port"`		// Port number of the service
	Timeout		Duration		`yaml:"timeout"`		// Number of seconds to wait for response
	UseSSL		bool			`yaml:"ssl,omitempty"`		// The service uses SSL

	XXX map[string]interface{} `yaml`	// Catch any unknown flags.
}

// Similar to a banner check, but first sends the specified data befoe looking
// for a response.
type ChallengeResponseConfig struct {
	ChallengeLiteral string		`yaml:"challenge,omitempty"`
	ResponseRegex	*regexp.Regexp		`yaml:"response_re,omitempty"`// Regex that must match
	ResponseLiteral []byte		`yaml:"response,omitempty"`// Literal string that must match
	MaxBytes uint64				`yaml:"max_bytes,omitempty"` // Maximum number of bytes to read while looking for the response regex. 0 means read until connection closes.
	BasicServiceConfig
}

func (this ChallengeResponseConfig) UnmarshalYAML() (interface{}, error) {
	if err := unmarshal(&this); err != nil {
		return err
	}

	// Validate that at least 1 response condition exists
	if this.ResponseRegex == nil && this.ResponseLiteral == "" {
		return
	}

	return nil
}

// An HTTP speaking service
type HTTPServiceConfig struct {
	Verb	string	// HTTP verb to use
	Host 	string	// HTTP Host header to set
	QueryString	string	// Query string including URL params
	BasicAuth bool	// Use HTTP basic auth
	Username string	// Username for HTTP basic auth
	Password string // Password for HTTP basic auth
	BasicServiceConfig
}

// Borrowed from the Prometheus config logic
type Duration time.Duration

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (d *Duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	dur, err := strutil.StringToDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(dur)
	return nil
}

// MarshalYAML implements the yaml.Marshaler interface.
func (d Duration) MarshalYAML() (interface{}, error) {
	return strutil.DurationToString(time.Duration(d)), nil
}

type Regexp regexp.Regexp

func (r *Regexp) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	rx, err := regexp.Compile(s)
	if err != nil {
		return err
	}
	*r = Regexp(rx)
	return nil
}
