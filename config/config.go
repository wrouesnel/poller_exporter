// This is similar to the main Prometheus scheme, because hey, it works pretty well.

package config
import (
	//"github.com/prometheus/client_golang/prometheus"
	"io/ioutil"
	"gopkg.in/yaml.v2"
	"time"
	"github.com/prometheus/prometheus/util/strutil"
	"regexp"
	//"errors"
	//"strconv"
	"fmt"
	"strings"
	"net/url"
	//"github.com/prometheus/log"
	//"github.com/davecgh/go-spew/spew"
)

var (
	DefaultConfig Config = Config{
		PollFrequency: Duration(30 * time.Second),
	}

	DefaultHostConfig HostConfig = HostConfig{
		PollFrequency: DefaultConfig.PollFrequency,
	}

	DefaultBasicServiceConfig = BasicServiceConfig{
		Protocol: "tcp",
	}

	DefaultChallengeResponseServiceConfig = ChallengeResponseConfig{
		BasicServiceConfig: DefaultBasicServiceConfig,
	}

	DefaultHTTPServiceConfig = HTTPServiceConfig{
		ChallengeResponseConfig: DefaultChallengeResponseServiceConfig,
	}
)

func Load(s string) (*Config, error) {
	cfg := new(Config)
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

func LoadFromFile(filename string) (*Config, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return Load(string(content))
}

func Save(cfg *Config) ([]byte, error) {
	out, err := yaml.Marshal(cfg)
	return out, err
}

type Config struct {
	PollFrequency Duration `yaml:"poll_frequency,omitempty"` // Default polling frequency for hosts
	PingTimeout	Duration `yaml:"ping_timeout,omitempty"` // Default ping time out for hosts
	Timeout Duration `yaml:"timeout,omitempty"`	// Default service IO timeout
	MaxBytes uint64		`yaml:"max_bytes,omitempty"` // Default maximum bytes to read from services
	PingDisable bool `yaml:"disable_ping,omitempty"`	// Disable ping checks by default

	Hosts []HostConfig	`yaml:"hosts"`// List of hosts which are to be polled

	XXX map[string]interface{} `yaml:",omitempty"`	// Catch any unknown flags.

	OriginalConfig string	// Original config file contents
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
	Hostname string		`yaml:"hostname"`	// Host or IP to contact
	PollFrequency Duration `yaml:"poll_frequency,omitempty"` // Frequency to poll this specific host
	PingDisable bool `yaml:"disable_ping,omitempty"`	// Disable ping checks for this host
	PingTimeout Duration `yaml:"ping_timeout"` // Maximum ping timeout

	BasicChecks []*BasicServiceConfig	`yaml:"basic_checks,omitempty"`
	ChallengeResponseChecks []*ChallengeResponseConfig	`yaml:"challenge_response_checks,omitempty"`
	HTTPChecks []*HTTPServiceConfig	`yaml:"http_checks,omitempty"`

	XXX map[string]interface{} `yaml:",omitempty"`	// Catch any unknown flags.
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
	Name		string			`yaml:"name"`		// Name of the service
	Protocol	string			`yaml:"proto,omitempty"`		// TCP or UDP
	Port		uint64			`yaml:"port"`		// Port number of the service
	Timeout		Duration		`yaml:"timeout,omitempty"`		// Number of seconds to wait for response
	UseSSL		bool			`yaml:"ssl,omitempty"`		// The service uses SSL

	XXX map[string]interface{} 	`yaml:",omitempty"`	// Catch any unknown flags.
}

// Ideally we'd use this, but go-yaml has problems with nested structs at the
// moment and I don't have time to debug them.

//func (this *BasicServiceConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
//	// Prevent recursively calling unmarshal
//	*this = DefaultBasicServiceConfig
//	fmt.Println()
//	type plain BasicServiceConfig
//	if err := unmarshal((*plain)(this)); err != nil {
//		return err
//	}
//
//	return nil
//}

// Similar to a banner check, but first sends the specified data befoe looking
// for a response.
type ChallengeResponseConfig struct {
	BasicServiceConfig			`yaml:",inline,omitempty"`
	ChallengeLiteral *Bytes		`yaml:"challenge,omitempty"`
	ResponseRegex	*Regexp		`yaml:"response_re,omitempty"`// Regex that must match
	ResponseLiteral *Bytes		`yaml:"response,omitempty"`// Literal string that must match
	MaxBytes uint64				`yaml:"max_bytes,omitempty"` // Maximum number of bytes to read while looking for the response regex. 0 means read until connection closes.
}

type ChallengeResponseConfigValidationError struct {}
func (r ChallengeResponseConfigValidationError) Error() string {
	return "validation: requires at least 1 of response_re or response"
}

//func (this *ChallengeResponseConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
//	// Prevent recursively calling unmarshal
//	*this = DefaultChallengeResponseServiceConfig
//
//	type plain ChallengeResponseConfig
//	if err := unmarshal((*plain)(this)); err != nil {
//		return err
//	}
//
//	if err := unmarshal((*plain)(this)); err != nil {
//		return err
//	}
//
//	//spew.Print(*this)
//
////	// Validate that at least 1 response condition exists
////	if this.ResponseRegex == nil && this.ResponseLiteral == nil {
////		return error(ChallengeResponseConfigValidationError{})
////	}
//
//	return nil
//}

// An HTTP speaking service. Does not yet support being a proxy.
// If UseSSL is not set but you request HTTPS, it'll fail.
type HTTPServiceConfig struct {
	ChallengeResponseConfig 	`yaml:",inline,omitempty"`
	Verb	string		`yaml:"verb,omitempty"` // HTTP verb to use
	Url		URL			`yaml:"url,omitempty"`	// HTTP request URL to send
	SuccessStatuses []int `yaml:"success_status,omitempty"` // List of status codes indicating success
	BasicAuth bool		`yaml:"auth,omitempty"` // Use HTTP basic auth
	Username string		`yaml:"username,omitempty"` // Username for HTTP basic auth
	Password string 	`yaml:"password,omitempty"` // Password for HTTP basic auth
}

//func (this *HTTPServiceConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
//	*this = DefaultHTTPServiceConfig
//
//	type plain HTTPServiceConfig
//	if err := unmarshal((*plain)(this)); err != nil {
//		log.Debugln(err)
//		return err
//		switch err.(type) {
//		default:
//			return err
//		case ChallengeResponseConfigValidationError:
//			// Allowed since HTTP may have no matchers
//			break
//		}
//	}
//
//	return nil
//}

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

func (d Duration) String() string {
	return strutil.DurationToString(time.Duration(d))
}

// Implements a custom []byte slice so we can unmarshal one from an escaped string
type Bytes []byte

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (this *Bytes) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}

	*this = Bytes(s)
	return nil
}

// MarshalYAML implements the yaml.Marshaler interface.
func (this *Bytes) MarshalYAML() (interface{}, error) {
	if len(*this) != 0 {
		return string(*this), nil
	}
	return nil,nil
}

// Regexp encapsulates a regexp.Regexp and makes it YAML marshallable.
type Regexp struct {
	regexp.Regexp
	original string
}

// NewRegexp creates a new anchored Regexp and returns an error if the
// passed-in regular expression does not compile.
func NewRegexp(s string) (*Regexp, error) {
	regex, err := regexp.Compile(s)
	if err != nil {
		return nil, err
	}
	return &Regexp{
		Regexp:   *regex,
		original: s,
	}, nil
}

// MustNewRegexp works like NewRegexp, but panics if the regular expression does not compile.
func MustNewRegexp(s string) *Regexp {
	re, err := NewRegexp(s)
	if err != nil {
		panic(err)
	}
	return re
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (re *Regexp) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	r, err := NewRegexp(s)
	if err != nil {
		return err
	}
	*re = *r
	return nil
}

// MarshalYAML implements the yaml.Marshaler interface.
func (re *Regexp) MarshalYAML() (interface{}, error) {
	if re != nil {
		return re.original, nil
	}
	return nil, nil
}

// URL is a custom URL type that allows validation at configuration load time.
type URL struct {
	*url.URL
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for URLs.
func (u *URL) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}

	urlp, err := url.Parse(s)
	if err != nil {
		return err
	}
	u.URL = urlp
	return nil
}

// MarshalYAML implements the yaml.Marshaler interface for URLs.
func (u URL) MarshalYAML() (interface{}, error) {
	if u.URL != nil {
		return u.String(), nil
	}
	return nil, nil
}

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