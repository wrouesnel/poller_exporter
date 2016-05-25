// This is similar to the main Prometheus scheme, because hey, it works pretty well.

package config
import (
	//"github.com/prometheus/client_golang/prometheus"
	"io/ioutil"
	"gopkg.in/yaml.v2"
	"time"
	. "github.com/prometheus/common/model"
	"regexp"
	//"errors"
	//"strconv"
	"fmt"
	"strings"
	"net/url"
	//"github.com/prometheus/common/log"
	//"github.com/davecgh/go-spew/spew"
	//"github.com/prometheus/common/log"
	"strconv"
	"sort"
	"net"
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
		//MinimumFailures: 1,
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
	BasicAuthUsername string `yaml:"username,omitempty"`	// If set, enables basic auth
	BasicAuthPassword string `yaml:"password,omitempty"` // If set, enables basic auth (must have a username)

	TLSCertificatePath string `yaml:"tls_cert,omitempty"` // Path to TLS certificate. Enables TLS if specified.
	TLSKeyPath string `yaml:"tls_key,omitempty"` // Path to TLS key file. Enables TLS if specified.

	PollFrequency Duration `yaml:"poll_frequency,omitempty"` // Default polling frequency for hosts
	PingTimeout	Duration `yaml:"ping_timeout,omitempty"` // Default ping time out for hosts
	Timeout Duration `yaml:"timeout,omitempty"`	// Default service IO timeout
	MaxBytes uint64		`yaml:"max_bytes,omitempty"` // Default maximum bytes to read from services
	PingDisable bool `yaml:"disable_ping,omitempty"`	// Disable ping checks by default
	PingCount uint64 `yaml:"ping_count,omitempty"`	// Number of pings to send

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

// Config wrapper type for an IP Network
type IPNetwork struct {
	net.IPNet
}

func (this *IPNetwork) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}

	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return err
	}

	this.IPNet = *ipnet
	return nil
}

func (this IPNetwork) MarshalYAML() (interface{}, error) {
	return this.String(), nil
}

// Defines a host which we want to find service information about.
// Hosts export DNS checks.
type HostConfig struct {
	Hostname string		`yaml:"hostname"`	// Host or IP to contact
	PollFrequency Duration `yaml:"poll_frequency,omitempty"` // Frequency to poll this specific host
	PingDisable bool `yaml:"disable_ping,omitempty"`	// Disable ping checks for this host
	PingTimeout Duration `yaml:"ping_timeout,omitempty"` // Maximum ping timeout
	PingCount uint64 `yaml:"ping_count,omitempty"`	// Number of pings to send each poll

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
	//MinimumFailures uint64		`yaml:"minimum_failures,omitempty` // Minimum number of failures before marking servie as down
}

// Ideally we'd use this, but go-yaml has problems with nested structs at the
// moment and I don't have time to debug them.

func (this *BasicServiceConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Prevent recursively calling unmarshal
	*this = DefaultBasicServiceConfig
	fmt.Println()
	type plain BasicServiceConfig
	if err := unmarshal((*plain)(this)); err != nil {
		return err
	}

	return nil
}

// Similar to a banner check, but first sends the specified data befoe looking
// for a response.
type ChallengeResponseConfig struct {
	BasicServiceConfig			`yaml:",inline,omitempty"`
	ChallengeLiteral *Bytes		`yaml:"challenge,omitempty"`
	ResponseRegex	*Regexp		`yaml:"response_re,omitempty"`// Regex that must match
	ResponseLiteral *Bytes		`yaml:"response,omitempty"`// Literal string that must match
	MaxBytes uint64				`yaml:"max_bytes,omitempty"` // Maximum number of bytes to read while looking for the response regex. 0 means read until connection closes.
}

type ChallengeResponseConfigValidationError struct {
	ServiceDescription string
}
func (r ChallengeResponseConfigValidationError) Error() string {
	return fmt.Sprintln("validation: requires at least 1 of response_re or response:", r.ServiceDescription)
}

func (this *ChallengeResponseConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Prevent recursively calling unmarshal
	*this = DefaultChallengeResponseServiceConfig

	type plain ChallengeResponseConfig
	if err := unmarshal((*plain)(this)); err != nil {
		return err
	}

	return nil
}

// A range of HTTP status codes which can be specifid in YAML using human-friendly
// ranging notation
type HTTPStatusRange map[int]bool
func (this *HTTPStatusRange) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*this = make(HTTPStatusRange)
	var ranges string
	var statusCodes []int

	if err := unmarshal(&ranges); err != nil {
		return err
	}

	fields := strings.Fields(ranges)

	for _, v := range fields {
		code, err := strconv.ParseInt(v, 10, 32)
		if err == nil {
			statusCodes = append(statusCodes, int(code))
			continue
		}
		// Didn't work, but might be a range
		if strings.Count(v, "-") == 0 || strings.Count(v, "-") > 1 {
			return err // Not a valid range
		}
		// Is a range.
		statusRange := strings.Split(v, "-")
		startCode, err := strconv.ParseInt(statusRange[0], 10, 32)
		if err != nil {
			return err
		}

		endCode, err := strconv.ParseInt(statusRange[1], 10, 32)
		if err != nil {
			return err
		}

		// Loop over the codes in sequential order
		if startCode < endCode {
			for i := startCode; i < endCode+1; i++ {
				statusCodes = append(statusCodes, int(i))
			}
		} else {
			for i := startCode; i > endCode-1; i-- {
				statusCodes = append(statusCodes, int(i))
			}
		}
	}

	for _, v := range statusCodes {
		(*this)[v] = true
	}
	return nil
}

// MarshalYAML implements the yaml.Marshaler interface.
func (this HTTPStatusRange) MarshalYAML() (interface{}, error) {
	var statusCodes []int
	var output []string
	for k, _ := range this {
		statusCodes = append(statusCodes, k)
	}

	sort.Ints(statusCodes)

	// This could probably be neater, but its what you get when you iterate.
	idx := 0
	for {
		start := statusCodes[idx]
		prev := start
		for {
			idx++
			if idx >= len(statusCodes) {
				break
			}
			if statusCodes[idx] - prev != 1 {
				// Check if it's a single number
				if statusCodes[idx-1] == start {
					output = append(output, fmt.Sprintf("%d", start))
				} else {
					output = append(output, fmt.Sprintf("%d-%d", start, statusCodes[idx-1]))
				}
				break
			}
			prev = statusCodes[idx]
		}
		if idx >= len(statusCodes) {
			break
		}
	}

	return strings.Join(output, " "), nil
}

// An HTTP speaking service. Does not yet support being a proxy.
// If UseSSL is not set but you request HTTPS, it'll fail.
type HTTPServiceConfig struct {
	ChallengeResponseConfig 	`yaml:",inline,omitempty"`
	Verb	string		`yaml:"verb,omitempty"` // HTTP verb to use
	Url		URL			`yaml:"url,omitempty"`	// HTTP request URL to send
	SuccessStatuses HTTPStatusRange `yaml:"success_status,omitempty"` // List of status codes indicating success
	BasicAuth bool		`yaml:"auth,omitempty"` // Use HTTP basic auth
	Username string		`yaml:"username,omitempty"` // Username for HTTP basic auth
	Password string 	`yaml:"password,omitempty"` // Password for HTTP basic auth
}

func (this *HTTPServiceConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*this = DefaultHTTPServiceConfig

	type plain HTTPServiceConfig

	if err := unmarshal((*plain)(this)); err != nil {
		return err
	}

	return nil
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