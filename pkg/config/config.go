// This is similar to the main Prometheus scheme, because hey, it works pretty well.

//nolint:tagliatelle,exhaustruct,gochecknoglobals,cyclop,varnamelen
package config

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wrouesnel/poller_exporter/pkg/errutils"
	"go.uber.org/zap"

	"github.com/pkg/errors"
	"github.com/prometheus/common/model"

	"gopkg.in/yaml.v3"
)

const DefaultPollFrequency = 30 * time.Second
const TLSCACertsSystem string = "system"

var (
	DefaultConfig Config = Config{
		PollFrequency: model.Duration(DefaultPollFrequency),
	}

	DefaultHostConfig HostConfig = HostConfig{
		PollFrequency: DefaultConfig.PollFrequency,
	}

	DefaultBasicServiceConfig = BasicServiceConfig{
		Protocol: "tcp",
		//MinimumFailures: 1,
		TLSCACerts: TLSCertificatePool{
			CertPool: errutils.Must(x509.SystemCertPool()),
			original: []string{TLSCACertsSystem},
		},
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

func Load(s string) (*Config, error) {
	cfg := new(Config)
	*cfg = DefaultConfig

	// Important: we treat the yaml file as a big list, and unmarshal to our
	// big list here.
	err := yaml.Unmarshal([]byte(s), cfg)
	if err != nil {
		return nil, errors.Wrap(err, "Load config failed")
	}
	cfg.OriginalConfig = s
	return cfg, nil
}

func LoadFromFile(filename string) (*Config, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrapf(err, "LoadFromFile failed: %s", filename)
	}
	return Load(string(content))
}

func Save(cfg *Config) ([]byte, error) {
	out, err := yaml.Marshal(cfg)
	return out, errors.Wrap(err, "Config.Save failed")
}

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
	DefaultChallengeResponseServiceConfig.MaxBytes = c.MaxBytes
	DefaultHTTPServiceConfig.MaxBytes = c.MaxBytes

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

// HTTPStatusRange is a range of HTTP status codes which can be specifid in YAML using human-friendly ranging notation.
type HTTPStatusRange map[int]bool

//nolint:gomnd,cyclop
func (hsr *HTTPStatusRange) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*hsr = make(HTTPStatusRange)
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
			return errors.New("HTTPStatusRange.UnmarshalYAML: not a valid range")
		}
		// Is a range.
		statusRange := strings.Split(v, "-")
		startCode, err := strconv.ParseInt(statusRange[0], 10, 32)
		if err != nil {
			return errors.Wrapf(err, "HTTPStatusRange.UnmarshalYAML failed: startCode: %s", v)
		}

		endCode, err := strconv.ParseInt(statusRange[1], 10, 32)
		if err != nil {
			return errors.Wrapf(err, "HTTPStatusRange.UnmarshalYAML failed: endCode: %s", v)
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
		(*hsr)[v] = true
	}
	return nil
}

// MarshalYAML implements the yaml.Marshaler interface.
func (hsr HTTPStatusRange) MarshalYAML() (interface{}, error) {
	statusCodes := make([]int, 0, len(hsr))
	var output []string
	for k := range hsr {
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
			if statusCodes[idx]-prev != 1 {
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
// If TLSEnable is not set but you request HTTPS, it'll fail.
type HTTPServiceConfig struct {
	ChallengeResponseConfig `yaml:",inline,omitempty"`
	Verb                    string          `yaml:"verb,omitempty"`           // HTTP verb to use
	URL                     URL             `yaml:"url,omitempty"`            // HTTP request URL to send
	SuccessStatuses         HTTPStatusRange `yaml:"success_status,omitempty"` // List of status codes indicating success
	BasicAuth               bool            `yaml:"auth,omitempty"`           // Use HTTP basic auth
	Username                string          `yaml:"username,omitempty"`       // Username for HTTP basic auth
	Password                string          `yaml:"password,omitempty"`       // Password for HTTP basic auth
}

func (hsc *HTTPServiceConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*hsc = DefaultHTTPServiceConfig

	type plain HTTPServiceConfig

	if err := unmarshal((*plain)(hsc)); err != nil {
		return err
	}

	return nil
}

// Bytes implements a custom []byte slice so we can unmarshal one from an escaped string.
type Bytes []byte

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (b *Bytes) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}

	*b = Bytes(s)
	return nil
}

// MarshalYAML implements the yaml.Marshaler interface.
func (b *Bytes) MarshalYAML() (interface{}, error) {
	if len(*b) != 0 {
		return string(*b), nil
	}
	return nil, nil //nolint:nilnil
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
		return nil, errors.Wrap(err, "NewRegexp failed")
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
//nolint:nilnil
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
		return errors.Wrap(err, "URL UnmarshalYAML failed")
	}
	u.URL = urlp
	return nil
}

// MarshalYAML implements the yaml.Marshaler interface for URLs.
//nolint:nilnil
func (u URL) MarshalYAML() (interface{}, error) {
	if u.URL != nil {
		return u.String(), nil
	}
	return nil, nil
}

// TLSCertificatePool is our custom type for decoding a certificate pool out of
// YAML.
type TLSCertificatePool struct {
	*x509.CertPool
	original []string
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for tls_cacerts.
func (t *TLSCertificatePool) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s []string
	if err := unmarshal(&s); err != nil {
		return err
	}

	// Prescan to check for system cert package request
	t.CertPool = nil
	for _, entry := range s {
		if entry == TLSCACertsSystem {
			rootCAs, err := x509.SystemCertPool()
			if err != nil {
				zap.L().Warn("could not fetch system certificate pool", zap.Error(err))
				rootCAs = x509.NewCertPool()
			}
			t.CertPool = rootCAs
			break
		}
	}

	if t.CertPool == nil {
		t.CertPool = x509.NewCertPool()
	}

	for idx, entry := range s {
		var pem []byte
		if entry == TLSCACertsSystem {
			// skip - handled above
			continue
		} else if _, err := os.Stat(entry); err == nil {
			// Is a file
			pem, err = ioutil.ReadFile(entry)
			if err != nil {
				return errors.Wrapf(err, "could not read certificate file: %s", entry)
			}
		} else {
			pem = []byte(entry)
		}
		if ok := t.CertPool.AppendCertsFromPEM(pem); !ok {
			return errors.Wrapf(ErrInvalidPEMFile, "failed at item %v", idx)
		}
	}

	t.original = s

	return nil
}

// MarshalYAML implements the yaml.Marshaler interface for tls_cacerts.
func (t *TLSCertificatePool) MarshalYAML() (interface{}, error) {
	return t.original, nil
}

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
