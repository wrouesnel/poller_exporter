package config

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// HTTPStatusRange is a range of HTTP status codes which can be specifid in YAML using human-friendly ranging notation.
type HTTPStatusRange map[int]bool

func (hsr *HTTPStatusRange) FromString(ranges string) error {
	*hsr = make(HTTPStatusRange)
	var statusCodes []int
	fields := strings.Fields(ranges)

	for _, v := range fields {
		code, err := strconv.ParseInt(v, 10, 32)
		if err == nil {
			statusCodes = append(statusCodes, int(code))
			continue
		}
		// Didn't work, but might be a range
		if strings.Count(v, "-") == 0 || strings.Count(v, "-") > 1 {
			return errors.New("HTTPStatusRange.FromString: not a valid range")
		}
		// Is a range.
		statusRange := strings.Split(v, "-")
		startCode, err := strconv.ParseInt(statusRange[0], 10, 32)
		if err != nil {
			return errors.Wrapf(err, "HTTPStatusRange.FromString failed: startCode: %s", v)
		}

		endCode, err := strconv.ParseInt(statusRange[1], 10, 32)
		if err != nil {
			return errors.Wrapf(err, "HTTPStatusRange.FromString failed: endCode: %s", v)
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

//nolint:gomnd,cyclop
func (hsr *HTTPStatusRange) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var ranges string
	if err := unmarshal(&ranges); err != nil {
		return err
	}

	return hsr.FromString(ranges)
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
		itemSample := ""
		if entry == TLSCACertsSystem {
			// skip - handled above
			continue
		} else if _, err := os.Stat(entry); err == nil {
			// Is a file
			pem, err = ioutil.ReadFile(entry)
			if err != nil {
				return errors.Wrapf(err, "could not read certificate file: %s", entry)
			}
			itemSample = entry
		} else {
			pem = []byte(entry)
			if len(entry) < 50 {
				itemSample = entry
			} else {
				itemSample = entry[:50]
			}

		}
		if ok := t.CertPool.AppendCertsFromPEM(pem); !ok {
			return errors.Wrapf(ErrInvalidPEMFile, "failed at item %v: %s", idx, itemSample)
		}
	}

	t.original = s

	return nil
}

// MarshalYAML implements the yaml.Marshaler interface for tls_cacerts.
func (t *TLSCertificatePool) MarshalYAML() (interface{}, error) {
	return t.original, nil
}
