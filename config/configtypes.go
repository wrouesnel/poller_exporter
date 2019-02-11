// Custom types implemented for YAML deserialization

package config

import (
	"net/url"
	"regexp"
	"strings"
	"strconv"
	"sort"
	"fmt"
)

// Implements a custom []byte slice so we can unmarshal one from an escaped string
type Bytes []byte

// Copy makes a memory-independent copy, safe for use with channels
func (b *Bytes) Copy() *Bytes {
	if b == nil {
		return nil
	}
	c := b[:]
	return &c
}

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
	return nil, nil
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

// A range of HTTP status codes which can be specifid in YAML using human-friendly
// ranging notation
type HTTPStatusRange map[int]bool

// Copy makes a memory independent copy of this object, safe for use with channels
func (hsr HTTPStatusRange) Copy() HTTPStatusRange {
	c := HTTPStatusRange{}
	for k, v := range hsr {
		c[k] = v
	}
	return c
}

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
		(*hsr)[v] = true
	}
	return nil
}

// MarshalYAML implements the yaml.Marshaler interface.
func (hsr HTTPStatusRange) MarshalYAML() (interface{}, error) {
	var statusCodes []int
	var output []string
	for k, _ := range hsr {
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