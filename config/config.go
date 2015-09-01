package main
import (
	//"github.com/prometheus/client_golang/prometheus"
)

type HostConfigs struct {
	Hosts []Host	// List of hosts which are to be polled
}

// Defines a host which we want to find service information about.
// Hosts export DNS checks.
type HostConfig struct {
	Hostname string		`yaml:"hostname"`	// Host or IP to contact

	BasicChecks []*BasicServiceConfig	`yaml:"basic_checks,omitempty"`
	ChallengeResponseChecks []*ChallengeResponseConfig	`yaml:"challenge_reponse_checks,omitempty"`
	HTTPChecks []*HTTPServiceConfig	`yaml:"http_checks,omitempty"`
}

// A basic network service.
type BasicServiceConfig struct {
	Name		string			`yaml:"name"`		// Name of the service
	Protocol	string			`yaml:"proto"`		// TCP or UDP
	Port		uint64			`yaml:"port"`		// Port number of the service
	Timeout		uint64			`yaml:"timeout"`		// Number of seconds to wait for response
	UseSSL		bool			`yaml:"ssl,omitempty"`		// The service uses SSL
}

// Similar to a banner check, but first sends the specified data befoe looking
// for a response.
type ChallengeResponseConfig struct {
	ChallengeLiteral string		`yaml:"challenge,omitempty"`
	ResponseRegex	string		`yaml:"response_re,omitempty"`// Regex that must match
	ResponseLiteral string		`yaml:"response,omitempty"`// Literal string that must match

	BasicServiceConfig
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