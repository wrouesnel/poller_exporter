package config

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/pmezard/go-difflib/difflib"
	. "github.com/prometheus/common/model"
	. "gopkg.in/check.v1"
)

var testConfig = `
username: testuser
password: testpass

tls_cert: cert.crt
tls_key: key.pem

poll_frequency: 999s
ping_timeout: 111s

timeout: 222s

max_bytes: 1242

ping_disable: false
ping_count: 44

hosts:
- hostname: test.host
  ping_count: 21
  basic_checks:
  - name: example-A
    protocol: tcp
    port: 80
  - name: example-A
    protocol: udp
    port: 91
    timeout: 1211s
  - name: example-A
    protocol: udp
    port: 92
    timeout: 1212s
  - name: example-A
    protocol: tcp
    port: 93
    timeout: 1213s
    use_ssl: true
`

const numHosts = 1

var expectedConfig = PollerExporterConfig{
	BasicAuthUsername:  "testuser",
	BasicAuthPassword:  "testpass",
	TLSCertificatePath: "cert.crt",
	TLSKeyPath:         "key.pem",
	PollFrequency:      Duration(999 * time.Second),
	PingTimeout:        Duration(111 * time.Second),
	Timeout:            Duration(222 * time.Second),
	MaxBytes:           1242,
	PingDisable:        false,
	PingCount:          44,
	Hosts: []HostConfig{
		{
			Hostname:     "test.host",
			PollInterval: 999,   // should be same as global
			PingDisable:  false, // same as global
			PingTimeout:  111,   // same as global
			PingCount:    21,
			BasicChecks: []*BasicServiceConfig{
				{
					Name:     "example-A",
					Protocol: "tcp",
					Port:     80,
				},
				{
					Name:     "example-A",
					Protocol: "udp",
					Port:     91,
					Timeout:  1211,
				},
				{
					Name:    "example-A",
					Port:    92,
					Timeout: 1212,
				},
				{
					Name:    "example-A",
					Port:    93,
					Timeout: 1213,
					UseSSL:  true,
				},
			},
			ChallengeResponseChecks: []*ChallengeResponseConfig{},
			HTTPChecks:              []*HTTPServiceConfig{},
		},
	},
}

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type ConfigSuite struct{}

var _ = Suite(&ConfigSuite{})

func structDiff(a, b interface{}) string {
	diff := difflib.UnifiedDiff{
		A:        difflib.SplitLines(spew.Sdump(a)),
		B:        difflib.SplitLines(spew.Sdump(b)),
		FromFile: "a",
		ToFile:   "b",
		Context:  3,
	}
	text, _ := difflib.GetUnifiedDiffString(diff)
	return text
}

func (s *ConfigSuite) TestConfigParsing(c *C) {
	f, err := ioutil.TempFile("", "reverse_exporter_test")

	c.Assert(err, IsNil, Commentf("error writing temporary file for config test"))

	f.WriteString(testConfig)
	f.Close()
	configFileName := f.Name()
	defer os.Remove(f.Name())

	config, err := LoadFromFile(configFileName)

	c.Assert(err, IsNil, Commentf("got error while parsing test YAML"))
	c.Assert(config, Not(IsNil), Commentf("no config returned from YAML parser"))

	c.Check(len(config.XXX), Equals, 0, Commentf("test config with no extra keys had extra keys?"))
	c.Check(len(config.Hosts), Equals, numHosts, Commentf("test config read incorrect number of endpoints"))

	c.Check(config, DeepEquals, expectedConfig,
		Commentf("Parsed config did not match expected config.\nDifference Was:\n%s",
			structDiff(config, expectedConfig)))
}
