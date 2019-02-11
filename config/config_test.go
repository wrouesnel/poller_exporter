package config

import (
	"testing"
	. "gopkg.in/check.v1"
	"github.com/pmezard/go-difflib/difflib"
	"github.com/davecgh/go-spew/spew"
	"io/ioutil"
	"os"
)

var testConfig = `
username: testuser
password: testpass

tls_cert: cert.crt
tls_key: key.pem

poll_frequency: 999
ping_timeout: 111

timeout: 222

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
	timeout: 1212
  - name: example-A
	protocol: udp
	port: 91
	timeout: 1212
  - name: example-A
	protocol: tcp
	port: 91
	timeout: 1213
	use_ssl: true
`

const numHosts = 1

var expectedConfig = PollerExporterConfig{

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
