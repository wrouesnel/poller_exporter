//nolint:forcetypeassert
package config_test

import (
	"crypto/x509"
	"io/ioutil"
	"reflect"
	"regexp"
	"testing"
	"time"
	"unsafe"

	"github.com/prometheus/common/model"

	"github.com/wrouesnel/poller_exporter/pkg/certutils"
	"github.com/wrouesnel/poller_exporter/pkg/config"
	"github.com/wrouesnel/poller_exporter/pkg/errutils"
	. "gopkg.in/check.v1"
	"gopkg.in/yaml.v3"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type TLSCACertsSuite struct{}

var _ = Suite(&TLSCACertsSuite{})

func GetPoolCertificates(pool *x509.CertPool) []*x509.Certificate {
	poolReflect := reflect.ValueOf(pool).Elem()
	lazyCerts := poolReflect.FieldByName("lazyCerts")
	poolCerts := make([]*x509.Certificate, 0)

	for i := 0; i < lazyCerts.Len(); i++ {
		methodInterface := lazyCerts.Index(i)
		methodField := methodInterface.FieldByName("getCert")
		callable := reflect.NewAt(methodField.Type(), unsafe.Pointer(methodField.UnsafeAddr())).Elem()
		certs := callable.Call(nil)[0].Interface().(*x509.Certificate)
		poolCerts = append(poolCerts, certs)
	}
	return poolCerts
}

func (s *TLSCACertsSuite) TestLoadFullExample(c *C) {
	data := errutils.Must(ioutil.ReadFile("test_data/tls_cacerts/system_file_inline.yml"))
	pool := new(config.TLSCertificatePool)

	err := yaml.Unmarshal(data, pool)
	c.Assert(err, IsNil)

	poolCerts := GetPoolCertificates(pool.CertPool)

	// Check the inline and file certs are there
	otherCert := errutils.Must(certutils.LoadCertificatesFromPem(errutils.Must(ioutil.ReadFile("test_data/tls_cacerts/other.crt"))))[0]
	someCert := errutils.Must(certutils.LoadCertificatesFromPem(errutils.Must(ioutil.ReadFile("test_data/tls_cacerts/some.crt"))))[0]

	otherCertFound := false
	someCertFound := false

	for _, cert := range poolCerts {
		if cert.Equal(otherCert) {
			otherCertFound = true
		}

		if cert.Equal(someCert) {
			someCertFound = true
		}
	}

	c.Check(otherCertFound, Equals, true)
	c.Check(someCertFound, Equals, true)
}

func (s *TLSCACertsSuite) TestLoadNoSystem(c *C) {
	data := errutils.Must(ioutil.ReadFile("test_data/tls_cacerts/file_inline.yml"))
	pool := new(config.TLSCertificatePool)

	err := yaml.Unmarshal(data, pool)
	c.Assert(err, IsNil)

	poolCerts := GetPoolCertificates(pool.CertPool)

	// Check the inline and file certs are there
	otherCert := errutils.Must(certutils.LoadCertificatesFromPem(errutils.Must(ioutil.ReadFile("test_data/tls_cacerts/other.crt"))))[0]
	someCert := errutils.Must(certutils.LoadCertificatesFromPem(errutils.Must(ioutil.ReadFile("test_data/tls_cacerts/some.crt"))))[0]

	otherCertFound := false
	someCertFound := false

	for _, cert := range poolCerts {
		if cert.Equal(otherCert) {
			otherCertFound = true
		}

		if cert.Equal(someCert) {
			someCertFound = true
		}
	}

	c.Check(otherCertFound, Equals, true)
	c.Check(someCertFound, Equals, true)
	c.Check(len(poolCerts), Equals, 2)
}

func (s *TLSCACertsSuite) TestLoadNone(c *C) {
	data := errutils.Must(ioutil.ReadFile("test_data/tls_cacerts/none.yml"))
	pool := new(config.TLSCertificatePool)

	err := yaml.Unmarshal(data, pool)
	c.Assert(err, IsNil)

	poolCerts := GetPoolCertificates(pool.CertPool)
	c.Check(len(poolCerts), Equals, 0)
}

type ConfigOverrideSuite struct{}

var _ = Suite(&ConfigOverrideSuite{})

func (cos *ConfigOverrideSuite) TestTLSOverride(c *C) {
	conf := errutils.Must(config.LoadFromFile("test_data/config_override/config_override_tls.yml"))

	globalCerts := GetPoolCertificates(conf.TLSCACerts.CertPool)
	systemPool := GetPoolCertificates(errutils.Must(x509.SystemCertPool()))

	hostConfigs := map[string]config.HostConfig{}

	for _, host := range conf.Hosts {
		hostConfigs[host.Hostname] = host
	}

	// Check TLS CA certs looks like the system pool
	c.Check(len(globalCerts), Equals, len(systemPool))

	// Check the host with a custom cert has it
	c.Check(len(GetPoolCertificates(hostConfigs["host-with-custom"].BasicChecks[0].TLSCACerts.CertPool)),
		Equals, 1)
	c.Check(len(GetPoolCertificates(hostConfigs["host-with-custom"].ChallengeResponseChecks[0].TLSCACerts.CertPool)),
		Equals, 1)
	c.Check(len(GetPoolCertificates(hostConfigs["host-with-custom"].HTTPChecks[0].TLSCACerts.CertPool)),
		Equals, 1)

	// Check the host with no certs has the globals
	c.Check(len(GetPoolCertificates(hostConfigs["host-with-default"].BasicChecks[0].TLSCACerts.CertPool)),
		Equals, len(globalCerts))
	c.Check(len(GetPoolCertificates(hostConfigs["host-with-default"].ChallengeResponseChecks[0].TLSCACerts.CertPool)),
		Equals, len(globalCerts))
	c.Check(len(GetPoolCertificates(hostConfigs["host-with-default"].HTTPChecks[0].TLSCACerts.CertPool)),
		Equals, len(globalCerts))
}

func (cos *ConfigOverrideSuite) TestTLSOverrideWithNoSpecifiedDefaults(c *C) {
	conf := errutils.Must(config.LoadFromFile("test_data/config_override/config_override_tlsdefault.yml"))

	globalCerts := GetPoolCertificates(conf.TLSCACerts.CertPool)
	systemPool := GetPoolCertificates(errutils.Must(x509.SystemCertPool()))

	hostConfigs := map[string]config.HostConfig{}

	for _, host := range conf.Hosts {
		hostConfigs[host.Hostname] = host
	}

	// Check TLS CA certs looks like the system pool
	c.Check(len(globalCerts), Equals, len(systemPool))

	// Check the host with a custom cert has it
	c.Check(len(GetPoolCertificates(hostConfigs["host-with-custom"].BasicChecks[0].TLSCACerts.CertPool)),
		Equals, 1)
	c.Check(len(GetPoolCertificates(hostConfigs["host-with-custom"].ChallengeResponseChecks[0].TLSCACerts.CertPool)),
		Equals, 1)
	c.Check(len(GetPoolCertificates(hostConfigs["host-with-custom"].HTTPChecks[0].TLSCACerts.CertPool)),
		Equals, 1)

	// Check the host with no certs has the globals
	c.Check(len(GetPoolCertificates(hostConfigs["host-with-default"].BasicChecks[0].TLSCACerts.CertPool)),
		Equals, len(globalCerts))
	c.Check(len(GetPoolCertificates(hostConfigs["host-with-default"].ChallengeResponseChecks[0].TLSCACerts.CertPool)),
		Equals, len(globalCerts))
	c.Check(len(GetPoolCertificates(hostConfigs["host-with-default"].HTTPChecks[0].TLSCACerts.CertPool)),
		Equals, len(globalCerts))
}

type ConfigExpected struct{}

var _ = Suite(&ConfigExpected{})

// TestCompleteConfig loads poller_exporter.complete.yml and checks the loaded file matches.
func (ce *ConfigExpected) TestCompleteConfig(c *C) {
	conf := errutils.Must(config.LoadFromFile("../../poller_exporter.complete.yml"))

	c.Check(conf.BasicAuthUsername, Equals, "admin")
	c.Check(conf.BasicAuthPassword, Equals, "my-pass")

	c.Check(conf.TLSCertificatePath, Equals, "test_data/localhost.crt")
	c.Check(conf.TLSKeyPath, Equals, "test_data/localhost.pem")

	globalCerts := GetPoolCertificates(conf.TLSCACerts.CertPool)
	systemPool := GetPoolCertificates(errutils.Must(x509.SystemCertPool()))

	// Check TLS CA certs looks like the system pool
	c.Check(len(globalCerts), Equals, len(systemPool))

	c.Check(conf.PollFrequency, Equals, model.Duration(60*time.Second))
	c.Check(conf.Timeout, Equals, model.Duration(40*time.Second))
	c.Check(conf.MaxBytes, Equals, uint64(8192))

	c.Check(conf.PingDisable, Equals, false)
	c.Check(conf.PingCount, Equals, uint64(5))
	c.Check(conf.PingTimeout, Equals, model.Duration(time.Second))

	hostConfigs := map[string]config.HostConfig{}

	for _, host := range conf.Hosts {
		hostConfigs[host.Hostname] = host
	}

	hostConf := hostConfigs["myhost"]
	c.Check(hostConf.Hostname, Equals, "myhost")
	c.Check(hostConf.PollFrequency, Equals, model.Duration(2*time.Second))
	c.Check(hostConf.PingDisable, Equals, true)
	c.Check(hostConf.PingTimeout, Equals, model.Duration(5*time.Second))
	c.Check(hostConf.PingCount, Equals, uint64(2))

	basicChecks := hostConf.BasicChecks[0]
	c.Check(basicChecks.Name, Equals, "SMTP")
	c.Check(basicChecks.Protocol, Equals, "tcp")
	c.Check(basicChecks.Port, Equals, uint64(465))
	c.Check(basicChecks.Timeout, Equals, model.Duration(5*time.Second))
	c.Check(basicChecks.TLSEnable, Equals, true)

	serviceCerts := GetPoolCertificates(basicChecks.TLSCACerts.CertPool)
	c.Check(len(serviceCerts), Equals, len(systemPool)+2)

	crChecks := hostConf.ChallengeResponseChecks[0]
	c.Check(crChecks.Name, Equals, "CustomDaemon")
	c.Check(crChecks.Protocol, Equals, "tcp")
	c.Check(crChecks.Port, Equals, uint64(22))
	c.Check(crChecks.Timeout, Equals, model.Duration(6*time.Second))
	c.Check(crChecks.TLSEnable, Equals, false)

	crServiceCerts := GetPoolCertificates(crChecks.TLSCACerts.CertPool)
	c.Check(len(crServiceCerts), Equals, 2)

	c.Check(crChecks.ChallengeLiteral, Equals, []byte("MY_UNIQUE_HEADER"))
	c.Check(crChecks.ResponseRegex.String(), Equals, regexp.MustCompile("RESPONSE_HEADER").String())
	c.Check(crChecks.ResponseLiteral, Equals, []byte("literal-value"))
	c.Check(crChecks.MaxBytes, Equals, 65535)

	httpChecks := hostConf.HTTPChecks[0]
	c.Check(httpChecks.Name, Equals, "CustomDaemon")
	c.Check(httpChecks.Protocol, Equals, "tcp")
	c.Check(httpChecks.Port, Equals, uint64(22))
	c.Check(httpChecks.Timeout, Equals, model.Duration(6*time.Second))
	c.Check(httpChecks.TLSEnable, Equals, false)

	httpServiceCerts := GetPoolCertificates(httpChecks.TLSCACerts.CertPool)
	c.Check(len(httpServiceCerts), Equals, uint64(1))

	c.Check(httpChecks.ChallengeLiteral, Equals, []byte("some-data"))
	c.Check(httpChecks.ResponseRegex.String(), Equals, regexp.MustCompile("^<field-tag>").String())
	c.Check(httpChecks.ResponseLiteral, Equals, []byte("<html>"))
	c.Check(httpChecks.MaxBytes, Equals, uint64(131072))

	c.Check(httpChecks.Verb, Equals, "GET")
	c.Check(httpChecks.URL.String(), Equals, "http://vhost/query-path?with_paramters=1")
	testRange := &config.HTTPStatusRange{}
	c.Check(testRange.FromString("200 201 300-399"), IsNil)
	c.Check(httpChecks.SuccessStatuses, DeepEquals, testRange)

	c.Check(httpChecks.BasicAuth, Equals, true)
	c.Check(httpChecks.Username, Equals, "monitor")
	c.Check(httpChecks.Password, Equals, "monitoring")
}
