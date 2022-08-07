package config //nolint:testpackage

import (
	"io/ioutil"

	"github.com/samber/lo"
	. "gopkg.in/check.v1"
)

type ConfigLoadingSuite struct{}

var _ = Suite(&ConfigLoadingSuite{})

// TestLoadingDefaultConfig tests that the default configuration file can be loaded.
func (cls *ConfigLoadingSuite) TestLoadingDefaultConfig(c *C) {
	result := loadDefaultConfigMap()

	// Check the high level headers are found
	for _, key := range []string{"web", "collector", "host_defaults", "hosts"} {
		_, ok := result[key]
		c.Check(ok, Equals, true, Commentf("top-level key %s not found in default_config.yml", key))
	}
}

func (cls *ConfigLoadingSuite) TestLoadingCompleteConfig(c *C) {
	configMap := lo.Must(loadConfigMap(lo.Must(ioutil.ReadFile("../../poller_exporter.complete.yml"))))

	// Check the high level headers are found
	for _, key := range []string{"web", "collector", "host_defaults", "hosts"} {
		_, ok := configMap[key]
		c.Check(ok, Equals, true, Commentf("top-level key %s not found in default_config.yml", key))
	}

	// Check hosts contains an entry
	hosts, ok := configMap["hosts"].([]interface{})
	c.Assert(ok, Equals, true)
	c.Check(len(hosts), Equals, 1)
}

// TestMergingConfig.
func (cls *ConfigLoadingSuite) TestMergingConfig(c *C) {
	defaultMap := loadDefaultConfigMap()
	configMap := lo.Must(loadConfigMap(lo.Must(ioutil.ReadFile("test_data/config_merge/config_merge.yml"))))

	configMapMerge(defaultMap, configMap)
	c.Assert(configMap, Not(IsNil))

	// Check the config map inherited the defaults
	c.Check(configMap, DeepEquals, defaultMap, Commentf("blank config should now be default config"))
}

// TestLoadConfig tests that we can successfully load and parse the poller_exporter.complete.yml.
func (cls *ConfigLoadingSuite) TestLoadConfig(c *C) {
	config, err := Load(lo.Must(ioutil.ReadFile("../../poller_exporter.complete.yml")))
	c.Check(err, IsNil, Commentf("%v", err))
	c.Assert(config, Not(IsNil))
}
