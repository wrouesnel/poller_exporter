package config

import (
	"io/ioutil"
	"reflect"

	"github.com/samber/lo"

	"go.uber.org/zap"

	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

var (
	ErrMapStructureDecode = errors.New("MapStructureDecode function failed")
	ErrInconsistentLabels = errors.New("Extra Prometheus labels found without defaults set")
)

// loadDefaultConfigMap returns the config file which is embedded in the binary
// and sets defaults.
func loadDefaultConfigMap() map[string]interface{} {
	defaultConfig, err := loadConfigMap(DefaultConfigFile())
	if err != nil {
		// Panic because this should *never* happen
		zap.L().Panic("loading embedded default_config failed - this is a bug", zap.Error(err))
		return nil // this is never reached
	}

	return defaultConfig
}

// loadConfigMap unmarshals config bytes into the map for mapstructure.
func loadConfigMap(configBytes []byte) (map[string]interface{}, error) {
	// Load the default config to setup the defaults
	configMap := make(map[string]interface{})
	err := yaml.Unmarshal(configBytes, configMap)
	if err != nil {
		return configMap, errors.Wrapf(err, "loadConfigMap: yaml unmarshalling failed")
	}

	return configMap, nil
}

// configMapMerge merges config maps right-to-left. Maps and nested maps
// are merged key-by-key, but lists will be replaced.
func configMapMerge(left, right map[string]interface{}) {
	for k, leftValue := range left {
		// left key does not exist in right map
		rightValue, ok := right[k]
		if !ok {
			right[k] = leftValue
			continue
		}
		// does exist - check if this is a map type on the right
		switch v := rightValue.(type) {
		case map[string]interface{}:
			// check if map on the left
			leftValueMap, ok := leftValue.(map[string]interface{})
			if !ok {
				// Not a value map on left.
				break
			}
			// map on both sides - descend and merge.
			configMapMerge(leftValueMap, v)
		default:
			// leave non-maps alone on the right.
			continue
		}
	}
}

// Decoder returns the decoder for config maps.
//
//nolint:exhaustruct
func Decoder(target interface{}, allowUnused bool) (*mapstructure.Decoder, error) {
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		ErrorUnused: !allowUnused,
		DecodeHook:  mapstructure.ComposeDecodeHookFunc(MapStructureDecodeHookFunc(), mapstructure.TextUnmarshallerHookFunc()),
		Result:      target,
	})
	if err != nil {
		return nil, errors.Wrap(err, "Load: BUG - decoder configuration rejected")
	}
	return decoder, nil
}

// LoadAndSanitizeConfig is used purely for displaying the config to users. It removes
// sensitive keys from the config and provides a reserialized YAML view of it.
func LoadAndSanitizeConfig(configData []byte) (string, error) {
	// note: this is a separate decoding, so it's safe to edit this map when sanitizing.
	configMap, err := loadConfigMap(configData)
	if err != nil {
		return "", errors.Wrap(err, "LoadAndSanitizeConfig: failed")
	}

	sanitized, err := yaml.Marshal(configMap)
	if err != nil {
		return "", errors.Wrap(err, "LoadAndSanitizeConfig: YAML reserialization failed")
	}

	return string(sanitized), nil
}

// Load loads a configuration file from the supplied bytes.
//
//nolint:forcetypeassert,funlen,cyclop,gocognit
func Load(configData []byte) (*Config, error) {
	defaultMap := loadDefaultConfigMap()
	configMap, err := loadConfigMap(configData)
	if err != nil {
		return nil, errors.Wrap(err, "Load: failed")
	}

	// Merge default configuration into the configMap
	configMapMerge(defaultMap, configMap)

	// Do an initial decode to detect any unused key errors
	cfg := new(Config)
	decoder, err := Decoder(cfg, false)
	if err != nil {
		return nil, errors.Wrapf(err, "Load: config map decoder failed to initialize")
	}

	if err := decoder.Decode(configMap); err != nil {
		return nil, errors.Wrap(err, "Load: config map decoding failed")
	}

	// Merge host defaults to all hosts
	hostDefaults := configMap["host_defaults"].(map[string]interface{})
	for _, hostIntf := range configMap["hosts"].([]interface{}) {
		host := hostIntf.(map[string]interface{})
		configMapMerge(hostDefaults, host)
	}

	// Merge host service defaults to all services
	for _, hostIntf := range configMap["hosts"].([]interface{}) {
		host := hostIntf.(map[string]interface{})
		hostServiceDefaults := host["service_defaults"].(map[string]interface{})

		if _, ok := host["basic_checks"]; ok {
			for _, serviceIntf := range host["basic_checks"].([]interface{}) {
				service := serviceIntf.(map[string]interface{})
				configMapMerge(hostServiceDefaults, service)
			}
		}

		if _, ok := host["challenge_response_checks"]; ok {
			for _, serviceIntf := range host["challenge_response_checks"].([]interface{}) {
				service := serviceIntf.(map[string]interface{})
				configMapMerge(hostServiceDefaults, service)
			}
		}

		if _, ok := host["http_checks"]; ok {
			for _, serviceIntf := range host["http_checks"].([]interface{}) {
				service := serviceIntf.(map[string]interface{})
				configMapMerge(hostServiceDefaults, service)
			}
		}
	}

	// Do the decode after inheritance and allow unused key errors.
	cfg = new(Config)
	decoder, err = Decoder(cfg, true)
	if err != nil {
		return nil, errors.Wrapf(err, "Load: second-pass config map decoder failed to initialize")
	}

	if err := decoder.Decode(configMap); err != nil {
		return nil, errors.Wrap(err, "Load: second-pass config map decoding failed")
	}

	// Check that Prometheus extra label keys are consistent.
	hostDefaultKeys := lo.Keys(cfg.HostDefault.ExtraLabels)
	serviceDefaultKeys := lo.Union(hostDefaultKeys, lo.Keys(cfg.HostDefault.ServiceDefaults.ExtraLabels))
	for _, host := range cfg.Hosts {
		hostKeys := lo.Keys(host.ExtraLabels)
		if _, right := lo.Difference(hostDefaultKeys, hostKeys); len(right) > 0 {
			zap.L().Error("Extra keys must have default values from host_defaults, and this host has more then allowed",
				zap.Strings("allowed_keys", hostDefaultKeys),
				zap.Strings("undefined_keys", right),
				zap.String("hostname", host.Hostname))
			return nil, errors.Wrapf(ErrInconsistentLabels, "Load: undefined labels found for host: %v", host.Hostname)
		}

		hostServiceDefaultKeys := lo.Keys(host.ServiceDefaults.ExtraLabels)
		if _, right := lo.Difference(serviceDefaultKeys, hostServiceDefaultKeys); len(right) > 0 {
			zap.L().Error("Extra keys must have default values from host_defaults.service_defaults, and this host has more then allowed",
				zap.Strings("allowed_keys", hostServiceDefaultKeys),
				zap.Strings("undefined_keys", right),
				zap.String("hostname", host.Hostname))
			return nil, errors.Wrapf(ErrInconsistentLabels, "Load: undefined labels found for host: %v", host.Hostname)
		}

		for _, service := range host.BasicChecks {
			if _, right := lo.Difference(serviceDefaultKeys, lo.Keys(service.ExtraLabels)); len(right) > 0 {
				zap.L().Error("Extra keys must have default values from host_defaults.service_defaults, and this host has more then allowed",
					zap.Strings("allowed_keys", hostServiceDefaultKeys),
					zap.Strings("undefined_keys", right),
					zap.String("hostname", host.Hostname),
					zap.String("service", service.Name))
				return nil, errors.Wrapf(ErrInconsistentLabels, "Load: undefined labels found for host: %v", host.Hostname)
			}
		}

		for _, service := range host.ChallengeResponseChecks {
			if _, right := lo.Difference(serviceDefaultKeys, lo.Keys(service.ExtraLabels)); len(right) > 0 {
				zap.L().Error("Extra keys must have default values from host_defaults.service_defaults, and this host has more then allowed",
					zap.Strings("allowed_keys", hostServiceDefaultKeys),
					zap.Strings("undefined_keys", right),
					zap.String("hostname", host.Hostname),
					zap.String("service", service.Name))
				return nil, errors.Wrapf(ErrInconsistentLabels, "Load: undefined labels found for host: %v", host.Hostname)
			}
		}

		for _, service := range host.HTTPChecks {
			if _, right := lo.Difference(serviceDefaultKeys, lo.Keys(service.ExtraLabels)); len(right) > 0 {
				zap.L().Error("Extra keys must have default values from host_defaults.service_defaults, and this host has more then allowed",
					zap.Strings("allowed_keys", hostServiceDefaultKeys),
					zap.Strings("undefined_keys", right),
					zap.String("hostname", host.Hostname),
					zap.String("service", service.Name))
				return nil, errors.Wrapf(ErrInconsistentLabels, "Load: undefined labels found for host: %v", host.Hostname)
			}
		}
	}

	return cfg, nil
}

func LoadFromFile(filename string) (*Config, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrapf(err, "LoadFromFile failed: %s", filename)
	}
	return Load(content)
}

// MapStructureDecoder is detected by MapStructureDecodeHookFunc to allow a type
// to decode itself.
type MapStructureDecoder interface {
	MapStructureDecode(interface{}) error
}

// MapStructureDecodeHookFunc returns a DecodeHookFunc that applies
// output to the UnmarshalYAML function, when the target type
// implements the yaml.Unmarshaller interface.
func MapStructureDecodeHookFunc() mapstructure.DecodeHookFuncType {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{}) (interface{}, error) {
		result := reflect.New(t).Interface()
		unmarshaller, ok := result.(MapStructureDecoder)
		if !ok {
			return data, nil
		}
		if err := unmarshaller.MapStructureDecode(data); err != nil {
			return nil, errors.Wrapf(err, "MapStructureDecode function returned error")
		}
		return result, nil
	}
}
