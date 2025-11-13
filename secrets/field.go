// Copyright 2025 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package secrets

import (
	"encoding/json"
	"fmt"
	"time"

	"go.yaml.in/yaml/v2"
)

// SecretField is a field containing a secret.
type SecretField struct {
	providerName   string
	providerConfig ProviderConfig
	manager        *Manager
	validator      SecretValidator
	settings       SecretFieldSettings
}

type SecretFieldSettings struct {
	RefreshInterval time.Duration `yaml:"refreshInterval,omitempty"`
	Default         string        `yaml:"default,omitempty"`
}

func (s SecretField) String() string {
	return fmt.Sprintf("SecretField{Provider: %s}", s.providerName)
}

// MarshalYAML implements the yaml.Marshaler interface for SecretField.
func (s SecretField) MarshalYAML() (interface{}, error) {
	if s.providerName == "inline" && s.manager != nil && s.manager.MarshalInlineSecrets {
		return s.Get(), nil
	}

	// Marshal settings to a map to merge them with the provider config.
	settingsBytes, err := yaml.Marshal(s.settings)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal secret field settings: %w", err)
	}

	out := make(map[string]interface{})
	if err := yaml.Unmarshal(settingsBytes, &out); err != nil {
		return nil, fmt.Errorf("failed to unmarshal marshaled settings: %w", err)
	}

	// Add the provider configuration.
	out[s.providerName] = s.providerConfig
	return out, nil
}

// MarshalJSON implements the json.Marshaler interface for SecretField.
func (s SecretField) MarshalJSON() ([]byte, error) {
	data, err := s.MarshalYAML()
	if err != nil {
		return nil, err
	}
	return json.Marshal(data)
}

type mapType = map[string]interface{}

// splitProviderAndSettings separates provider-specific configuration from the generic SecretField settings.
func splitProviderAndSettings(baseMap mapType) (providerName string, providerData interface{}, settingsMap mapType, err error) {
	settingsMap = make(mapType)

	for k, v := range baseMap {
		// Check if the key corresponds to a registered provider.
		if _, err := Providers.Get(k); err == nil {
			if providerName != "" {
				// A provider has already been found, which is an error.
				return "", nil, nil, fmt.Errorf("secret must contain exactly one provider type, but multiple were found: %s, %s", providerName, k)
			}
			providerName = k
			providerData = v
		} else {
			// If it's not a provider key, treat it as a setting.
			settingsMap[k] = v
		}
	}

	if providerName == "" {
		// Marshal the map back to YAML for a readable error message.
		yamlBytes, err := yaml.Marshal(baseMap)
		if err != nil {
			// Fallback to the original format if marshalling fails for some reason.
			return "", nil, nil, fmt.Errorf("no valid secret provider found in configuration: %v", baseMap)
		}
		return "", nil, nil, fmt.Errorf("no valid secret provider found in configuration:\n%s", string(yamlBytes))
	}

	return providerName, providerData, settingsMap, nil
}

// convertConfig takes a map-like structure and unmarshals it into a typed struct.
// It achieves this by first marshalling the input to YAML and then unmarshalling
// it into the target struct.
func convertConfig[T any](source interface{}, target T) error {
	bytes, err := yaml.Marshal(source)
	if err != nil {
		return fmt.Errorf("failed to re-marshal config: %w", err)
	}
	if err := yaml.Unmarshal(bytes, target); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}
	return nil
}

func (s *SecretField) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var plainSecret string
	if err := unmarshal(&plainSecret); err == nil {
		s.providerName = "inline"
		s.providerConfig = &InlineProviderConfig{
			secret: plainSecret,
		}
		s.validator = DefaultValidator{}
		return nil
	}

	var baseMap mapType
	if err := unmarshal(&baseMap); err != nil {
		return err
	}

	providerName, providerConfigData, settingsMap, err := splitProviderAndSettings(baseMap)
	if err != nil {
		return err
	}

	providerConfig, err := Providers.Get(providerName)
	if err != nil {
		return err
	}

	if err := convertConfig(providerConfigData, providerConfig); err != nil {
		return fmt.Errorf("failed to unmarshal into %s provider: %w", providerName, err)
	}
	var settings SecretFieldSettings
	if err := convertConfig(settingsMap, &settings); err != nil {
		return fmt.Errorf("failed to unmarshal secret field settings: %w", err)
	}
	s.providerName = providerName
	s.providerConfig = providerConfig
	s.validator = DefaultValidator{}
	s.settings = settings
	return nil
}

// SetSecretValidation registers an optional validation function for the secret.
//
// When the secret manager fetches a new version of the secret, it will not
// be used immediately if there is a validator. Instead, the manager will
// hold the new secret in a pending state and call the provided Validate
// with it until it returns true, there is an explicit refresh request,
// there is a time out, or the old secret was never valid.
func (s *SecretField) SetSecretValidation(validator SecretValidator) {
	s.validator = validator
	if s.manager != nil {
		s.manager.setSecretValidation(s, validator)
	}
}

func (s *SecretField) Get() string {
	if s.manager == nil {
		panic("secret field has not been discovered by a manager; was NewManager(&cfg) called?")
	}
	return s.manager.get(s)
}

func (s *SecretField) TriggerRefresh() {
	if s.manager == nil {
		panic("secret field has not been discovered by a manager; was NewManager(&cfg) called?")
	}
	s.manager.triggerRefresh(s)
}
