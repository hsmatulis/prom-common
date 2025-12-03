package config

import (
	"encoding/json"

	"github.com/prometheus/common/secrets"
)

const secretToken = "<secret>"

// Secret special type for storing secrets.
type Secret string

// MarshalSecretValue if set to true will expose Secret type
// through the marshal interfaces. Useful for outside projects
// that load and marshal the Prometheus config.
var MarshalSecretValue = false

// MarshalYAML implements the yaml.Marshaler interface for Secrets.
func (s Secret) MarshalYAML() (interface{}, error) {
	if MarshalSecretValue {
		return string(s), nil
	}
	if s != "" {
		return secretToken, nil
	}
	return nil, nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for Secrets.
func (s *Secret) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Secret
	return unmarshal((*plain)(s))
}

// MarshalJSON implements the json.Marshaler interface for Secret.
func (s Secret) MarshalJSON() ([]byte, error) {
	if MarshalSecretValue {
		return json.Marshal(string(s))
	}
	if len(s) == 0 {
		return json.Marshal("")
	}
	return json.Marshal(secretToken)
}

type SecretReader interface {
	Get() string
	Path() string
}

func NewInlineSecret(text string) SecretReader {
	return nil
}

func NewFileSecret(path string) SecretReader {
	return nil
}

func init() {
	// Intermediate step in the migration to the new secrets API.
	secrets.SetVisibilityPolicy(func() bool { return MarshalSecretValue })
}
