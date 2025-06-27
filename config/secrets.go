package config

import (
	"github.com/prometheus/common/secrets"
)

func init() {
	// Intermediate step in the migration to the new secrets API.
	secrets.SetVisibilityPolicy(func() bool { return MarshalSecretValue })
}
