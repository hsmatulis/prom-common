package secrets

import (
	"fmt"
)

// SecretPreparer is implemented by structs that need to mutate or validate
// their state before the Secret Manager attempts to fetch values.
//
// Returning an error here is FATAL. It indicates the configuration
// is structurally unsound and the Manager should exit immediately.
type SecretPreparer interface {
	PrepareSecrets(h Hydrator) error
}

// SecretVerifier is implemented by structs that need to validate
// the data *after* the Secret Manager has populated the fields.
//
// This may be called multiple times (e.g. on rotation or retry).
// Returning an error here indicates the *current values* are invalid,
// potentially causing this specific config to be ignored/dropped until fixed.
type SecretVerifier interface {
	VerifySecrets() error
}

type Hydrator struct {
	fields  secretPaths
	manager *Manager
}

func (h Hydrator) OrFromFile(
	secretField *Field, filePath string) error {
	if h.manager == nil || h.manager.hydrating == false {
		panic("secret field is sealed by the manager; call this from PrepareSecrets")
	}
	if count(secretField != nil, len(filePath) > 0) == 2 {
		path := h.fields[secretField]
		return fmt.Errorf("at most one of %s & %s_file must be configured", path, path)
	}
	if len(filePath) > 0 {
		secretField = &Field{
			rawConfig: fmt.Sprintf(`file:
  file_path: %q
`, filePath),
		}
	}
	return nil
}
