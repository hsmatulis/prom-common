package secrets

import (
	"errors"
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
// Commented out as behaviour is not stable yet.
// type SecretVerifier interface {
// 	VerifySecrets() error
// }

type Hydrator struct {
	manager *Manager
	fields  fieldResults[*Field]
}

func runPreppers(m *Manager, cfg any) error {
	fields, err := findFields[*Field](cfg)
	if err != nil {
		return err
	}
	h := Hydrator{
		manager: m,
		fields:  fields,
	}

	preppers, err := findFields[SecretPreparer](cfg)
	if err != nil {
		return err
	}

	errs := make([]error, 0)
	for i := len(preppers.ordered) - 1; i >= 0; i-- {
		prep := preppers.ordered[i]
		if err := prep.PrepareSecrets(h); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)

}

func (h Hydrator) OrFromFile(
	secretField **Field, filePath string) error {
	if h.manager == nil || h.manager.hydrating == false {
		panic("secret field is sealed by the manager; call this from PrepareSecrets")
	}
	if count(secretField != nil && *secretField != nil, len(filePath) > 0) == 2 {
		path := h.fields.paths[*secretField]
		return fmt.Errorf("at most one of %s & %s_file must be configured", path, path)
	}
	if len(filePath) > 0 {
		cfg := map[string]any{
			"file": FileProviderConfig{
				Path: filePath,
			},
		}
		(*secretField) = &Field{}
		return convertConfig(cfg, &(*secretField).rawConfig)
	}

	return nil
}
