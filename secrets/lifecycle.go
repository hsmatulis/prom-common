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
	"errors"
	"fmt"
)

// SecretPreparer is implemented by structs that need to mutate or validate
// their state before the Secret Manager attempts to fetch values.
//
// Returning an error here is FATAL. It indicates the configuration
// is structurally unsound and the Manager should exit immediately.
type SecretPreparer interface {
	PrepareSecrets(h Populator) error
}

type Populator struct {
	manager *Manager
	fields  fieldResults[*Field]
}

func runPreppers(m *Manager, cfg any) error {
	fields, err := findFields[*Field](cfg)
	if err != nil {
		return err
	}
	h := Populator{
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

func (h Populator) FromFieldOrFile(
	secretField *Field, filePath string,
) error {
	if h.manager == nil || !h.manager.populating {
		panic("FromFieldOrFile can only be called during PrepareSecrets; the manager has not yet started populating")
	}
	if count(secretField.rawConfig != nil, len(filePath) > 0) == 2 {
		path := h.fields.paths[secretField]
		return fmt.Errorf("at most one of %s & %s_file must be configured", path, path)
	}
	if len(filePath) > 0 {
		secretField.rawConfig = map[string]any{
			"file": FileProviderConfig{
				Path: filePath,
			},
		}
	}

	return nil
}
