package secrets

import "testing"

func MockField(inline string) Field {
	if !testing.Testing() {
		panic("Mock can only be used for testing")
	}
	return Field{
		rawConfig: inline,
		state: &fieldState{
			path:         "mocked_path",
			providerName: InlineProviderName,
			value:        inline,
		},
	}
}
