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
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v2"
)

func (mp *mockProvider) FetchSecret(ctx context.Context) (string, error) {
	// Block if the test requires it, to simulate fetch latency.
	if mp.blockChan != nil {
		select {
		case <-mp.blockChan:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}

	// Release if the test requires it, to signal fetch has started.
	if mp.releaseChan != nil {
		close(mp.releaseChan)
	}

	mp.mtx.RLock()
	defer mp.mtx.RUnlock()
	mp.fetchedLatest = true
	return mp.Secret, mp.fetchErr
}

func (mp *mockProvider) setSecret(s string) {
	mp.mtx.Lock()
	defer mp.mtx.Unlock()
	mp.fetchedLatest = false
	mp.Secret = s
}

func (mp *mockProvider) setFetchError(err error) {
	mp.mtx.Lock()
	defer mp.mtx.Unlock()
	mp.fetchedLatest = false
	mp.fetchErr = err
}

func (mp *mockProvider) hasFetchedLatest() bool {
	mp.mtx.Lock()
	defer mp.mtx.Unlock()
	return mp.fetchedLatest
}

type mockProvider struct {
	Secret        string `yaml:"secret"`
	Id            string `yaml:"id"`
	mtx           *sync.RWMutex
	fetchErr      error
	fetchedLatest bool
	blockChan     chan struct{}
	releaseChan   chan struct{}
}

func (mpc *mockProvider) NewProvider() (Provider, error) {
	return mpc, nil
}

func (mpc *mockProvider) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err == nil {
		mpc.Secret = s
		return nil
	}
	type plain mockProvider
	return unmarshal((*plain)(mpc))
}

func (mpc *mockProvider) ID() string {
	if len(mpc.Id) > 0 {
		return mpc.Id
	}
	return mpc.Secret
}

func (mpc *mockProvider) Clone() ProviderConfig {
	mtx := mpc.mtx
	if mtx == nil {
		mtx = &sync.RWMutex{}
	}
	return &mockProvider{
		Secret:        mpc.Secret,
		fetchErr:      mpc.fetchErr,
		mtx:           mtx,
		fetchedLatest: mpc.fetchedLatest,
		blockChan:     mpc.blockChan,
		releaseChan:   mpc.releaseChan,
	}
}

// testConfig is a struct used for discovering SecretFields in tests.
type testConfig struct {
	APIKeys []Field `yaml:"api_keys"`
}

func parseConfig[T any](t *testing.T, content string) *T {
	var cfg T
	require.NoError(t, yaml.Unmarshal([]byte(content), &cfg))
	return &cfg
}

func setupManagerTest[T any](t *testing.T, content string, mockPrototype *mockProvider) (*Manager, *T, func() *T) {
	reg := prometheus.NewRegistry()
	t.Cleanup(func() {
		currentPolicy = func() bool { return true }
		policyInitialized = atomic.Bool{}
	})

	providerReg := &ProviderRegistry{}
	providerReg.Register("inline", &InlineProviderConfig{})
	providerReg.Register("file", &FileProviderConfig{})
	providerReg.Register("mock", mockPrototype)

	cfg := parseConfig[T](t, content)

	m, err := NewManager(promslog.NewNopLogger(), reg, providerReg, cfg)
	require.NoError(t, err)

	m.Start(t.Context())
	return m, cfg, func() *T {
		// Hydrate
		cfg := parseConfig[T](t, content)
		require.NoError(t, m.HydrateConfig(cfg))
		return cfg
	}
}

func fetchMockProvider(t *testing.T, field Field) *mockProvider {
	config, ok := field.state.config.(*mockProvider)
	require.Truef(t, ok, "fetching non-mock provider")
	return config
}

func TestNewManager(t *testing.T) {
	content := `
api_keys:
  - mock: secret1
  - mock: secret2
  - "inline_secret"
`

	m, cfg, _ := setupManagerTest[testConfig](t, content, &mockProvider{})

	require.Lenf(t, m.secrets, 3, "Manager should discover 3 secrets")

	assert.Equal(t, "mock>secret1", cfg.APIKeys[0].state.id())
	assert.Equal(t, "mock>secret2", cfg.APIKeys[1].state.id())
	assert.Equal(t, "inline>testConfig.APIKeys[2]", cfg.APIKeys[2].state.id())
	assert.NotNil(t, m.secrets[cfg.APIKeys[0].state.id()])
	assert.NotNil(t, m.secrets[cfg.APIKeys[1].state.id()])
	assert.NotNil(t, m.secrets[cfg.APIKeys[2].state.id()])
}

func TestManager_SecretLifecycle(t *testing.T) {
	content := `
api_keys:
  - mock: initial_secret
    refreshInterval: 50ms
`
	_, cfg, hydrate := setupManagerTest[testConfig](t, content, &mockProvider{Id: "stable"})
	mock := fetchMockProvider(t, cfg.APIKeys[0])

	// 1. Initial fetch
	require.Eventuallyf(t, mock.hasFetchedLatest, time.Second, 10*time.Millisecond, "Initial fetch should occur")
	cfg = hydrate()
	assert.Equal(t, "initial_secret", cfg.APIKeys[0].Value())

	// 2. Scheduled refresh
	mock.setSecret("refreshed_secret")
	require.Eventuallyf(t, mock.hasFetchedLatest, time.Second, 10*time.Millisecond, "Scheduled refresh should occur")

	cfg = hydrate()
	assert.Equal(t, "refreshed_secret", cfg.APIKeys[0].Value())

	// 3. Triggered refresh
	mock.setSecret("triggered_secret")
	cfg.APIKeys[0].TriggerRefresh()
	require.Eventuallyf(t, mock.hasFetchedLatest, time.Second, 10*time.Millisecond, "Triggered refresh should occur")
	cfg = hydrate()
	assert.Equal(t, "triggered_secret", cfg.APIKeys[0].Value())
}

func TestManager_FetchErrorAndRecovery(t *testing.T) {
	content := `
api_keys:
  - mock: ""
`
	_, cfg, hydrate := setupManagerTest[testConfig](t, content, &mockProvider{
		fetchErr: errors.New("fetch failed"),
		Id:       "stable",
	})
	mock := fetchMockProvider(t, cfg.APIKeys[0])

	// Initial fetch fails.
	assert.Truef(t, mock.hasFetchedLatest(), "A fetch should have been attempted")
	assert.Emptyf(t, cfg.APIKeys[0].Value(), "Secret should be empty after failed fetch")

	// Recovery.
	mock.setFetchError(nil)
	mock.setSecret("recovered_secret")
	require.Eventuallyf(t, func() bool {
		return hydrate().APIKeys[0].Value() == "recovered_secret"
	}, 2*time.Second, 50*time.Millisecond, "Manager should eventually get the correct secret")
}

func TestManager_InlineSecret(t *testing.T) {
	inlineSecret := "this-is-inline"
	content := fmt.Sprintf(`
api_keys:
  - "%s"
`, inlineSecret)
	_, cfg, _ := setupManagerTest[testConfig](t, content, &mockProvider{})
	assert.Equal(t, inlineSecret, cfg.APIKeys[0].Value())
}
