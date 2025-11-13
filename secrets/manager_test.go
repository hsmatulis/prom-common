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
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockProvider allows controlling the secret value and simulating errors for tests.
type mockProvider struct {
	mtx           sync.RWMutex
	secret        string
	fetchErr      error
	fetchedLatest bool
	blockChan     chan struct{}
	releaseChan   chan struct{}
}

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
	return mp.secret, mp.fetchErr
}

func (mp *mockProvider) setSecret(s string) {
	mp.mtx.Lock()
	defer mp.mtx.Unlock()
	mp.fetchedLatest = false
	mp.secret = s
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

type mockProviderConfig struct {
	provider *mockProvider
}

func newMockProviderConfig(secret string) *mockProviderConfig {
	return &mockProviderConfig{
		provider: &mockProvider{secret: secret},
	}
}

func (mpc *mockProviderConfig) NewProvider() (Provider, error) {
	return mpc.provider, nil
}

func (mpc *mockProviderConfig) Clone() ProviderConfig {
	return &mockProviderConfig{
		provider: mpc.provider,
	}
}

// testConfig is a struct used for discovering SecretFields in tests.
type testConfig struct {
	APIKeys []Field `yaml:"api_keys"`
}

func setupManagerTest(t *testing.T, cfg *testConfig) (*Manager, *prometheus.Registry) {
	// Register the mock provider for tests.
	originalProviders := Providers
	Providers = &ProviderRegistry{}
	Providers.Register("inline", &InlineProviderConfig{})
	Providers.Register("file", &FileProviderConfig{})
	Providers.Register("mock", &mockProviderConfig{})

	t.Cleanup(func() {
		Providers = originalProviders
	})

	reg := prometheus.NewRegistry()
	m, err := NewManager(reg, cfg)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)
	t.Cleanup(cancel)
	t.Cleanup(m.Stop)

	return m, reg
}

func TestNewManager(t *testing.T) {
	provider1 := newMockProviderConfig("secret1")
	provider2 := newMockProviderConfig("secret2")

	cfg := &testConfig{
		APIKeys: []Field{
			{providerConfig: provider1, providerName: "mock"},
			{providerConfig: provider2, providerName: "mock"},
			{providerConfig: &InlineProviderConfig{secret: "inline_secret"}, providerName: "inline"},
		},
	}

	reg := prometheus.NewRegistry()
	m, err := NewManager(reg, cfg)
	require.NoError(t, err)

	require.Lenf(t, m.secrets, 3, "Manager should discover 3 secrets")
	assert.NotNil(t, m.secrets[&cfg.APIKeys[0]])
	assert.NotNil(t, m.secrets[&cfg.APIKeys[1]])
	assert.NotNil(t, m.secrets[&cfg.APIKeys[2]])
}

func TestManager_SecretLifecycle(t *testing.T) {
	providerConfig := newMockProviderConfig("initial_secret")
	cfg := &testConfig{
		APIKeys: []Field{
			{
				providerConfig: providerConfig,
				providerName:   "mock",
				settings:       FieldSettings{RefreshInterval: 50 * time.Millisecond},
			},
		},
	}

	m, _ := setupManagerTest(t, cfg)

	// 1. Initial fetch
	require.Eventuallyf(t, providerConfig.provider.hasFetchedLatest, time.Second, 10*time.Millisecond, "Initial fetch should occur")
	ready, err := m.SecretsReady(cfg)
	require.NoError(t, err)
	assert.Truef(t, ready, "Secrets should be ready after initial fetch")
	assert.Equal(t, "initial_secret", cfg.APIKeys[0].Get())

	// 2. Scheduled refresh
	providerConfig.provider.setSecret("refreshed_secret")
	require.Eventuallyf(t, providerConfig.provider.hasFetchedLatest, time.Second, 10*time.Millisecond, "Scheduled refresh should occur")
	_, err = m.SecretsReady(cfg)
	require.NoError(t, err)
	assert.Equal(t, "refreshed_secret", cfg.APIKeys[0].Get())

	// 3. Triggered refresh
	providerConfig.provider.setSecret("triggered_secret")
	cfg.APIKeys[0].TriggerRefresh()
	require.Eventuallyf(t, providerConfig.provider.hasFetchedLatest, time.Second, 10*time.Millisecond, "Triggered refresh should occur")
	_, err = m.SecretsReady(cfg)
	require.NoError(t, err)
	assert.Equal(t, "triggered_secret", cfg.APIKeys[0].Get())
}

func TestManager_FetchErrorAndRecovery(t *testing.T) {
	providerConfig := newMockProviderConfig("")
	providerConfig.provider.setFetchError(errors.New("fetch failed"))
	cfg := &testConfig{
		APIKeys: []Field{
			{
				providerConfig: providerConfig,
				providerName:   "mock",
			},
		},
	}
	m, _ := setupManagerTest(t, cfg)

	// Initial fetch fails.
	require.Eventuallyf(t, providerConfig.provider.hasFetchedLatest, time.Second, 10*time.Millisecond, "A fetch should be attempted")
	assert.Emptyf(t, cfg.APIKeys[0].Get(), "Secret should be empty after failed fetch")

	ready, err := m.SecretsReady(cfg)
	require.NoError(t, err)
	assert.Falsef(t, ready, "Secrets should not be ready after failed fetch")

	// Recovery.
	providerConfig.provider.setFetchError(nil)
	providerConfig.provider.setSecret("recovered_secret")
	require.Eventuallyf(t, func() bool {
		ready, err := m.SecretsReady(cfg)
		require.NoError(t, err)
		return ready
	}, 2*time.Second, 50*time.Millisecond, "Manager should recover after error")

	assert.Equal(t, "recovered_secret", cfg.APIKeys[0].Get())
	ready, err = m.SecretsReady(cfg)
	require.NoError(t, err)
	assert.Truef(t, ready, "Secrets should be ready after recovery")
}

func TestManager_InlineSecret(t *testing.T) {
	inlineSecret := "this-is-inline"
	cfg := &testConfig{
		APIKeys: []Field{
			{
				providerConfig: &InlineProviderConfig{secret: inlineSecret},
				providerName:   "inline",
				resolvedSecret: inlineSecret,
			},
		},
	}
	setupManagerTest(t, cfg)

	assert.Equal(t, inlineSecret, cfg.APIKeys[0].Get())
}
