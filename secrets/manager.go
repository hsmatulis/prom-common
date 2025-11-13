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
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	// fetchTimeout governs the maximum time a single fetch attempt can take.
	fetchTimeout = 5 * time.Minute
	// fetchInitialBackoff is the initial backoff duration for refetching a secret after a failure.
	fetchInitialBackoff = 1 * time.Second
	// fetchMaxBackoff is the maximum backoff duration for retrying a failed fetch.
	fetchMaxBackoff = 2 * time.Minute

	// the default refresh interval for secrets.
	defaultRefreshInterval = time.Hour

	// Prometheus secret states.
	stateSuccess      float64 = 0
	stateStale        float64 = 1
	stateError        float64 = 2
	stateInitializing float64 = 3
)

type Manager struct {
	MarshalInlineSecrets bool
	mtx                  sync.RWMutex
	secrets              map[*SecretField]*managedSecret
	refreshC             chan struct{}
	cancel               context.CancelFunc
	wg                   sync.WaitGroup
	// Prometheus metrics
	lastSuccessfulFetch *prometheus.GaugeVec
	secretState         *prometheus.GaugeVec
	fetchSuccessTotal   *prometheus.CounterVec
	fetchFailuresTotal  *prometheus.CounterVec
	fetchDuration       *prometheus.HistogramVec
}

type managedSecret struct {
	mtx              sync.RWMutex
	secret           string
	fetched          time.Time
	fetchInProgress  bool
	refreshInterval  time.Duration
	refreshRequested bool
	metricLabels     prometheus.Labels
	provider         Provider
}

// NewManager discovers all SecretField instances within the provided config
// structure using reflection and registers them with this manager.
func NewManager(r prometheus.Registerer, config interface{}) (*Manager, error) {
	paths, err := getSecretFields(config)
	if err != nil {
		return nil, err
	}
	manager := &Manager{
		secrets: make(map[*SecretField]*managedSecret),
	}
	manager.registerMetrics(r)
	for path, field := range paths {
		if err := manager.registerSecret(path, field); err != nil {
			return nil, err
		}
	}
	return manager, nil
}

func (m *Manager) registerMetrics(r prometheus.Registerer) {
	labels := []string{"provider", "secret_id"}

	m.lastSuccessfulFetch = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "prometheus_remote_secret_last_successful_fetch_seconds",
			Help: "The unix timestamp of the last successful secret fetch.",
		},
		labels,
	)
	m.secretState = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "prometheus_remote_secret_state",
			Help: "Describes the current state of a remotely fetched secret (0=success, 1=stale, 2=error, 3=initializing).",
		},
		labels,
	)
	m.fetchSuccessTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "prometheus_remote_secret_fetch_success_total",
			Help: "Total number of successful secret fetches.",
		},
		labels,
	)
	m.fetchFailuresTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "prometheus_remote_secret_fetch_failures_total",
			Help: "Total number of failed secret fetches.",
		},
		labels,
	)

	m.fetchDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "prometheus_remote_secret_fetch_duration_seconds",
			Help:    "Duration of secret fetch attempts.",
			Buckets: prometheus.DefBuckets,
		},
		labels,
	)

	// Register all metrics with the provided registry
	r.MustRegister(
		m.lastSuccessfulFetch,
		m.secretState,
		m.fetchSuccessTotal,
		m.fetchFailuresTotal,
		m.fetchDuration,
	)
}

func (m *Manager) registerSecret(path string, s *SecretField) error {
	s.manager = m

	m.mtx.Lock()
	defer m.mtx.Unlock()

	secretID := path
	if providerID, ok := s.providerConfig.(ProviderConfigID); ok {
		secretID = providerID.ID()
	}

	labels := prometheus.Labels{
		"provider":  s.providerName,
		"secret_id": secretID,
	}

	refreshInterval := s.settings.RefreshInterval
	if refreshInterval == 0 {
		refreshInterval = defaultRefreshInterval
	}

	provider, err := s.providerConfig.NewProvider()
	if err != nil {
		return err
	}

	ms := &managedSecret{
		refreshInterval: refreshInterval,
		metricLabels:    labels,
		provider:        provider,
	}
	m.secrets[s] = ms
	m.secretState.With(labels).Set(stateInitializing)
	m.fetchSuccessTotal.With(labels).Add(0)
	m.fetchFailuresTotal.With(labels).Add(0)
	return nil
}

func (m *Manager) secretReady(s *SecretField) bool {
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	ms := m.secrets[s]
	ready := !ms.fetched.IsZero()
	if ready {
		ms.mtx.RLock()
		s.resolvedSecret = ms.secret
		ms.mtx.RUnlock()
	}
	return ready
}

func (m *Manager) SecretsReady(config interface{}) (bool, error) {
	paths, err := getSecretFields(config)
	if err != nil {
		return false, err
	}
	allReady := true
	for _, field := range paths {
		if !m.secretReady(field) {
			allReady = false
		}
	}
	return allReady, nil
}

func (m *Manager) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.fetchSecretsLoop(ctx)
	}()

	m.cancel = cancel
}

func (m *Manager) Stop() {
	m.cancel()
	m.wg.Wait()
}

func (m *Manager) triggerRefresh(s *SecretField) {
	m.mtx.RLock()
	secret := m.secrets[s]
	m.mtx.RUnlock()
	secret.mtx.Lock()
	defer secret.mtx.Unlock()
	secret.refreshRequested = true
	select {
	case m.refreshC <- struct{}{}:
	default:
		// a refresh is already pending, do nothing
	}
}

// fetchSecretsLoop is a long-running goroutine that periodically fetches secrets.
func (m *Manager) fetchSecretsLoop(ctx context.Context) {
	timer := time.NewTimer(time.Duration(0))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-m.refreshC:
			if !timer.Stop() {
				<-timer.C
			}
		}
		m.mtx.RLock()
		// Create a list of secrets to check to avoid holding the lock during fetch operations.
		secretsToCheck := make([]*managedSecret, 0, len(m.secrets))
		for _, secret := range m.secrets {
			secretsToCheck = append(secretsToCheck, secret)
		}
		m.mtx.RUnlock()

		waitTime := 5 * time.Minute

		for _, ms := range secretsToCheck {
			ms.mtx.Lock()

			timeToRefresh := time.Until(ms.fetched.Add(ms.refreshInterval))
			refreshNeeded := ms.refreshRequested || timeToRefresh < 0
			waitTime = min(waitTime, ms.refreshInterval)

			if ms.fetchInProgress {
				ms.mtx.Unlock()
				continue
			}

			if !refreshNeeded {
				ms.mtx.Unlock()
				if timeToRefresh > 0 {
					waitTime = min(waitTime, timeToRefresh)
				}
				continue
			}
			ms.fetchInProgress = true
			ms.mtx.Unlock()

			go m.fetchAndStoreSecret(ctx, ms)
		}
		timer.Reset(waitTime)
	}
}

// fetchAndStoreSecret performs a single secret fetch, including retry logic with exponential backoff.
// It is robust against hangs in the underlying provider's FetchSecret method.
func (m *Manager) fetchAndStoreSecret(ctx context.Context, ms *managedSecret) {
	var newSecret string
	var err error
	ms.mtx.RLock()
	provider := ms.provider
	labels := ms.metricLabels
	hasBeenFetchedBefore := !ms.fetched.IsZero()
	ms.mtx.RUnlock()

	backoff := fetchInitialBackoff
	for {
		fetchCtx, cancel := context.WithTimeout(ctx, fetchTimeout)

		newSecret, err = provider.FetchSecret(fetchCtx)
		cancel()

		if err == nil {
			break // Success
		}

		m.fetchFailuresTotal.With(labels).Inc()
		if hasBeenFetchedBefore {
			m.secretState.With(labels).Set(stateStale)
		} else {
			m.secretState.With(labels).Set(stateError)
		}

		select {
		case <-time.After(backoff):
			backoff = min(fetchMaxBackoff, backoff*2)
		case <-ctx.Done():
			return
		}
	}
	ms.mtx.Lock()

	m.fetchSuccessTotal.With(labels).Inc()
	m.lastSuccessfulFetch.With(labels).SetToCurrentTime()
	m.secretState.With(labels).Set(stateSuccess)

	ms.secret = newSecret
	ms.fetched = time.Now()
	ms.fetchInProgress = false
	ms.refreshRequested = false
	ms.mtx.Unlock()
}
