// Copyright 2016 The Prometheus Authors
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

package config

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mwitkow/go-conntrack"
	"github.com/prometheus/common/secrets"
	"go.yaml.in/yaml/v2"
	"golang.org/x/net/http/httpproxy"
	"golang.org/x/net/http2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	grantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

var (
	// DefaultHTTPClientConfig is the default HTTP client configuration.
	DefaultHTTPClientConfig = HTTPClientConfig{
		FollowRedirects: true,
		EnableHTTP2:     true,
	}

	// defaultHTTPClientOptions holds the default HTTP client options.
	defaultHTTPClientOptions = httpClientOptions{
		keepAlivesEnabled: true,
		http2Enabled:      true,
		// 5 minutes is typically above the maximum sane scrape interval. So we can
		// use keepalive for all configurations.
		idleConnTimeout:  5 * time.Minute,
		newTLSConfigFunc: NewTLSConfigWithContext,
	}
)

type closeIdler interface {
	CloseIdleConnections()
}

type TLSVersion uint16

var TLSVersions = map[string]TLSVersion{
	"TLS13": (TLSVersion)(tls.VersionTLS13),
	"TLS12": (TLSVersion)(tls.VersionTLS12),
	"TLS11": (TLSVersion)(tls.VersionTLS11),
	"TLS10": (TLSVersion)(tls.VersionTLS10),
}

func (tv *TLSVersion) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	err := unmarshal(&s)
	if err != nil {
		return err
	}
	if v, ok := TLSVersions[s]; ok {
		*tv = v
		return nil
	}
	return fmt.Errorf("unknown TLS version: %s", s)
}

func (tv TLSVersion) MarshalYAML() (interface{}, error) {
	for s, v := range TLSVersions {
		if tv == v {
			return s, nil
		}
	}
	return nil, fmt.Errorf("unknown TLS version: %d", tv)
}

// MarshalJSON implements the json.Unmarshaler interface for TLSVersion.
func (tv *TLSVersion) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if v, ok := TLSVersions[s]; ok {
		*tv = v
		return nil
	}
	return fmt.Errorf("unknown TLS version: %s", s)
}

// MarshalJSON implements the json.Marshaler interface for TLSVersion.
func (tv TLSVersion) MarshalJSON() ([]byte, error) {
	for s, v := range TLSVersions {
		if tv == v {
			return json.Marshal(s)
		}
	}
	return nil, fmt.Errorf("unknown TLS version: %d", tv)
}

// String implements the fmt.Stringer interface for TLSVersion.
func (tv *TLSVersion) String() string {
	if tv == nil || *tv == 0 {
		return ""
	}
	for s, v := range TLSVersions {
		if *tv == v {
			return s
		}
	}
	return fmt.Sprintf("%d", tv)
}

// BasicAuth contains basic HTTP authentication credentials.
type BasicAuth struct {
	Username     *secrets.Field `yaml:"username" json:"username"`
	UsernameFile string         `yaml:"username_file,omitempty" json:"username_file,omitempty"`
	Password     *secrets.Field `yaml:"password,omitempty" json:"password,omitempty"`
	PasswordFile string         `yaml:"password_file,omitempty" json:"password_file,omitempty"`
}

func (c *BasicAuth) PrepareSecrets(h secrets.Hydrator) error {
	return errors.Join(
		h.OrFromFile(c.Username, c.UsernameFile),
		h.OrFromFile(c.Password, c.PasswordFile))
}

// SetDirectory joins any relative file paths with dir.
func (a *BasicAuth) SetDirectory(dir string) {
	if a == nil {
		return
	}
	a.PasswordFile = JoinDir(dir, a.PasswordFile)
	a.UsernameFile = JoinDir(dir, a.UsernameFile)
}

// Authorization contains HTTP authorization credentials.
type Authorization struct {
	Type            string         `yaml:"type,omitempty" json:"type,omitempty"`
	Credentials     *secrets.Field `yaml:"credentials,omitempty" json:"credentials,omitempty"`
	CredentialsFile string         `yaml:"credentials_file,omitempty" json:"credentials_file,omitempty"`
}

func (a *Authorization) PrepareSecrets(h secrets.Hydrator) error {
	return h.OrFromFile(a.Credentials, a.CredentialsFile)
}

// SetDirectory joins any relative file paths with dir.
func (a *Authorization) SetDirectory(dir string) {
	if a == nil {
		return
	}
	a.CredentialsFile = JoinDir(dir, a.CredentialsFile)
}

// URL is a custom URL type that allows validation at configuration load time.
type URL struct {
	*url.URL
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for URLs.
func (u *URL) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}

	urlp, err := url.Parse(s)
	if err != nil {
		return err
	}
	u.URL = urlp
	return nil
}

// MarshalYAML implements the yaml.Marshaler interface for URLs.
func (u URL) MarshalYAML() (interface{}, error) {
	if u.URL != nil {
		return u.Redacted(), nil
	}
	return nil, nil
}

// Redacted returns the URL but replaces any password with "xxxxx".
func (u URL) Redacted() string {
	if u.URL == nil {
		return ""
	}

	ru := *u.URL
	if _, ok := ru.User.Password(); ok {
		// We can not use secretToken because it would be escaped.
		ru.User = url.UserPassword(ru.User.Username(), "xxxxx")
	}
	return ru.String()
}

// UnmarshalJSON implements the json.Marshaler interface for URL.
func (u *URL) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	urlp, err := url.Parse(s)
	if err != nil {
		return err
	}
	u.URL = urlp
	return nil
}

// MarshalJSON implements the json.Marshaler interface for URL.
func (u URL) MarshalJSON() ([]byte, error) {
	if u.URL != nil {
		return json.Marshal(u.String())
	}
	return []byte("null"), nil
}

// OAuth2 is the oauth2 client configuration.
type OAuth2 struct {
	ClientID                 string         `yaml:"client_id" json:"client_id"`
	ClientSecret             *secrets.Field `yaml:"client_secret" json:"client_secret"`
	ClientSecretFile         string         `yaml:"client_secret_file" json:"client_secret_file"`
	ClientCertificateKeyID   string         `yaml:"client_certificate_key_id" json:"client_certificate_key_id"`
	ClientCertificateKey     *secrets.Field `yaml:"client_certificate_key" json:"client_certificate_key"`
	ClientCertificateKeyFile string         `yaml:"client_certificate_key_file" json:"client_certificate_key_file"`
	// GrantType is the OAuth2 grant type to use. It can be one of
	// "client_credentials" or "urn:ietf:params:oauth:grant-type:jwt-bearer" (RFC 7523).
	// Default value is "client_credentials"
	GrantType string `yaml:"grant_type" json:"grant_type"`
	// SignatureAlgorithm is the RSA algorithm used to sign JWT token. Only used if
	// GrantType is set to "urn:ietf:params:oauth:grant-type:jwt-bearer".
	// Default value is RS256 and valid values RS256, RS384, RS512
	SignatureAlgorithm string `yaml:"signature_algorithm,omitempty" json:"signature_algorithm,omitempty"`
	// Iss is the OAuth client identifier used when communicating with
	// the configured OAuth provider. Default value is client_id. Only used if
	// GrantType is set to "urn:ietf:params:oauth:grant-type:jwt-bearer".
	Iss string `yaml:"iss,omitempty" json:"iss,omitempty"`
	// Audience optionally specifies the intended audience of the
	// request.  If empty, the value of TokenURL is used as the
	// intended audience. Only used if
	// GrantType is set to "urn:ietf:params:oauth:grant-type:jwt-bearer".
	Audience string `yaml:"audience,omitempty" json:"audience,omitempty"`
	// Claims is a map of claims to be added to the JWT token. Only used if
	// GrantType is set to "urn:ietf:params:oauth:grant-type:jwt-bearer".
	Claims         map[string]interface{} `yaml:"claims,omitempty" json:"claims,omitempty"`
	Scopes         []string               `yaml:"scopes,omitempty" json:"scopes,omitempty"`
	TokenURL       string                 `yaml:"token_url" json:"token_url"`
	EndpointParams map[string]string      `yaml:"endpoint_params,omitempty" json:"endpoint_params,omitempty"`
	TLSConfig      TLSConfig              `yaml:"tls_config,omitempty"`
	ProxyConfig    `yaml:",inline"`
}

func (o *OAuth2) PrepareSecrets(h secrets.Hydrator) error {
	return errors.Join(
		h.OrFromFile(o.ClientSecret, o.ClientSecretFile),
		h.OrFromFile(o.ClientCertificateKey, o.ClientCertificateKeyFile))
}

// SetDirectory joins any relative file paths with dir.
func (o *OAuth2) SetDirectory(dir string) {
	if o == nil {
		return
	}
	o.ClientSecretFile = JoinDir(dir, o.ClientSecretFile)
	o.TLSConfig.SetDirectory(dir)
}

// LoadHTTPConfig parses the YAML input s into a HTTPClientConfig.
func LoadHTTPConfig(s string) (*HTTPClientConfig, error) {
	cfg := &HTTPClientConfig{}
	err := yaml.UnmarshalStrict([]byte(s), cfg)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadHTTPConfigFile parses the given YAML file into a HTTPClientConfig.
func LoadHTTPConfigFile(filename string) (*HTTPClientConfig, []byte, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, nil, err
	}
	cfg, err := LoadHTTPConfig(string(content))
	if err != nil {
		return nil, nil, err
	}
	cfg.SetDirectory(filepath.Dir(filepath.Dir(filename)))
	return cfg, content, nil
}

// HTTPClientConfig configures an HTTP client.
type HTTPClientConfig struct {
	// The HTTP basic authentication credentials for the targets.
	BasicAuth *BasicAuth `yaml:"basic_auth,omitempty" json:"basic_auth,omitempty"`
	// The HTTP authorization credentials for the targets.
	Authorization *Authorization `yaml:"authorization,omitempty" json:"authorization,omitempty"`
	// The OAuth2 client credentials used to fetch a token for the targets.
	OAuth2 *OAuth2 `yaml:"oauth2,omitempty" json:"oauth2,omitempty"`
	// The bearer token for the targets. Deprecated in favour of
	// Authorization.Credentials.
	BearerToken *secrets.Field `yaml:"bearer_token,omitempty" json:"bearer_token,omitempty"`
	// The bearer token file for the targets. Deprecated in favour of
	// Authorization.CredentialsFile.
	BearerTokenFile string `yaml:"bearer_token_file,omitempty" json:"bearer_token_file,omitempty"`
	// TLSConfig to use to connect to the targets.
	TLSConfig TLSConfig `yaml:"tls_config,omitempty" json:"tls_config,omitempty"`
	// FollowRedirects specifies whether the client should follow HTTP 3xx redirects.
	// The omitempty flag is not set, because it would be hidden from the
	// marshalled configuration when set to false.
	FollowRedirects bool `yaml:"follow_redirects" json:"follow_redirects"`
	// EnableHTTP2 specifies whether the client should configure HTTP2.
	// The omitempty flag is not set, because it would be hidden from the
	// marshalled configuration when set to false.
	EnableHTTP2 bool `yaml:"enable_http2" json:"enable_http2"`
	// Proxy configuration.
	ProxyConfig `yaml:",inline"`
	// HTTPHeaders specify headers to inject in the requests. Those headers
	// could be marshalled back to the users.
	HTTPHeaders *Headers `yaml:"http_headers,omitempty" json:"http_headers,omitempty"`
}

// SetDirectory joins any relative file paths with dir.
func (c *HTTPClientConfig) SetDirectory(dir string) {
	if c == nil {
		return
	}
	c.TLSConfig.SetDirectory(dir)
	c.BasicAuth.SetDirectory(dir)
	c.Authorization.SetDirectory(dir)
	c.OAuth2.SetDirectory(dir)
	c.HTTPHeaders.SetDirectory(dir)
	c.BearerTokenFile = JoinDir(dir, c.BearerTokenFile)
}

// nonZeroCount returns the amount of values that are non-zero.
func nonZeroCount[T comparable](values ...T) int {
	count := 0
	var zero T
	for _, value := range values {
		if value != zero {
			count++
		}
	}
	return count
}

func (c *HTTPClientConfig) PrepareSecrets(h secrets.Hydrator) error {
	return h.OrFromFile(c.BearerToken, c.BearerTokenFile)
}

// Validate validates the HTTPClientConfig to check only one of BearerToken,
// BasicAuth and BearerTokenFile is configured. It also validates that ProxyURL
// is set if ProxyConnectHeader is set.
func (c *HTTPClientConfig) Validate() error {
	// Backwards compatibility with the bearer_token field.
	if (c.BasicAuth != nil || c.OAuth2 != nil) && c.BearerToken != nil {
		return errors.New("at most one of basic_auth, oauth2, bearer_token & bearer_token_file must be configured")
	}
	if c.Authorization != nil {
		if c.BearerToken != nil {
			return errors.New("authorization is not compatible with bearer_token & bearer_token_file")
		}
		c.Authorization.Type = strings.TrimSpace(c.Authorization.Type)
		if len(c.Authorization.Type) == 0 {
			c.Authorization.Type = "Bearer"
		}
		if strings.ToLower(c.Authorization.Type) == "basic" {
			return errors.New(`authorization type cannot be set to "basic", use "basic_auth" instead`)
		}
		if c.BasicAuth != nil || c.OAuth2 != nil {
			return errors.New("at most one of basic_auth, oauth2 & authorization must be configured")
		}
	} else {
		if c.BearerToken != nil {
			c.Authorization = &Authorization{Credentials: c.BearerToken, Type: "Bearer"}
			c.BearerToken = nil
		}
	}
	if c.OAuth2 != nil {
		if c.BasicAuth != nil {
			return errors.New("at most one of basic_auth, oauth2 & authorization must be configured")
		}
		if len(c.OAuth2.ClientID) == 0 {
			return errors.New("oauth2 client_id must be configured")
		}
		if len(c.OAuth2.TokenURL) == 0 {
			return errors.New("oauth2 token_url must be configured")
		}
		if c.OAuth2.GrantType == grantTypeJWTBearer {
			if c.OAuth2.SignatureAlgorithm != "" && !slices.Contains(validSignatureAlgorithm, c.OAuth2.SignatureAlgorithm) {
				return errors.New("valid signature algorithms are RS256, RS384 and RS512")
			}
		}
	}
	if err := c.ProxyConfig.Validate(); err != nil {
		return err
	}
	if c.HTTPHeaders != nil {
		if err := c.HTTPHeaders.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (a *BasicAuth) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain BasicAuth
	return unmarshal((*plain)(a))
}

// DialContextFunc defines the signature of the DialContext() function implemented
// by net.Dialer.
type DialContextFunc func(context.Context, string, string) (net.Conn, error)

// NewTLSConfigFunc returns tls.Config.
type NewTLSConfigFunc func(context.Context, *TLSConfig) (*tls.Config, error)

type httpClientOptions struct {
	dialContextFunc   DialContextFunc
	newTLSConfigFunc  NewTLSConfigFunc
	keepAlivesEnabled bool
	http2Enabled      bool
	idleConnTimeout   time.Duration
	userAgent         string
	host              string
}

// HTTPClientOption defines an option that can be applied to the HTTP client.
type HTTPClientOption interface {
	applyToHTTPClientOptions(options *httpClientOptions)
}

type httpClientOptionFunc func(options *httpClientOptions)

func (f httpClientOptionFunc) applyToHTTPClientOptions(options *httpClientOptions) {
	f(options)
}

// WithDialContextFunc allows you to override the func gets used for the dialing.
// The default is `net.Dialer.DialContext`.
func WithDialContextFunc(fn DialContextFunc) HTTPClientOption {
	return httpClientOptionFunc(func(opts *httpClientOptions) {
		opts.dialContextFunc = fn
	})
}

// WithNewTLSConfigFunc allows you to override the func that creates the TLS config
// from the prometheus http config.
// The default is `NewTLSConfigWithContext`.
func WithNewTLSConfigFunc(newTLSConfigFunc NewTLSConfigFunc) HTTPClientOption {
	return httpClientOptionFunc(func(opts *httpClientOptions) {
		opts.newTLSConfigFunc = newTLSConfigFunc
	})
}

// WithKeepAlivesDisabled allows to disable HTTP keepalive.
func WithKeepAlivesDisabled() HTTPClientOption {
	return httpClientOptionFunc(func(opts *httpClientOptions) {
		opts.keepAlivesEnabled = false
	})
}

// WithHTTP2Disabled allows to disable HTTP2.
func WithHTTP2Disabled() HTTPClientOption {
	return httpClientOptionFunc(func(opts *httpClientOptions) {
		opts.http2Enabled = false
	})
}

// WithIdleConnTimeout allows setting the idle connection timeout.
func WithIdleConnTimeout(timeout time.Duration) HTTPClientOption {
	return httpClientOptionFunc(func(opts *httpClientOptions) {
		opts.idleConnTimeout = timeout
	})
}

// WithUserAgent allows setting the user agent.
func WithUserAgent(ua string) HTTPClientOption {
	return httpClientOptionFunc(func(opts *httpClientOptions) {
		opts.userAgent = ua
	})
}

// WithHost allows setting the host header.
func WithHost(host string) HTTPClientOption {
	return httpClientOptionFunc(func(opts *httpClientOptions) {
		opts.host = host
	})
}

// NewClient returns a http.Client using the specified http.RoundTripper.
func newClient(rt http.RoundTripper) *http.Client {
	return &http.Client{Transport: rt}
}

// NewClientFromConfig returns a new HTTP client configured for the
// given config.HTTPClientConfig and config.HTTPClientOption.
// The name is used as go-conntrack metric label.
func NewClientFromConfig(cfg HTTPClientConfig, name string, optFuncs ...HTTPClientOption) (*http.Client, error) {
	rt, err := NewRoundTripperFromConfig(cfg, name, optFuncs...)
	if err != nil {
		return nil, err
	}
	client := newClient(rt)
	if !cfg.FollowRedirects {
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client, nil
}

// NewRoundTripperFromConfig returns a new HTTP RoundTripper configured for the
// given config.HTTPClientConfig and config.HTTPClientOption.
// The name is used as go-conntrack metric label.
func NewRoundTripperFromConfig(cfg HTTPClientConfig, name string, optFuncs ...HTTPClientOption) (http.RoundTripper, error) {
	return NewRoundTripperFromConfigWithContext(context.Background(), cfg, name, optFuncs...)
}

// NewRoundTripperFromConfigWithContext returns a new HTTP RoundTripper configured for the
// given config.HTTPClientConfig and config.HTTPClientOption.
// The name is used as go-conntrack metric label.
func NewRoundTripperFromConfigWithContext(ctx context.Context, cfg HTTPClientConfig, name string, optFuncs ...HTTPClientOption) (http.RoundTripper, error) {
	opts := defaultHTTPClientOptions
	for _, opt := range optFuncs {
		opt.applyToHTTPClientOptions(&opts)
	}

	var dialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	if opts.dialContextFunc != nil {
		dialContext = conntrack.NewDialContextFunc(
			conntrack.DialWithDialContextFunc((func(context.Context, string, string) (net.Conn, error))(opts.dialContextFunc)),
			conntrack.DialWithTracing(),
			conntrack.DialWithName(name))
	} else {
		dialContext = conntrack.NewDialContextFunc(
			conntrack.DialWithTracing(),
			conntrack.DialWithName(name))
	}

	newRT := func(tlsConfig *tls.Config) (http.RoundTripper, error) {
		// The only timeout we care about is the configured scrape timeout.
		// It is applied on request. So we leave out any timings here.
		var rt http.RoundTripper = &http.Transport{
			Proxy:                 cfg.Proxy(),
			ProxyConnectHeader:    cfg.GetProxyConnectHeader(),
			MaxIdleConns:          20000,
			MaxIdleConnsPerHost:   1000, // see https://github.com/golang/go/issues/13801
			DisableKeepAlives:     !opts.keepAlivesEnabled,
			TLSClientConfig:       tlsConfig,
			DisableCompression:    true,
			IdleConnTimeout:       opts.idleConnTimeout,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DialContext:           dialContext,
		}
		if opts.http2Enabled && cfg.EnableHTTP2 {
			http2t, err := http2.ConfigureTransports(rt.(*http.Transport))
			if err != nil {
				return nil, err
			}
			http2t.ReadIdleTimeout = time.Minute
		}

		// If a authorization_credentials is provided, create a round tripper that will set the
		// Authorization header correctly on each request.
		if cfg.Authorization != nil {
			rt = NewAuthorizationCredentialsRoundTripper(cfg.Authorization.Type, cfg.Authorization.Credentials, rt)
		}
		// Backwards compatibility, be nice with importers who would not have
		// called unmarshalled from yaml.
		if cfg.BearerToken != nil {
			rt = NewAuthorizationCredentialsRoundTripper("Bearer", cfg.BearerToken, rt)
		}

		if cfg.BasicAuth != nil {
			rt = NewBasicAuthRoundTripper(cfg.BasicAuth.Username, cfg.BasicAuth.Password, rt)
		}

		if cfg.OAuth2 != nil {
			var (
				oauthCredential *secrets.Field
			)

			if cfg.OAuth2.GrantType == grantTypeJWTBearer {
				oauthCredential = cfg.OAuth2.ClientCertificateKey
			} else {
				oauthCredential = cfg.OAuth2.ClientSecret
			}
			rt = NewOAuth2RoundTripper(oauthCredential, cfg.OAuth2, rt, &opts)
		}

		if cfg.HTTPHeaders != nil {
			rt = NewHeadersRoundTripper(cfg.HTTPHeaders, rt)
		}

		if opts.userAgent != "" {
			rt = NewUserAgentRoundTripper(opts.userAgent, rt)
		}

		if opts.host != "" {
			rt = NewHostRoundTripper(opts.host, rt)
		}

		if cfg.HTTPHeaders != nil {
			rt = NewHeadersRoundTripper(cfg.HTTPHeaders, rt)
		}
		// Return a new configured RoundTripper.
		return rt, nil
	}

	tlsConfig, err := opts.newTLSConfigFunc(ctx, &cfg.TLSConfig)
	if err != nil {
		return nil, err
	}
	return newRT(tlsConfig)
}

type authorizationCredentialsRoundTripper struct {
	authType        string
	authCredentials *secrets.Field
	rt              http.RoundTripper
}

// NewAuthorizationCredentialsRoundTripper adds the authorization credentials
// read from the provided *secrets.Field to a request unless the authorization header
// has already been set.
func NewAuthorizationCredentialsRoundTripper(authType string, authCredentials *secrets.Field, rt http.RoundTripper) http.RoundTripper {
	return &authorizationCredentialsRoundTripper{authType, authCredentials, rt}
}

func (rt *authorizationCredentialsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if len(req.Header.Get("Authorization")) != 0 {
		return rt.rt.RoundTrip(req)
	}

	req = cloneRequest(req)
	req.Header.Set("Authorization", fmt.Sprintf("%s %s", rt.authType, rt.authCredentials.ValueOrEmpty()))

	return rt.rt.RoundTrip(req)
}

func (rt *authorizationCredentialsRoundTripper) CloseIdleConnections() {
	if ci, ok := rt.rt.(closeIdler); ok {
		ci.CloseIdleConnections()
	}
}

type basicAuthRoundTripper struct {
	username *secrets.Field
	password *secrets.Field
	rt       http.RoundTripper
}

// NewBasicAuthRoundTripper will apply a BASIC auth authorization header to a request unless it has
// already been set.
func NewBasicAuthRoundTripper(username, password *secrets.Field, rt http.RoundTripper) http.RoundTripper {
	return &basicAuthRoundTripper{username, password, rt}
}

func (rt *basicAuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if len(req.Header.Get("Authorization")) != 0 {
		return rt.rt.RoundTrip(req)
	}
	req = cloneRequest(req)
	req.SetBasicAuth(rt.username.ValueOrEmpty(), rt.password.ValueOrEmpty())
	return rt.rt.RoundTrip(req)
}

func (rt *basicAuthRoundTripper) CloseIdleConnections() {
	if ci, ok := rt.rt.(closeIdler); ok {
		ci.CloseIdleConnections()
	}
}

type oauth2RoundTripper struct {
	mtx        sync.RWMutex
	lastRT     *oauth2.Transport
	lastSecret string

	// Required for interaction with Oauth2 server.
	config          *OAuth2
	oauthCredential *secrets.Field
	opts            *httpClientOptions
	client          *http.Client
}

func NewOAuth2RoundTripper(oauthCredential *secrets.Field, config *OAuth2, next http.RoundTripper, opts *httpClientOptions) http.RoundTripper {
	return &oauth2RoundTripper{
		config: config,
		// A correct tokenSource will be added later on.
		lastRT:          &oauth2.Transport{Base: next},
		opts:            opts,
		oauthCredential: oauthCredential,
	}
}

type oauth2TokenSourceConfig interface {
	TokenSource(ctx context.Context) oauth2.TokenSource
}

func (rt *oauth2RoundTripper) newOauth2TokenSource(req *http.Request, clientCredential string) (client *http.Client, source oauth2.TokenSource, err error) {
	tlsConfig, err := NewTLSConfig(&rt.config.TLSConfig)
	if err != nil {
		return nil, nil, err
	}

	tlsTransport := func(tlsConfig *tls.Config) (http.RoundTripper, error) {
		return &http.Transport{
			TLSClientConfig:       tlsConfig,
			Proxy:                 rt.config.Proxy(),
			ProxyConnectHeader:    rt.config.GetProxyConnectHeader(),
			DisableKeepAlives:     !rt.opts.keepAlivesEnabled,
			MaxIdleConns:          20,
			MaxIdleConnsPerHost:   1, // see https://github.com/golang/go/issues/13801
			IdleConnTimeout:       10 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}, nil
	}

	var t http.RoundTripper
	t, _ = tlsTransport(tlsConfig)
	if ua := req.UserAgent(); ua != "" {
		t = NewUserAgentRoundTripper(ua, t)
	}

	var config oauth2TokenSourceConfig

	if rt.config.GrantType == grantTypeJWTBearer {
		// RFC 7523 3.1 - JWT authorization grants
		// RFC 7523 3.2 - Client Authentication Processing is not implement upstream yet,
		// see https://github.com/golang/oauth2/pull/745

		var sig *jwt.SigningMethodRSA
		switch rt.config.SignatureAlgorithm {
		case jwt.SigningMethodRS256.Name:
			sig = jwt.SigningMethodRS256
		case jwt.SigningMethodRS384.Name:
			sig = jwt.SigningMethodRS384
		case jwt.SigningMethodRS512.Name:
			sig = jwt.SigningMethodRS512
		default:
			sig = jwt.SigningMethodRS256
		}

		iss := rt.config.Iss
		if iss == "" {
			iss = rt.config.ClientID
		}
		config = &JwtGrantTypeConfig{
			PrivateKey:       []byte(clientCredential),
			PrivateKeyID:     rt.config.ClientCertificateKeyID,
			Scopes:           rt.config.Scopes,
			TokenURL:         rt.config.TokenURL,
			SigningAlgorithm: sig,
			Iss:              iss,
			Subject:          rt.config.ClientID,
			Audience:         rt.config.Audience,
			PrivateClaims:    rt.config.Claims,
			EndpointParams:   mapToValues(rt.config.EndpointParams),
		}
	} else {
		config = &clientcredentials.Config{
			ClientID:       rt.config.ClientID,
			ClientSecret:   clientCredential,
			Scopes:         rt.config.Scopes,
			TokenURL:       rt.config.TokenURL,
			EndpointParams: mapToValues(rt.config.EndpointParams),
		}
	}
	client = &http.Client{Transport: t}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)
	return client, config.TokenSource(ctx), nil
}

func (rt *oauth2RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	var (
		needsInit bool
	)

	rt.mtx.RLock()
	needsInit = rt.lastRT.Source == nil
	rt.mtx.RUnlock()

	// Fetch the secret if it's our first run or always if the secret can change.
	if needsInit {
		newSecret := rt.oauthCredential.ValueOrEmpty()
		// It's a first run. Rebuilt oauth2 setup.
		client, source, err := rt.newOauth2TokenSource(req, newSecret)
		if err != nil {
			return nil, err
		}

		rt.mtx.Lock()
		rt.lastRT.Source = source
		rt.client = client
		rt.mtx.Unlock()
	}

	rt.mtx.RLock()
	currentRT := rt.lastRT
	rt.mtx.RUnlock()
	return currentRT.RoundTrip(req)
}

func (rt *oauth2RoundTripper) CloseIdleConnections() {
	if rt.client != nil {
		rt.client.CloseIdleConnections()
	}
	if ci, ok := rt.lastRT.Base.(closeIdler); ok {
		ci.CloseIdleConnections()
	}
}

func mapToValues(m map[string]string) url.Values {
	v := url.Values{}
	for name, value := range m {
		v.Set(name, value)
	}

	return v
}

// cloneRequest returns a clone of the provided *http.Request.
// The clone is a shallow copy of the struct and its Header map.
func cloneRequest(r *http.Request) *http.Request {
	// Shallow copy of the struct.
	r2 := new(http.Request)
	*r2 = *r
	// Deep copy of the Header.
	r2.Header = make(http.Header)
	for k, s := range r.Header {
		r2.Header[k] = s
	}
	return r2
}

// NewTLSConfig creates a new tls.Config from the given TLSConfig.
func NewTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	return NewTLSConfigWithContext(context.Background(), cfg)
}

// NewTLSConfigWithContext creates a new tls.Config from the given TLSConfig.
func NewTLSConfigWithContext(ctx context.Context, cfg *TLSConfig) (*tls.Config, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		MinVersion:         uint16(cfg.MinVersion),
		MaxVersion:         uint16(cfg.MaxVersion),
	}

	if cfg.MaxVersion != 0 && cfg.MinVersion != 0 {
		if cfg.MaxVersion < cfg.MinVersion {
			return nil, errors.New("tls_config.max_version must be greater than or equal to tls_config.min_version if both are specified")
		}
	}

	// If a CA cert is provided then let's read it in so we can validate the
	// scrape target's certificate properly.
	if cfg.CA != nil {
		if !updateRootCA(tlsConfig, []byte(cfg.CA.Value())) {
			return nil, fmt.Errorf("unable to use specified CA cert %s", cfg.CA)
		}
	}

	if len(cfg.ServerName) > 0 {
		tlsConfig.ServerName = cfg.ServerName
	}

	// If a client cert & key is provided then configure TLS config accordingly.
	if nonZeroCount(cfg.CA, cfg.Key) == 2 {
		// Verify that client cert and key are valid.
		if _, err := cfg.getClientCertificate(); err != nil {
			return nil, err
		}
		tlsConfig.GetClientCertificate = func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return cfg.getClientCertificate()
		}
	}

	return tlsConfig, nil
}

// TLSConfig configures the options for TLS connections.
type TLSConfig struct {
	// Text of the CA cert to use for the targets.
	CA *secrets.Field `yaml:"ca,omitempty" json:"ca,omitempty"`
	// Text of the client cert file for the targets.
	Cert *secrets.Field `yaml:"cert,omitempty" json:"cert,omitempty"`
	// Text of the client key file for the targets.
	Key *secrets.Field `yaml:"key,omitempty" json:"key,omitempty"`
	// The CA cert to use for the targets.
	CAFile string `yaml:"ca_file,omitempty" json:"ca_file,omitempty"`
	// The client cert file for the targets.
	CertFile string `yaml:"cert_file,omitempty" json:"cert_file,omitempty"`
	// The client key file for the targets.
	KeyFile string `yaml:"key_file,omitempty" json:"key_file,omitempty"`
	// Used to verify the hostname for the targets.
	ServerName string `yaml:"server_name,omitempty" json:"server_name,omitempty"`
	// Disable target certificate validation.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`
	// Minimum TLS version.
	MinVersion TLSVersion `yaml:"min_version,omitempty" json:"min_version,omitempty"`
	// Maximum TLS version.
	MaxVersion TLSVersion `yaml:"max_version,omitempty" json:"max_version,omitempty"`
}

// SetDirectory joins any relative file paths with dir.
func (c *TLSConfig) SetDirectory(dir string) {
	if c == nil {
		return
	}
	c.CAFile = JoinDir(dir, c.CAFile)
	c.CertFile = JoinDir(dir, c.CertFile)
	c.KeyFile = JoinDir(dir, c.KeyFile)
}

func (c *TLSConfig) PrepareSecrets(h secrets.Hydrator) error {
	return errors.Join(
		c.Validate(),
		h.OrFromFile(c.CA, c.CAFile),
		h.OrFromFile(c.Cert, c.CertFile),
		h.OrFromFile(c.Key, c.KeyFile),
	)
}

// Validate validates the TLSConfig to check that only one of the inlined or
// file-based fields for the TLS CA, client certificate, and client key are
// used.
func (c *TLSConfig) Validate() error {
	if nonZeroCount(c.Cert, c.Key) == 1 {
		return errors.New("Client certificate and client key must be both configured, or both not")
	}
	return nil
}

func (c *TLSConfig) roundTripperSettings() TLSRoundTripperSettings {
	return TLSRoundTripperSettings{
		CA:   c.CA,
		Cert: c.Cert,
		Key:  c.Key,
	}
}

// getClientCertificate reads the pair of client cert and key and returns a tls.Certificate.
func (c *TLSConfig) getClientCertificate() (*tls.Certificate, error) {

	certData := c.Cert.ValueOrEmpty()
	keyData := c.Key.ValueOrEmpty()

	cert, err := tls.X509KeyPair([]byte(certData), []byte(keyData))
	if err != nil {
		return nil, fmt.Errorf("unable to use specified client cert (%s) & key (%s): %w", c.Cert, c.Key, err)
	}

	return &cert, nil
}

// updateRootCA parses the given byte slice as a series of PEM encoded certificates and updates tls.Config.RootCAs.
func updateRootCA(cfg *tls.Config, b []byte) bool {
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(b) {
		return false
	}
	cfg.RootCAs = caCertPool
	return true
}

// tlsRoundTripper is a RoundTripper that updates automatically its TLS
// configuration whenever the content of the CA file changes.
type tlsRoundTripper struct {
	settings TLSRoundTripperSettings

	// newRT returns a new RoundTripper.
	newRT func(*tls.Config) (http.RoundTripper, error)

	mtx          sync.RWMutex
	rt           http.RoundTripper
	hashCAData   []byte
	hashCertData []byte
	hashKeyData  []byte
	tlsConfig    *tls.Config
}

type TLSRoundTripperSettings struct {
	CA   *secrets.Field
	Cert *secrets.Field
	Key  *secrets.Field
}

type userAgentRoundTripper struct {
	userAgent string
	rt        http.RoundTripper
}

type hostRoundTripper struct {
	host string
	rt   http.RoundTripper
}

// NewUserAgentRoundTripper adds the user agent every request header.
func NewUserAgentRoundTripper(userAgent string, rt http.RoundTripper) http.RoundTripper {
	return &userAgentRoundTripper{userAgent, rt}
}

// NewHostRoundTripper sets the [http.Request.Host] of every request.
func NewHostRoundTripper(host string, rt http.RoundTripper) http.RoundTripper {
	return &hostRoundTripper{host, rt}
}

func (rt *userAgentRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = cloneRequest(req)
	req.Header.Set("User-Agent", rt.userAgent)
	return rt.rt.RoundTrip(req)
}

func (rt *userAgentRoundTripper) CloseIdleConnections() {
	if ci, ok := rt.rt.(closeIdler); ok {
		ci.CloseIdleConnections()
	}
}

func (rt *hostRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = cloneRequest(req)
	req.Host = rt.host
	req.Header.Set("Host", rt.host)
	return rt.rt.RoundTrip(req)
}

func (rt *hostRoundTripper) CloseIdleConnections() {
	if ci, ok := rt.rt.(closeIdler); ok {
		ci.CloseIdleConnections()
	}
}

func (c HTTPClientConfig) String() string {
	b, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Sprintf("<error creating http client config string: %s>", err)
	}
	return string(b)
}

type ProxyConfig struct {
	// HTTP proxy server to use to connect to the targets.
	ProxyURL URL `yaml:"proxy_url,omitempty" json:"proxy_url,omitempty"`
	// NoProxy contains addresses that should not use a proxy.
	NoProxy string `yaml:"no_proxy,omitempty" json:"no_proxy,omitempty"`
	// ProxyFromEnvironment makes use of net/http ProxyFromEnvironment function
	// to determine proxies.
	ProxyFromEnvironment bool `yaml:"proxy_from_environment,omitempty" json:"proxy_from_environment,omitempty"`
	// ProxyConnectHeader optionally specifies headers to send to
	// proxies during CONNECT requests. Assume that at least _some_ of
	// these headers are going to contain secrets and use Secret as the
	// value type instead of string.
	ProxyConnectHeader ProxyHeader `yaml:"proxy_connect_header,omitempty" json:"proxy_connect_header,omitempty"`

	proxyFunc func(*http.Request) (*url.URL, error)
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *ProxyConfig) Validate() error {
	if len(c.ProxyConnectHeader) > 0 && (!c.ProxyFromEnvironment && (c.ProxyURL.URL == nil || c.ProxyURL.String() == "")) {
		return errors.New("if proxy_connect_header is configured, proxy_url or proxy_from_environment must also be configured")
	}
	if c.ProxyFromEnvironment && c.ProxyURL.URL != nil && c.ProxyURL.String() != "" {
		return errors.New("if proxy_from_environment is configured, proxy_url must not be configured")
	}
	if c.ProxyFromEnvironment && c.NoProxy != "" {
		return errors.New("if proxy_from_environment is configured, no_proxy must not be configured")
	}
	if c.ProxyURL.URL == nil && c.NoProxy != "" {
		return errors.New("if no_proxy is configured, proxy_url must also be configured")
	}
	return nil
}

// Proxy returns the Proxy URL for a request.
func (c *ProxyConfig) Proxy() (fn func(*http.Request) (*url.URL, error)) {
	if c == nil {
		return nil
	}
	defer func() {
		fn = c.proxyFunc
	}()
	if c.proxyFunc != nil {
		return fn
	}
	if c.ProxyFromEnvironment {
		proxyFn := httpproxy.FromEnvironment().ProxyFunc()
		c.proxyFunc = func(req *http.Request) (*url.URL, error) {
			return proxyFn(req.URL)
		}
		return fn
	}
	if c.ProxyURL.URL != nil && c.ProxyURL.String() != "" {
		if c.NoProxy == "" {
			c.proxyFunc = http.ProxyURL(c.ProxyURL.URL)
			return fn
		}
		proxy := &httpproxy.Config{
			HTTPProxy:  c.ProxyURL.String(),
			HTTPSProxy: c.ProxyURL.String(),
			NoProxy:    c.NoProxy,
		}
		proxyFn := proxy.ProxyFunc()
		c.proxyFunc = func(req *http.Request) (*url.URL, error) {
			return proxyFn(req.URL)
		}
	}
	return fn
}

// ProxyConnectHeader() return the Proxy Connext Headers.
func (c *ProxyConfig) GetProxyConnectHeader() http.Header {
	return c.ProxyConnectHeader.HTTPHeader()
}
