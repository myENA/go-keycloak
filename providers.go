package keycloak

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// AuthServerURLProvider defines a single-user provider that is called once during client initialization, and is
// expected to return the full address and any path prefix for the target keycloak server.
//
// For example, if your hostname is example.com and you have keycloak behind a proxy that looks for the "/auth" path,
// the value returned from this must be "https://example.com/auth", or an error.
type AuthServerURLProvider interface {
	// AuthServerURL must set the key defined by ContextKeyIssuerAddress in the context, returning a descriptive
	// error if it was unable to do so
	AuthServerURL() (string, error)
}

type StaticAuthServerURL string

func (ip StaticAuthServerURL) AuthServerURL() (string, error) {
	return string(ip), nil
}

// NewAuthServerURLProvider builds an AuthServerURLProvider that will set the issuer address value provided to this constructor,
// unless the context provided to the setter already contains an an issuer address key
func NewAuthServerURLProvider(authServerURL string) StaticAuthServerURL {
	return StaticAuthServerURL(authServerURL)
}

// NewAuthServerURLProviderWithURL will construct a new StaticAuthServerURL using the provided *url.URL
func NewAuthServerURLProviderWithURL(purl *url.URL) StaticAuthServerURL {
	if purl == nil {
		panic("why did you pass me a nil *url.URL...")
	}
	return NewAuthServerURLProvider(purl.String())
}

func defaultAuthServerURLProvider() StaticAuthServerURL {
	return NewAuthServerURLProvider("http://127.0.0.1/auth")
}

type AuthenticationProvider interface {
	// RequestMutators must return the list of mutators necessary to decorate a request with a usable credential or fail
	// with an error
	RequestMutators(context.Context, *APIClient) ([]APIRequestMutator, error)
}

type BearerTokenProvider string

// NewBearerTokenProvider returns a AuthenticationProvider implementation that returns a fixed token value.
func NewBearerTokenProvider(bearerToken string) BearerTokenProvider {
	return BearerTokenProvider(bearerToken)
}

func NewBearerTokenProviderFromRequest(request *http.Request) (BearerTokenProvider, error) {
	var (
		bt string
		ok bool
	)
	if bt, ok = RequestBearerToken(request); ok {
		return NewBearerTokenProvider(bt), nil
	}
	return "", errors.New("missing bearer token in request")
}

func (p BearerTokenProvider) RequestMutators(_ context.Context, _ *APIClient) ([]APIRequestMutator, error) {
	return []APIRequestMutator{BearerAuthRequestMutator(string(p))}, nil
}

// CombinedProvider describes any provider that can fulfill auth url and auth provider roles
type CombinedProvider interface {
	AuthServerURLProvider
	AuthenticationProvider
}

// ClientSecretProviderConfig must be provided to a new ClientSecretProvider upon construction
type ClientSecretProviderConfig struct {
	// AuthServerURL [required] - Full domain and any path prefix to Keycloak server
	AuthServerURL string `json:"authServerURL"`
	// Realm [required] - Name of realm within Keycloak that contains this client
	Realm string `json:"realm"`
	// Resource [required] - client id of client (not uuid id)
	Resource string `json:"resource"`
	// Secret [required] - Authentication secret of client
	Secret string `json:"secret"`
	// ExpiryMargin [optional] - Margin of time before absolute expiration to execute a refresh
	ExpiryMargin time.Duration `json:"expiryMargin"`
}

func NewClientSecretConfigWithInstallDocument(id *InstallDocument) ClientSecretProviderConfig {
	return ClientSecretProviderConfig{
		AuthServerURL: id.AuthServerURL,
		Realm:         id.Realm,
		Resource:      id.Resource,
		Secret:        id.Credentials["secret"],
	}
}

// ClientSecretProvider
//
// This provider implements the CombinedProvider interface, and is designed to take care of the complexity of managing a
// confidential client token for you.
//
// Easiest way to implement would be the following:
//
//	conf := keycloak.NewClientSecretConfigWithInstallDocument({install document})
//  prov, err := NewClientSecretAuthenticationProvider(conf)
//  if err != nil {
// 		panic(err.Error())
//	}
type ClientSecretProvider struct {
	AuthServerURLProvider

	mu sync.RWMutex

	realmName          string
	clientID           string
	clientSecret       string
	expiryMargin       time.Duration
	token              *OpenIDConnectToken
	tokenRefreshed     time.Time
	tokenExpiry        time.Time
	tokenRefreshExpiry time.Time
}

// NewClientSecretAuthenticationProvider will attempt to construct a new ClientSecretProvider for you based on
// the provided configuration.
func NewClientSecretAuthenticationProvider(conf ClientSecretProviderConfig) (*ClientSecretProvider, error) {
	var (
		expiryMargin = DefaultTokenExpirationMargin
		tp           = new(ClientSecretProvider)
	)

	if conf.AuthServerURL == "" {
		return nil, errors.New("conf.AuthServerURL is required")
	}
	if conf.Realm == "" {
		return nil, errors.New("conf.Realm is required")
	}
	if conf.Resource == "" {
		return nil, errors.New("conf.Resource is required")
	}
	if conf.Secret == "" {
		return nil, errors.New("conf.Secret is required")
	}

	// did they override default expiry margin?
	if conf.ExpiryMargin > 0 {
		expiryMargin = conf.ExpiryMargin
	}

	tp.AuthServerURLProvider = NewAuthServerURLProvider(conf.AuthServerURL)
	tp.realmName = conf.Realm
	tp.clientID = conf.Resource
	tp.clientSecret = conf.Secret
	tp.expiryMargin = expiryMargin

	return tp, nil
}

func (p *ClientSecretProvider) Realm() (string, error) {
	return p.realmName, nil
}

func (p *ClientSecretProvider) ClientID() string {
	return p.clientID
}

func (p *ClientSecretProvider) Current(ctx context.Context, client *APIClient) (OpenIDConnectToken, error) {
	p.mu.RLock()

	// check if there is anything to actually do.
	if !p.expired() {
		defer p.mu.RUnlock()
		return *p.token, nil
	}

	p.mu.RUnlock()
	p.mu.Lock()
	defer p.mu.Unlock()

	// test to ensure that another routine did not grab the lock and already refresh the token.
	if !p.expired() {
		return *p.token, nil
	}

	var (
		oidc *OpenIDConnectToken
		err  error

		req = NewOpenIDConnectTokenRequest(GrantTypeClientCredentials)
	)

	// attempt to fetch a new openid token for our confidential client
	req.ClientID = p.clientID
	req.ClientSecret = p.clientSecret

	// if the refresh token is not expired perform a call with grant_type=refresh_token
	if p.token != nil && time.Now().Before(p.tokenRefreshExpiry) {
		req.GrantType = GrantTypeRefreshToken
		req.RefreshToken = p.token.RefreshToken
	}

	// fetch new oidc token
	if oidc, err = client.Login(ctx, req, p.realmName); err != nil {
		return OpenIDConnectToken{}, fmt.Errorf("unable to fetch OpenIDConnectToken: %w", err)
	}

	// update client with new token
	now := time.Now()
	p.token = oidc
	p.tokenRefreshed = now
	p.tokenExpiry = now.Add((time.Duration(oidc.ExpiresIn) * time.Second) - p.expiryMargin)
	p.tokenRefreshExpiry = now.Add((time.Duration(oidc.RefreshExpiresIn) * time.Second) - p.expiryMargin)
	return *p.token, nil
}

// LastRefreshed returns a unix nano timestamp of the last time this client's bearer token was refreshed.
func (p *ClientSecretProvider) LastRefreshed() int64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	lr := p.tokenRefreshed
	return lr.Unix()
}

// Expiry returns a unix nano timestamp of when the current token, if defined, expires.
func (p *ClientSecretProvider) Expiry() int64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	e := p.tokenExpiry
	return e.Unix()
}

func (p *ClientSecretProvider) expired() bool {
	return p.token == nil || time.Now().After(p.tokenExpiry)
}

// Expired will return true if the currently stored token has expired
func (p *ClientSecretProvider) Expired() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.expired()
}

// AuthMutators handles token refresh and builds a list of mutators to be applied to an outgoing authenticated request
func (p *ClientSecretProvider) RequestMutators(ctx context.Context, client *APIClient) ([]APIRequestMutator, error) {
	if token, err := p.Current(ctx, client); err != nil {
		return nil, err
	} else {
		return []APIRequestMutator{BearerAuthRequestMutator(token.AccessToken)}, nil
	}
}
