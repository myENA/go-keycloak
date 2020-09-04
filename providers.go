package keycloak

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"
)

const (
	// DefaultTokenExpirationMargin will be used if you do not specify your own ExpiryMargin key in the config
	DefaultTokenExpirationMargin = 2 * time.Second
)

var ErrTokenExpired = errors.New("token has expired")

func IsTokenExpiredErr(err error) bool {
	for err != nil {
		if errors.Is(err, ErrTokenExpired) {
			return true
		}
		err = errors.Unwrap(err)
	}
	return false
}

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

type staticAuthServerURLProvider string

func (ip staticAuthServerURLProvider) AuthServerURL() (string, error) {
	return string(ip), nil
}

// NewAuthServerURLProvider builds an AuthServerURLProvider that will set the issuer address value provided to this constructor,
// unless the context provided to the setter already contains an an issuer address key
func NewAuthServerURLProvider(authServerURL string) AuthServerURLProvider {
	return staticAuthServerURLProvider(authServerURL)
}

// NewAuthServerURLProviderWithURL will construct a new staticAuthServerURLProvider using the provided *url.URL
func NewAuthServerURLProviderWithURL(purl *url.URL) AuthServerURLProvider {
	if purl == nil {
		panic("why did you pass me a nil *url.URL...")
	}
	return NewAuthServerURLProvider(purl.String())
}

// NewEnvironmentIssuerProvider will attempt to read the specified variable from the environment
func NewEnvironmentIssuerProvider(varName string) AuthServerURLProvider {
	return NewAuthServerURLProvider(ensureEnvVar(varName))
}

func defaultIssuerProvider() AuthServerURLProvider {
	return NewAuthServerURLProvider("http://127.0.0.1/auth")
}

// RealmProvider
type RealmProvider interface {
	// RealmName must return either the name of the realm targeted by this client or a useful error
	RealmName() (string, error)
	EnvironmentConfig(*APIClient) (*RealmEnvironment, error)
}

type staticRealmProvider string

// NewRealmProvider will return to you a type of RealmProvider that, given that the incoming context does not
// already have a realm defined, will always set it to the value provided to this constructor
func NewRealmProvider(keycloakRealm string) RealmProvider {
	return staticRealmProvider(keycloakRealm)
}

// EnvironmentConfig attempts to construct
func (rp staticRealmProvider) EnvironmentConfig(client *APIClient) (*RealmEnvironment, error) {
	var (
		v   interface{}
		ok  bool
		env *RealmEnvironment
		err error

		cacheKey = buildRealmEnvCacheKey(client.AuthServerURL(), string(rp))
	)
	// fetch or build realm env config
	if v, ok = globalCache.Load(cacheKey); !ok {
		env = new(RealmEnvironment)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if env.oidc, err = client.OpenIDConfiguration(ctx, string(rp)); err != nil {
			return nil, fmt.Errorf("error fetching OpenID configuration: %w", err)
		}
		// this is allowed to fail, as uma2 support in keycloak is "new"
		ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		env.uma2c, _ = client.UMA2Configuration(ctx, string(rp))
		globalCache.Store(cacheKey, env)
	} else if env, ok = v.(*RealmEnvironment); !ok {
		return nil, fmt.Errorf("cached environment config for realm %q expected to be %T, saw %T", env, v)
	} else {
		env = v.(*RealmEnvironment)
	}

	return env, nil
}

// NewRealmProviderFromEnvironment will attempt to fetch the provided env key using os.GetEnv, creating a new
// RealmProvider with that as the value.
func NewRealmProviderFromEnvironment(varName string) RealmProvider {
	return staticRealmProvider(ensureEnvVar(varName))
}

// SetRealmValue will attempt to locate a pre-existing realm key on the provided context, returning the original
// context if one is found.  If not, it will return a new context with its own realm value defined.
func (rp staticRealmProvider) RealmName() (string, error) {
	return string(rp), nil
}

func defaultRealmProvider() RealmProvider {
	return NewRealmProvider("master")
}

// BearerTokenProvider
//
// A token provider is just that: a provider of tokens.
//
// The rules are simple:
// 	1. If a token value is returned, it will be considered valid and ready for use in requests
// 		1a. That is to say, no additional checks are done.  It will be used in the Authorization header as-is.
//	2. If a token has expired, it MUST return an ErrTokenExpired error, or an error wrapping that error
// 		2a. If the returned error stems from ErrTokenExpired, your provider may optionally implement the
//			RenewableBearerTokenProvider interface
//		2b. If any other error is returned, the call will immediately fail
type BearerTokenProvider interface {
	// Current must return either a valid bearer token suitable for immediate use or an error
	Current() (string, error)
}

type staticBearerTokenProvider string

// NewBearerTokenProvider returns a token provider implementation that returns a fixed token value.
func NewBearerTokenProvider(bearerToken string) BearerTokenProvider {
	return staticBearerTokenProvider(bearerToken)
}

func (st staticBearerTokenProvider) Current() (string, error) {
	return string(st), nil
}

func NewBearerTokenProviderFromEnvironment(varName string) BearerTokenProvider {
	return NewBearerTokenProvider(ensureEnvVar(varName))
}

type RenewableBearerTokenProvider interface {
	BearerTokenProvider
	Renew() (*OpenIDConnectTokenRequest, error)
}

// CombinedEnvironmentProvider describes any provider that can fulfill auth url, realm, and renewable bearer token roles
type CombinedEnvironmentProvider interface {
	AuthServerURLProvider
	RealmProvider
	RenewableBearerTokenProvider
}

// ConfidentialClientTokenProviderConfig must be provided to a new ConfidentialClientTokenProvider upon construction
type ConfidentialClientTokenProviderConfig struct {
	// ID [optional] (required if IDKey left blank)
	//
	// If you already have a confidential client install document handy, you may pass it in here.
	ID *InstallDocument `json:"id"`

	// ExpiryMargin [optional]
	//
	// The margin of safety prior to the actual deadline of the internal token to go ahead and execute a refresh
	ExpiryMargin time.Duration `json:"expiryMargin"`
}

// ConfidentialClientTokenProvider
//
// This provider implements the TokenProviderClientAware interface, and is designed to take care of the complexity of
// managing a confidential client token for you.
//
// Easiest way to implement would be the following:
//
//	conf := keycloak.ConfidentialClientTokenProviderConfig {
//		ID: {id document}
//	}
//  ctx, cancel := context.WithTimeout(context.Background(), 2 * time.Second)
//  defer cancel()
//  tokenClient, err := NewTokenAPIClientForConfidentialClient(ctx, nil, conf)
//  if err != nil {
// 		panic(err.Error())
//	}
//
// The above call returns to you a fully constructed TokenAPIClient that will utilize your provided install document
// for requests that require authentication
type ConfidentialClientTokenProvider struct {
	issuerAddr     string
	clientID       string
	clientSecret   string
	expiryMargin   time.Duration
	clientRealm    string
	token          *OpenIDConnectToken
	tokenRefreshed int64
	tokenExpiry    int64
}

// NewConfidentialClientTokenProvider will attempt to construct a new ConfidentialClientTokenProvider for you based on
// the provided configuration.
func NewConfidentialClientTokenProvider(conf *ConfidentialClientTokenProviderConfig) (*ConfidentialClientTokenProvider, error) {
	var (
		secret    interface{}
		secretStr string
		id        *InstallDocument
		ok        bool

		expiryMargin = DefaultTokenExpirationMargin
		tp           = new(ConfidentialClientTokenProvider)
	)

	if conf.ID == nil {
		return nil, errors.New("ID must be defined")
	}

	id = conf.ID

	// validate doc
	if len(id.Credentials) == 0 {
		return nil, errors.New("install document Credentials field is empty")
	}
	if secret, ok = id.Credentials["secret"]; !ok {
		return nil, errors.New("install document Credentials field is missing key \"secret\"")
	}
	if secretStr, ok = secret.(string); !ok {
		return nil, errors.New("install document Credentials field \"secret\" is not a string")
	}

	// did they override default expiry margin?
	if conf.ExpiryMargin > 0 {
		expiryMargin = conf.ExpiryMargin
	}

	tp.issuerAddr = id.AuthServerURL
	tp.clientID = id.Resource
	tp.clientRealm = id.Realm
	tp.clientSecret = secretStr
	tp.expiryMargin = expiryMargin

	return tp, nil
}

func (tp *ConfidentialClientTokenProvider) AuthServerURL() (string, error) {
	return tp.issuerAddr, nil
}

func (tp *ConfidentialClientTokenProvider) TargetRealm() string {
	return tp.clientRealm
}

// LastRefreshed returns a unix nano timestamp of the last time this client's bearer token was refreshed.
func (tp *ConfidentialClientTokenProvider) LastRefreshed() int64 {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	lr := tp.tokenRefreshed
	return lr
}

// Expiry returns a unix nano timestamp of when the current token, if defined, expires.
func (tp *ConfidentialClientTokenProvider) Expiry() int64 {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	e := tp.tokenExpiry
	return e
}

func (tp *ConfidentialClientTokenProvider) expired() bool {
	if tp.token == nil {
		return true
	}
	return time.Now().After(time.Unix(0, tp.tokenExpiry))
}

// Expired will return true if the currently stored token has expired
func (tp *ConfidentialClientTokenProvider) Expired() bool {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return tp.expired()
}

// RefreshToken provides an external way to manually refresh a bearer token
func (tp *ConfidentialClientTokenProvider) Renew(ctx context.Context, client RenewableTokenClient, force bool) error {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	// check if there is anything to actually do.
	if !force && !tp.expired() {
		return nil
	}

	var (
		oidc *OpenIDConnectToken
		err  error

		req = NewOpenIDConnectTokenRequest(GrantTypeClientCredentials)
	)

	// attempt to fetch a new openid token for our confidential client
	req.ClientID = tp.clientID
	req.ClientSecret = tp.clientSecret

	// fetch new oidc token
	if oidc, err = client.OpenIDConnectToken(ctx, nil, req); err != nil {
		return fmt.Errorf("unable to fetch OpenIDConnectToken: %w", err)
	}

	// try to refresh access token.  this has the side-effect of also validating our new token
	if _, err = client.ParseToken(ctx, oidc.AccessToken, nil); err != nil {
		return fmt.Errorf("unable to refresh access token: %w", err)
	}

	// if valid, update client
	tp.token = oidc
	tp.tokenRefreshed = time.Now().UnixNano()
	tp.tokenExpiry = time.Now().Add((time.Duration(oidc.ExpiresIn) * time.Second) - tp.expiryMargin).UnixNano()
	return nil
}

// SetTokenValue will first attempt to use the locally cached last-known-good token.  If not defined or beyond the
// expiration window, it will call RefreshToken before attempting to set the context token value.
func (tp *ConfidentialClientTokenProvider) Current() (string, error) {
	tp.mu.RLock()
	defer tp.mu.Unlock()
	if tp.expired() {
		return "", ErrTokenExpired
	}
	return tp.token.AccessToken, nil
}