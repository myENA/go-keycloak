package keycloak

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
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

func defaultAuthServerURLProvider() AuthServerURLProvider {
	return NewAuthServerURLProvider("http://127.0.0.1/auth")
}

type RealmProvider interface {
	RealmName() (string, error)
}

type staticRealmProvider string

func NewStaticRealmProvider(realmName string) RealmProvider {
	return staticRealmProvider(realmName)
}

func (rp staticRealmProvider) RealmName() (string, error) {
	return string(rp), nil
}

type BearerTokenProvider interface {
	BearerToken() (string, error)
}

type RenewableBearerTokenProvider interface {
	BearerTokenProvider
	RenewBearerToken(ctx context.Context, client *APIClient, force bool) error
}

type StaticBearerTokenProvider struct {
	bearerToken string
}

// NewStaticBearerTokenProvider returns a token provider implementation that returns a fixed token value.
func NewStaticBearerTokenProvider(bearerToken string) *StaticBearerTokenProvider {
	bt := new(StaticBearerTokenProvider)
	bt.bearerToken = bearerToken
	return bt
}

func (p StaticBearerTokenProvider) BearerToken() (string, error) {
	return p.bearerToken, nil
}

// CombinedProvider describes any provider that can fulfill auth url, realm, and renewable bearer token roles
type CombinedProvider interface {
	AuthServerURLProvider
	RealmProvider
	BearerTokenProvider
}

// ConfidentialClientTokenProviderConfig must be provided to a new ConfidentialClientTokenProvider upon construction
type ConfidentialClientTokenProviderConfig struct {
	// InstallDocument [optional]
	//
	// If you already have a confidential client install document handy, you may pass it in here.
	InstallDocument *InstallDocument `json:"id"`

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
//		InstallDocument: {id document}
//	}
//  ctx, cancel := context.WithTimeout(context.Background(), 2 * time.Second)
//  defer cancel()
//  tokenClient, err := NewTokenAPIClientForConfidentialClient(ctx, nil, conf)
//  if err != nil {
// 		panic(err.Error())
//	}
type ConfidentialClientTokenProvider struct {
	staticAuthServerURLProvider
	mu sync.RWMutex

	realmName      string
	clientID       string
	clientSecret   string
	expiryMargin   time.Duration
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

	if conf.InstallDocument == nil {
		return nil, errors.New("InstallDocument must be defined")
	}

	id = conf.InstallDocument

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

	tp.staticAuthServerURLProvider = NewAuthServerURLProvider(id.AuthServerURL).(staticAuthServerURLProvider)

	tp.realmName = id.Realm
	tp.clientID = id.Resource
	tp.clientSecret = secretStr
	tp.expiryMargin = expiryMargin

	return tp, nil
}

func (tp *ConfidentialClientTokenProvider) RealmName() (string, error) {
	return tp.realmName, nil
}

func (tp *ConfidentialClientTokenProvider) ClientID() string {
	return tp.clientID
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

// SetTokenValue will first attempt to use the locally cached last-known-good token.  If not defined or beyond the
// expiration window, it will call RefreshToken before attempting to set the context token value.
func (tp *ConfidentialClientTokenProvider) BearerToken() (string, error) {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	if tp.expired() {
		return "", ErrTokenExpired
	}
	return tp.token.AccessToken, nil
}

// RefreshToken provides an external way to manually refresh a bearer token
func (tp *ConfidentialClientTokenProvider) RenewBearerToken(ctx context.Context, client *APIClient, force bool) error {
	tp.mu.RLock()

	// check if there is anything to actually do.
	if !force && !tp.expired() {
		tp.mu.RUnlock()
		return nil
	}

	tp.mu.RUnlock()
	tp.mu.Lock()
	defer tp.mu.Unlock()

	// test to ensure that another routine did not grab the lock and already refresh the token.
	if !tp.expired() {
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
	if oidc, err = client.Login(ctx, req); err != nil {
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
