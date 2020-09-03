package keycloak

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
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

// TokenProvider
//
// A token provider is just that: a provider of tokens.
//
// The rules are simple:
// 	1. If a token value is returned, it will be considered valid and ready for use in requests
// 		1a. That is to say, no additional checks are done.  It will be used in the Authorization header as-is.
//	2. If a token has expired, it MUST return an ErrTokenExpired error, or an error wrapping that error
// 		2a. If the returned error stems from ErrTokenExpired, your provider may optionally implement the
//			RenewableTokenProvider interface
//		2b. If any other error is returned, the call will immediately fail
type TokenProvider interface {
	// BearerToken must return either a valid bearer token suitable for immediate use or an error
	BearerToken() (string, error)
}

// RenewableTokenClient describes any client that is suitable for being used with a RenewableTokenProvider
type RenewableTokenClient interface {
	OpenIDConnectToken(context.Context, TokenProvider, *OpenIDConnectTokenRequest, ...RequestMutator) (*OpenIDConnectToken, error)
	ParseToken(context.Context, string, jwt.Claims) (*jwt.Token, error)
}

// RenewableTokenProvider
//
// A RenewableTokenProvider is intended for use with long-running processes, most likely a Confidential Client, where
// the credentials are fairly static or can be fetched from an external source and then used to refresh the bearer
// token session in Keycloak.
//
// Refresh is only required to attempt a refresh if either the token has expired or force is set to true
type RenewableTokenProvider interface {
	TokenProvider
	Renew(ctx context.Context, client RenewableTokenClient, force bool) error
}

// FullStateTokenProvider is intended for user with a confidential client install document that contains the target
// issuer address and realm name.  It allows for an easier path to a TokenAPIClient.
type FullStateTokenProvider interface {
	TokenProvider
	AuthServerURLProvider
	TargetRealm() string
}

type staticTokenProvider string

// NewTokenProvider returns a token provider implementation that returns a fixed token value.
func NewTokenProvider(bearerToken string) TokenProvider {
	return staticTokenProvider(bearerToken)
}

func (st staticTokenProvider) BearerToken() (string, error) {
	return string(st), nil
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
	mu sync.RWMutex

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
func (tp *ConfidentialClientTokenProvider) BearerToken() (string, error) {
	tp.mu.RLock()
	defer tp.mu.Unlock()
	if tp.expired() {
		return "", ErrTokenExpired
	}
	return tp.token.AccessToken, nil
}
