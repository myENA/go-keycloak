package keycloak

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	// DefaultTokenExpirationMargin will be used if you do not specify your own ExpiryMargin key in the config
	DefaultTokenExpirationMargin = 2 * time.Second
)

// TokenProvider
//
// This interface describes any implementation that can provide a bearer token to the given context.
type TokenProvider interface {
	// BearerToken must return either a valid bearer token suitable for immediate use or an error
	BearerToken(context.Context, *RealmAPIClient) (string, error)
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
//	tp, err := keycloak.NewConfidentialClientTokenProvider(&conf)
//	if err != nil {
//		panic(err.Error())
//	}
// 	apiClient, err := keycloak.NewAPIClient(&keycloak.APIClientConfig{TokenProvider: tp})
//
// Now, every request called off of the APIClient will be automatically decorated with the correct bearer token,
// assuming your install document is valid.
type ConfidentialClientTokenProvider struct {
	mu sync.Mutex

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

	tp.clientID = id.Resource
	tp.clientRealm = id.Realm
	tp.clientSecret = secretStr
	tp.expiryMargin = expiryMargin

	return tp, nil
}

// LastRefreshed returns a unix nano timestamp of the last time this client's bearer token was refreshed.
func (tp *ConfidentialClientTokenProvider) LastRefreshed() int64 {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	lr := tp.tokenRefreshed
	return lr
}

// Expiry returns a unix nano timestamp of when the current token, if defined, expires.
func (tp *ConfidentialClientTokenProvider) Expiry() int64 {
	tp.mu.Lock()
	defer tp.mu.Unlock()
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

func (tp *ConfidentialClientTokenProvider) doRefresh(ctx context.Context, client *RealmAPIClient) (string, error) {
	var (
		oidc *OpenIDConnectToken
		err  error

		req = NewOpenIDConnectTokenRequest(GrantTypeClientCredentials)
	)

	// attempt to fetch a new openid token for our confidential client
	req.ClientID = tp.clientID
	req.ClientSecret = tp.clientSecret

	// fetch new oidc token
	if oidc, err = client.AuthService().OpenIDConnectToken(ctx, req); err != nil {
		return "", fmt.Errorf("unable to fetch OpenIDConnectToken: %w", err)
	}

	// try to refresh access token.  this has the side-effect of also validating our new token
	if _, err = client.AuthService().ParseToken(ctx, oidc.AccessToken, nil); err != nil {
		return "", fmt.Errorf("unable to refresh access token: %w", err)
	}

	// if valid, update client
	tp.token = oidc
	tp.tokenRefreshed = time.Now().UnixNano()
	tp.tokenExpiry = time.Now().Add((time.Duration(oidc.ExpiresIn) * time.Second) - tp.expiryMargin).UnixNano()
	return tp.token.AccessToken, nil
}

// RefreshToken provides an external way to manually refresh a bearer token
func (tp *ConfidentialClientTokenProvider) RefreshToken(ctx context.Context, client *RealmAPIClient) (string, error) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return tp.doRefresh(ctx, client)
}

// SetTokenValue will first attempt to use the locally cached last-known-good token.  If not defined or beyond the
// expiration window, it will call RefreshToken before attempting to set the context token value.
func (tp *ConfidentialClientTokenProvider) BearerToken(ctx context.Context, client *RealmAPIClient) (string, error) {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	var (
		token string
		err   error
	)

	if tp.expired() {
		token, err = tp.doRefresh(ctx, client)
	} else {
		token = tp.token.AccessToken
	}

	return token, err
}
