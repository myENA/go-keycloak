package keycloak

import (
	"context"
	"fmt"
	"sync"
	"time"
)

func buildRealmEnvironment(ctx context.Context, client *APIClient) (*RealmEnvironment, error) {
	var err error
	// if we land here, we're the one to build the cache entry
	env := new(RealmEnvironment)
	if env.oidc, err = client.OpenIDConfiguration(ctx); err != nil {
		// ensure we unlock before returning
		return nil, fmt.Errorf("error fetching OpenID configuration: %w", err)
	}
	// this is allowed to fail, as uma2 support in keycloak is "new"
	env.uma2c, _ = client.UMA2Configuration(ctx)
	return env, nil
}

// RealmEnvironmentProvider
type RealmEnvironmentProvider interface {
	RealmEnvironment(ctx context.Context, client *APIClient) (*RealmEnvironment, error)
}

type OnceRealmEnvironmentProvider struct {
	mu  sync.RWMutex
	env *RealmEnvironment
}

func NewOnceRealmEnvironmentProvider() *OnceRealmEnvironmentProvider {
	rp := new(OnceRealmEnvironmentProvider)
	return rp
}

func (rp *OnceRealmEnvironmentProvider) RealmEnvironment(ctx context.Context, client *APIClient) (*RealmEnvironment, error) {
	rp.mu.RLock()
	// first, check to see if env config already retrieved
	if rp.env != nil {
		// if so, unlock and return
		defer rp.mu.RUnlock()
		return rp.env, nil
	}
	// otherwise, acquire full lock
	rp.mu.RUnlock()
	rp.mu.Lock()
	defer rp.mu.Unlock()
	// test for env being nil as its possible another process already acquired full lock and retrieved between the above
	// runlock -> lock cycle
	if rp.env == nil {
		var err error
		if rp.env, err = buildRealmEnvironment(ctx, client); err != nil {
			return nil, err
		}
	}
	return rp.env, nil
}

type CachedRealmEnvironmentProvider struct {
	mu          sync.RWMutex
	envCacheTTL time.Duration
}

// NewCachedRealmEnvironmentProvider will return to you a type of RealmEnvironmentProvider that, given that the incoming context does not
// already have a realm defined, will always set it to the value provided to this constructor
func NewCachedRealmEnvironmentProvider(envCacheTTL time.Duration) *CachedRealmEnvironmentProvider {
	return &CachedRealmEnvironmentProvider{envCacheTTL: envCacheTTL}
}

// EnvironmentConfig attempts to construct
func (rp *CachedRealmEnvironmentProvider) RealmEnvironment(ctx context.Context, client *APIClient) (*RealmEnvironment, error) {
	var (
		v   interface{}
		ok  bool
		env *RealmEnvironment
		err error

		cacheKey = buildRealmEnvCacheKey(client.AuthServerURL(), client.RealmName())
	)

	// acquire read lock first
	rp.mu.RLock()

	// fetch or build realm env config
	if v, ok = client.CacheBackend().Load(cacheKey); !ok {
		// if not found in cache, acquire full lock
		rp.mu.RUnlock()
		rp.mu.Lock()
		// queue up unlock
		defer rp.mu.Unlock()
		// test once more, as another process may have already populated cache between full lock acquisition
		if v, ok = client.CacheBackend().Load(cacheKey); !ok {
			if env, err = buildRealmEnvironment(ctx, client); err != nil {
				return nil, err
			}
			// persist new cache entry
			client.CacheBackend().StoreUntil(cacheKey, env, time.Now().Add(rp.envCacheTTL))
		}
	} else {
		// queue up unlock
		defer rp.mu.RUnlock()
	}

	// if env was not initialized above, v will be cast.
	// if this panics, implementation is buggered and must be fixed.
	if env == nil {
		// this will panic if somebody overwrote the cache entry with something else.  scream at them.
		env = v.(*RealmEnvironment)
	}

	return env, nil
}

type RealmEnvironment struct {
	oidc  *OpenIDConfiguration
	uma2c *UMA2Configuration
}

// common configuration entries

func (e *RealmEnvironment) SupportsUMA2() bool {
	return e.uma2c != nil
}

func (e *RealmEnvironment) IssuerAddress() string {
	if e.uma2c != nil {
		return e.uma2c.Issuer
	} else {
		return e.oidc.Issuer
	}
}

func (e *RealmEnvironment) AuthorizationEndpoint() string {
	if e.uma2c != nil {
		return e.uma2c.AuthorizationEndpoint
	} else {
		return e.oidc.AuthorizationEndpoint
	}
}

func (e *RealmEnvironment) TokenEndpoint() string {
	if e.uma2c != nil {
		return e.uma2c.TokenEndpoint
	} else {
		return e.oidc.TokenEndpoint
	}
}

func (e *RealmEnvironment) IntrospectionEndpoint() string {
	if e.uma2c != nil {
		return e.uma2c.IntrospectionEndpoint
	} else {
		return e.oidc.IntrospectionEndpoint
	}
}

func (e *RealmEnvironment) EndSessionEndpoint() string {
	if e.uma2c != nil {
		return e.uma2c.EndSessionEndpoint
	} else {
		return e.oidc.EndSessionEndpoint
	}
}

func (e *RealmEnvironment) JSONWebKeysEndpoint() string {
	if e.uma2c != nil {
		return e.uma2c.JwksURI
	} else {
		return e.oidc.JSONWebKeysEndpoint
	}
}

func (e *RealmEnvironment) RegistrationEndpoint() string {
	if e.uma2c != nil {
		return e.uma2c.RegistrationEndpoint
	} else {
		return e.oidc.RegistrationEndpoint
	}
}

func (e *RealmEnvironment) GrantTypesSupported() []string {
	if e.uma2c != nil {
		return copyStrs(e.uma2c.GrantTypesSupported)
	} else {
		return copyStrs(e.oidc.GrantTypesSupported)
	}
}

func (e *RealmEnvironment) ResponseTypesSupported() []string {
	if e.uma2c != nil {
		return copyStrs(e.uma2c.ResponseTypesSupported)
	} else {
		return copyStrs(e.oidc.ResponseTypesSupported)
	}
}

func (e *RealmEnvironment) ResponseModesSupported() []string {
	if e.uma2c != nil {
		return copyStrs(e.uma2c.ResponseModesSupported)
	} else {
		return copyStrs(e.oidc.ResponseModesSupported)
	}
}

func (e *RealmEnvironment) TokenEndpointAuthMethodsSupported() []string {
	if e.uma2c != nil {
		return copyStrs(e.uma2c.TokenEndpointAuthMethodsSupported)
	} else {
		return copyStrs(e.oidc.TokenEndpointAuthMethodsSupported)
	}
}

func (e *RealmEnvironment) TokenEndpointAuthSigningAlgValuesSupported() []string {
	if e.uma2c != nil {
		return copyStrs(e.uma2c.TokenEndpointAuthSigningAlgValuesSupported)
	} else {
		return copyStrs(e.oidc.TokenEndpointAuthSigningAlgValuesSupported)
	}
}

func (e *RealmEnvironment) ScopesSupported() []string {
	if e.uma2c != nil {
		return copyStrs(e.uma2c.ScopesSupported)
	} else {
		return copyStrs(e.oidc.ScopesSupported)
	}
}

// oidc configuration entries

func (e *RealmEnvironment) UserInfoEndpoint() string {
	return e.oidc.UserInfoEndpoint
}

func (e *RealmEnvironment) CheckSessionIframe() string {
	return e.oidc.CheckSessionIframe
}

func (e *RealmEnvironment) SubjectTypesSupported() []string {
	return copyStrs(e.oidc.SubjectTypesSupported)
}

func (e *RealmEnvironment) IDTokenSigningAlgValuesSupported() []string {
	return copyStrs(e.oidc.IDTokenSigningAlgValuesSupported)
}

func (e *RealmEnvironment) IDTokenEncryptionAlgValuesSupported() []string {
	return copyStrs(e.oidc.IDTokenEncryptionAlgValuesSupported)
}

func (e *RealmEnvironment) IDTokenEncryptionEncValuesSupported() []string {
	return copyStrs(e.oidc.IDTokenEncryptionEncValuesSupported)
}

func (e *RealmEnvironment) UserInfoSigningAlgValuesSupported() []string {
	return copyStrs(e.oidc.UserinfoSigningAlgValuesSupported)
}

func (e *RealmEnvironment) RequestObjectSigningAlgValuesSupported() []string {
	return copyStrs(e.oidc.RequestObjectSigningAlgValuesSupported)
}

func (e *RealmEnvironment) ClaimsSupported() []string {
	return copyStrs(e.oidc.ClaimsSupported)
}

func (e *RealmEnvironment) ClaimTypesSupported() []string {
	return copyStrs(e.oidc.ClaimTypesSupported)
}

func (e *RealmEnvironment) ClaimsParameterSupported() bool {
	return e.oidc.ClaimsParameterSupported
}

func (e *RealmEnvironment) RequestParameterSupported() bool {
	return e.oidc.RequestParameterSupported
}

func (e *RealmEnvironment) RequestURIParameterSupported() bool {
	return e.oidc.RequestURIParameterSupported
}

func (e *RealmEnvironment) CodeChallengeMethodsSupported() []string {
	return copyStrs(e.oidc.CodeChallengeMethodsSupported)
}

func (e *RealmEnvironment) TLSClientCertificateBoundAccessTokens() bool {
	return e.oidc.TLSClientCertificateBoundAccessToken
}

// uma2 configuration entries

func (e *RealmEnvironment) ResourceRegistrationEndpoint() (string, bool) {
	if e.uma2c != nil {
		return e.uma2c.ResourceRegistrationEndpoint, true
	}
	return "", false
}

func (e *RealmEnvironment) PermissionEndpoint() (string, bool) {
	if e.uma2c != nil {
		return e.uma2c.PermissionEndpoint, true
	}
	return "", false
}

func (e *RealmEnvironment) PolicyEndpoint() (string, bool) {
	if e.uma2c != nil {
		return e.uma2c.PermissionEndpoint, true
	}
	return "", false
}
