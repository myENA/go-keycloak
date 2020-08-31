package keycloak

import (
	"context"
	"fmt"
	"os"
	"sync"
)

// RealmConfigurationProvider
//
// This interface describes any implementation that can provide a realm name to the given context
type RealmConfigurationProvider interface {
	// RealmConfiguration MUST either return a context with the realm key defined, or the original context with an error
	// describing why it was unable to do so.  It must also defer to any pre-defined key value already present in the
	// context.
	RealmConfiguration(context.Context, *APIClient) (RealmIssuerConfiguration, error)
}

// GlobalRealmConfigurationProvider will utilize the global config cache to handle realm configuration re-use.
type GlobalRealmConfigurationProvider struct {
	mu        sync.Mutex
	realmName string
	cache     RealmConfigCache
	mutators  []RequestMutator
}

func NewGlobalRealmConfigProvider(realmName string, mutators ...RequestMutator) *GlobalRealmConfigurationProvider {
	rp := new(GlobalRealmConfigurationProvider)
	rp.realmName = realmName
	rp.cache = globalRealmConfigCache
	if mutators == nil {
		mutators = make([]RequestMutator, 0, 0)
	}
	rp.mutators = mutators
	return rp
}

// NewGlobalRealmConfigurationProviderWith will attempt to fetch the provided env key using os.GetEnv, creating a new
// GlobalRealmConfigurationProvider with that as the value.
func NewGlobalRealmConfigurationProviderWith(envKey string, mutators ...RequestMutator) *GlobalRealmConfigurationProvider {
	realm := os.Getenv(envKey)
	if envKey == "" {
		panic(fmt.Sprintf("provided \"envKey\" value %q yielded empty string", envKey))
	}
	return NewGlobalRealmConfigProvider(realm, mutators...)
}

// SetRealmValue will attempt to locate a pre-existing realm key on the provided context, returning the original
// context if one is found.  If not, it will return a new context with its own realm value defined.
func (rp *GlobalRealmConfigurationProvider) RealmConfiguration(ctx context.Context, client *APIClient) (RealmIssuerConfiguration, error) {
	var (
		realmConfig RealmIssuerConfiguration
		ok          bool
		err         error
	)

	// todo: this is to prevent possibly tons of hits from all attempting to refresh the cache at once, but may not
	// be necessary...
	rp.mu.Lock()
	defer rp.mu.Unlock()

	// first, check if we have cached version of realm config
	if realmConfig, ok = rp.cache.Load(client.IssuerAddress(), rp.realmName); !ok {
		// failing that, try to fetch and update cache
		if realmConfig, err = client.RealmIssuerConfiguration(ctx, rp.realmName, rp.mutators...); err != nil {
			return realmConfig, fmt.Errorf("error fetching realm issuer configuration: %w", err)
		}
		rp.cache.Store(client.IssuerAddress(), rp.realmName, realmConfig)
	}

	return realmConfig, nil
}
