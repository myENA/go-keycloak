package keycloak

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// PublicKeyProvider
//
// This type is used on a per-client basis to return parsed public keys for a specific realm.  It must be able to
type PublicKeyProvider interface {
	// Load must attempt to fetch and parse the public key for the provided realm, returning a descriptive error if it
	// was unable to do so.
	//
	// The context provided to this method will contain at least the following two keys:
	//	- keycloak_realm
	//	- issuer_address
	//
	// The combination of these two values should be used as the identifier for a parsed public key
	Load(ctx context.Context, client *APIClient) (*rsa.PublicKey, error)
}

type debugPublicKeyProvider struct {
	mu sync.Mutex
	ca chan chan *APIClient
}

// NewDebugPublicKeyProvider
//
// This will return a PublicKeyProvider designed to be used when debugging your implementation and should not be used in
// a production environment.  It performs no public key caching of any sort, so each bearer & access token request will
// cause an additional http request and subsequent rsa public key parsing operation to happen.
func NewDebugPublicKeyProvider() PublicKeyProvider {
	pkp := new(debugPublicKeyProvider)
	pkp.ca = make(chan chan *APIClient)
	return pkp
}

func (pkp *debugPublicKeyProvider) Close() {
	pkp.mu.Lock()
	defer pkp.mu.Unlock()
	if pkp.ca == nil {
		return
	}
	close(pkp.ca)
	pkp.ca = nil
}

func (pkp *debugPublicKeyProvider) Load(ctx context.Context, client *APIClient) (*rsa.PublicKey, error) {
	var (
		realm string
		conf  *RealmIssuerConfiguration
		pk    *rsa.PublicKey
		ok    bool
		err   error
	)
	if realm, ok = ContextRealm(ctx); !ok {
		return nil, errors.New("unable to fetch public key as context realm is empty")
	}
	// attempt to load pk
	if conf, err = client.AuthService().RealmIssuerConfiguration(ctx); err != nil {
		return nil, fmt.Errorf("error querying for realm %q issuer configuration: %w", realm, err)
	}
	if pk, err = parsePublicKey(conf.PublicKey); err != nil {
		return nil, fmt.Errorf("error processing public key for realm %q: %w", realm, err)
	}
	return pk, nil
}

// CachingPublicKeyProvider
//
// This is an implementation of a PublicKeyProvider designed to utilize a cache backend
type CachingPublicKeyProvider struct {
	*debugPublicKeyProvider
	pkc PublicKeyCache
	ttl time.Duration
	log zerolog.Logger
}

// NewCachingPublicKeyProvider will return a new PublicKeyProvider using the provided caching backend
func NewCachingPublicKeyProvider(log zerolog.Logger, ttl time.Duration, cache PublicKeyCache) *CachingPublicKeyProvider {
	pkp := new(CachingPublicKeyProvider)
	pkp.debugPublicKeyProvider = NewDebugPublicKeyProvider().(*debugPublicKeyProvider)
	pkp.pkc = cache
	pkp.log = log
	pkp.ttl = ttl
	return pkp
}

// Load is intended to be called by clients
func (pkp *CachingPublicKeyProvider) Load(ctx context.Context, client *APIClient) (*rsa.PublicKey, error) {
	var (
		addr, realm string
		pk          *rsa.PublicKey
		ok          bool
		err         error
	)

	// attempt to locate issuer address
	if addr, ok = ContextIssuerAddress(ctx); !ok {
		return nil, errors.New("unable to fetch public key as issuer address is empty")
	}
	// attempt to locate realm
	if realm, ok = ContextRealm(ctx); !ok {
		return nil, errors.New("unable to fetch public key as context realm is empty")
	}

	// attempt to fetch from cache
	if v, ok := pkp.pkc.Load(addr, realm); ok {
		pkp.log.Printf("Public key for %q realm %q found in cache", addr, realm)
		return v, nil
	}

	// if not found in cache, attempt to fetch then store
	pkp.log.Printf("Public key for %q realm %q not found in cache, fetching...", addr, realm)
	if pk, err = pkp.debugPublicKeyProvider.Load(ctx, client); err != nil {
		return nil, err
	}

	// add parsed pk to cache
	pkp.pkc.Store(addr, realm, pk, pkp.ttl)

	pkp.log.Printf("Public key for %q realm %q persisting for %s", addr, realm, pkp.ttl)

	return pk, nil
}
