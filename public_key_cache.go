package keycloak

import (
	"sync"
	"time"

	"github.com/dcarbone/sclg/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/rs/zerolog"
)

// PublicKeyCache
//
// This type is used to store and retrieve processed public keys on a per-realm per-issuer basis, allowing for more
// efficient multi-realm functionality within the client
type PublicKeyCache interface {
	// Load must attempt to retrieve a the processed public key for the issuer's realm
	Load(issuer, realm, keyID string) (interface{}, bool)

	// Store must attempt to persist the provided pk into cache for the specified duration.  Any ttl value of 0 or less
	// must be considered "infinite"
	Store(issuer, realm, keyID string, pk interface{})

	// Remove must immediately render a cached public key no longer usable. It must block until removal has been
	// completed.
	Delete(issuer, realm, keyID string)

	// Flush must immediately render all cached public keys defunct, blocking until cache has been flushed.
	Flush()
}

func pkCacheEquivalencyTest(_, current, new interface{}) bool {
	return cmp.Equal(current, new)
}

func pkCacheEventCallback(pk *limitedPublicKeyCache) sclg.TimedCacheEventCallback {
	return func(ev sclg.TimedCacheEvent, _ interface{}, message string) {
		pk.log.Debug().Str("event", ev.String()).Str("event-message", message).Msg("Event seen")
	}
}

// simplePublicKeyCache stores keys indefinitely
type simplePublicKeyCache struct {
	pks *sync.Map
}

// NewPublicKeyCache returns a cache implementation that stores keys permanently
func NewPublicKeyCache() PublicKeyCache {
	dbg := new(simplePublicKeyCache)
	dbg.pks = new(sync.Map)
	return dbg
}

// Load will attempt to return an existing parsed key entry for the provided issuer and realm
func (pkc *simplePublicKeyCache) Load(issuer, realm, keyID string) (interface{}, bool) {
	if v, ok := pkc.pks.Load(buildPKCacheKey(issuer, realm, keyID)); ok {
		return v.(RealmIssuerConfiguration), true
	}
	return RealmIssuerConfiguration{}, false
}

// Store will persist the provided parsed public key for the issuer and realm
func (pkc *simplePublicKeyCache) Store(issuer, realm, keyID string, pk interface{}) {
	pkc.pks.Store(buildPKCacheKey(issuer, realm, keyID), pk)

}

// Remove will attempt to remove a stored parsed public key for the provided issuer and realm, returning true if an item
// was indeed removed
func (pkc *simplePublicKeyCache) Delete(issuer, realm, keyID string) {
	pkc.pks.Delete(buildPKCacheKey(issuer, realm, keyID))
}

// Flush will immediately remove all stored parsed public keys from this cache
func (pkc *simplePublicKeyCache) Flush() {
	pkc.pks.Range(func(key, _ interface{}) bool {
		pkc.pks.Delete(key)
		return true
	})
}

type limitedPublicKeyCache struct {
	log   zerolog.Logger
	ttl   time.Duration
	cache *sclg.TimedCache
}

// DefaultTimedConfigMutator is always passed to the underlying sclg.TimedCache constructor as the first mutator.  If
// you wish to further modify the config, pass your own sclg.TimedCacheConfigMutator funcs to the
// NewLimitedPublicKeyCache constructor
func defaultTimedCacheConfigMutator(pkc *limitedPublicKeyCache) sclg.TimedCacheConfigMutator {
	return func(c *sclg.TimedCacheConfig) {
		c.Comparator = pkCacheEquivalencyTest
		c.StoredEventCallback = pkCacheEventCallback(pkc)
		c.RemovedEventCallback = pkCacheEventCallback(pkc)
	}
}

// NewLimitedPublicKeyCache will return a new PublicKeyCache using sclg.TimedCache as its backend
func NewLimitedPublicKeyCache(log zerolog.Logger, ttl time.Duration, timedCacheMutators ...sclg.TimedCacheConfigMutator) PublicKeyCache {
	pkc := new(limitedPublicKeyCache)
	pkc.log = log
	pkc.ttl = ttl
	if timedCacheMutators == nil {
		timedCacheMutators = make([]sclg.TimedCacheConfigMutator, 0)
	}
	timedCacheMutators = append([]sclg.TimedCacheConfigMutator{defaultTimedCacheConfigMutator(pkc)}, timedCacheMutators...)
	pkc.cache = sclg.NewTimedCache(nil, timedCacheMutators...)
	return pkc
}

// Load will attempt to pull the specified cache item from the underlying TimedCache instance
func (pkc *limitedPublicKeyCache) Load(issuer, realm, keyID string) (interface{}, bool) {
	if v, ok := pkc.cache.Load(buildPKCacheKey(issuer, realm, keyID)); ok {
		return v.(interface{}), true
	}
	return nil, false
}

// Store will permanently persist the provided public key into the underlying TimedCache instance, overwriting any
// existing entry
func (pkc *limitedPublicKeyCache) Store(issuer, realm, keyID string, pk interface{}) {
	pkc.cache.StoreFor(buildPKCacheKey(issuer, realm, keyID), pk, pkc.ttl)
}

// Remove will delete a cached parsed public key from the underlying TimedCache instance, returning true if an item was
// actually deleted
func (pkc *limitedPublicKeyCache) Delete(issuer, realm, keyID string) {
	return
}

func (pkc *limitedPublicKeyCache) Flush() {
	pkc.cache.Flush()
}
