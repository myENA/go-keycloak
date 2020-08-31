package keycloak

import (
	"sync"
	"time"

	"github.com/dcarbone/sclg/v3"
	"github.com/rs/zerolog"
)

// RealmConfigCache
//
// This type is used to store and retrieve processed realm configuration on a per-issuer basis, allowing for more
// efficient multi-realm functionality within the client
type RealmConfigCache interface {
	// Load must attempt to retrieve a the processed config for the issuer's realm
	Load(issuerHost, realm string) (RealmIssuerConfiguration, bool)

	// Store must attempt to persist the provided realm config into cache for the specified duration.  Any ttl value of
	// 0 or less must be considered "infinite"
	Store(issuerHost, realm string, realmConfig RealmIssuerConfiguration)

	// Remove must immediately render a cached realm config no longer usable.
	Delete(issuerHost, realm string)

	// List must return a list of all currently cached realm configs in a map with a structure of
	// {"issuer": {"realm1": time.Time(expiry)}}
	// if the returned time.Time instance is zero, then it must be assumed the entry will never expire.
	List() map[string]map[string]time.Time

	// Flush must immediately render all cached realm configs defunct, blocking until cache has been flushed.
	Flush()
}

var (
	globalRealmConfigCacheMu sync.Mutex
	globalRealmConfigCache   *TimedRealmConfigCache
)

// globalRealmConfigCacheInst is responsible for only initializing and returning the global realm config cache if
// the global realm provider is used.  if implementors have their own realm config provider, there is no reason for the
// cache to be running.
func globalRealmConfigCacheInst() RealmConfigCache {
	globalRealmConfigCacheMu.Lock()
	defer globalRealmConfigCacheMu.Unlock()
	if globalRealmConfigCache == nil {
		globalRealmConfigCache = NewTimedRealmConfigCache(
			DefaultZerologLogger().With().Str("component", "keycloak-global-realm-config-cache").Logger(),
			time.Hour,
		)
	}
	return globalRealmConfigCache
}

type debugRealmConfigCache struct {
	configs *sync.Map
}

// NewDebugRealmConfigCache will return an implementation that ignores all TTL values, storing items indefinitely in an
// internal map.  Recommended only for use during debugging.
func NewDebugRealmConfigCache() RealmConfigCache {
	dbg := new(debugRealmConfigCache)
	dbg.configs = new(sync.Map)
	dbg.Flush()
	return dbg
}

// Load will attempt to return an existing parsed key entry for the provided issuer and realm
func (rcc *debugRealmConfigCache) Load(issuerHost, realm string) (RealmIssuerConfiguration, bool) {
	if v, ok := rcc.configs.Load(buildRCCacheKey(issuerHost, realm)); ok {
		return v.(RealmIssuerConfiguration), true
	}
	return RealmIssuerConfiguration{}, false
}

// Store will persist the provided parsed public key for the issuer and realm
func (rcc *debugRealmConfigCache) Store(issuerHost, realm string, realmConfig RealmIssuerConfiguration) {
	rcc.configs.Store(buildRCCacheKey(issuerHost, realm), realmConfig)
}

// Remove will attempt to remove a stored parsed public key for the provided issuer and realm, returning true if an item
// was indeed removed
func (rcc *debugRealmConfigCache) Delete(issuerHost, realm string) {
	rcc.configs.Delete(buildRCCacheKey(issuerHost, realm))
}

// List returns a map of all currently stored issuer realm public keys, and their expiration time
func (rcc *debugRealmConfigCache) List() map[string]map[string]time.Time {
	var (
		issuerHost, realm string
		ok                bool

		m = make(map[string]map[string]time.Time)
	)

	rcc.configs.Range(func(key, value interface{}) bool {
		issuerHost, realm = parseRCCacheKey(key.(string))
		if _, ok = m[issuerHost]; !ok {
			m[issuerHost] = make(map[string]time.Time)
		}
		m[issuerHost][realm] = time.Time{}
		return true
	})

	return m
}

// Flush will immediately remove all stored parsed public keys from this cache
func (rcc *debugRealmConfigCache) Flush() {
	rcc.configs.Range(func(key, _ interface{}) bool {
		rcc.configs.Delete(key)
		return true
	})
}

// TimedRealmConfigCache is an implementation of a RealmConfigCache that utilizes a timed cached backend
type TimedRealmConfigCache struct {
	log   zerolog.Logger
	ttl   time.Duration
	cache *sclg.TimedCache
}

func defaultTimedCacheConfigMutator(rcc *TimedRealmConfigCache) sclg.TimedCacheConfigMutator {
	return func(c *sclg.TimedCacheConfig) {
		c.Comparator = rcCacheEquivalencyTest
		c.StoredEventCallback = rcCacheEventCallback(rcc)
		c.RemovedEventCallback = rcCacheEventCallback(rcc)
	}
}

// NewTimedRealmConfigCache will return a new RealmConfigCache using sclg.TimedCache as its backend
func NewTimedRealmConfigCache(log zerolog.Logger, ttl time.Duration, timedCacheMutators ...sclg.TimedCacheConfigMutator) *TimedRealmConfigCache {
	rcc := new(TimedRealmConfigCache)
	rcc.log = log
	rcc.ttl = ttl
	if timedCacheMutators == nil {
		timedCacheMutators = make([]sclg.TimedCacheConfigMutator, 0)
	}
	timedCacheMutators = append([]sclg.TimedCacheConfigMutator{defaultTimedCacheConfigMutator(rcc)}, timedCacheMutators...)
	rcc.cache = sclg.NewTimedCache(nil, timedCacheMutators...)
	return rcc
}

// Load will attempt to pull the specified cache item from the underlying TimedCache instance
func (rcc *TimedRealmConfigCache) Load(issuerHost, realm string) (RealmIssuerConfiguration, bool) {
	if v, ok := rcc.cache.Load(buildRCCacheKey(issuerHost, realm)); ok {
		return v.(RealmIssuerConfiguration), true
	}
	return RealmIssuerConfiguration{}, false
}

// Store will permanently persist the provided public key into the underlying TimedCache instance, overwriting any
// existing entry
func (rcc *TimedRealmConfigCache) Store(issuerHost, realm string, realmConfig RealmIssuerConfiguration) {
	rcc.cache.StoreFor(buildRCCacheKey(issuerHost, realm), realmConfig, rcc.ttl)
}

// Remove will delete a cached parsed public key from the underlying TimedCache instance, returning true if an item was
// actually deleted
func (rcc *TimedRealmConfigCache) Delete(issuerHost, realm string) {
	rcc.cache.Delete(buildRCCacheKey(issuerHost, realm))
}

// List will return a map of all issuer hostnames with their associated realm's that have a public key cached.  The
// time value is the deadline after which the key will be removed from the cache.  A zero-val time.Time instance must be
// interpreted as never-expiring entry.
func (rcc *TimedRealmConfigCache) List() map[string]map[string]time.Time {
	var (
		issuer, realm string
		ok            bool

		m = make(map[string]map[string]time.Time)
	)
	for k, v := range rcc.cache.List() {
		issuer, realm = parseRCCacheKey(k)
		if _, ok = m[issuer]; !ok {
			m[issuer] = make(map[string]time.Time)
		}
		m[issuer][realm] = v
	}
	return m
}
func (rcc *TimedRealmConfigCache) Flush() {
	rcc.cache.Flush()
}

// GlobalPublicKeyCache returns the instance of the global public key cache used by the default realm config provider
func GlobalPublicKeyCache() RealmConfigCache {
	return globalRealmConfigCacheInst()
}

// SetGlobalPublicKeyCacheLogger allows you to specify a different logger for the global public key cache instance.
func SetGlobalPublicKeyCacheLogger(log zerolog.Logger) {
	globalRealmConfigCacheInst()
	globalRealmConfigCache.log = log
}

// FlushGlobalPublicKeyCache will immediately flush all entries in the global public key cache, blocking until they have
// been successfully flushed.  If the global realm config cache has not been instantiated, this method does nothing.
func FlushGlobalPublicKeyCache() {
	globalRealmConfigCacheMu.Lock()
	defer globalRealmConfigCacheMu.Unlock()
	if globalRealmConfigCache != nil {
		globalRealmConfigCache.Flush()
	}
}
