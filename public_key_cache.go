package keycloak

import (
	"sync"
	"time"

	"github.com/dcarbone/sclg/v3"
	"github.com/rs/zerolog"
)

// PublicKeyCache
//
// This type is used to store and retrieve processed public keys on a per-realm per-issuer basis, allowing for more
// efficient multi-realm functionality within the client
type PublicKeyCache interface {
	// Load must attempt to retrieve a the processed public key for the issuer's realm
	Load(issuerHost, realm string) (interface{}, bool)

	// Store must attempt to persist the provided pk into cache for the specified duration.  Any ttl value of 0 or less
	// must be considered "infinite"
	Store(issueHost, realm string, pk interface{}, ttl time.Duration)

	// Remove must immediately render a cached public key no longer usable. It must block until removal has been
	// completed.
	Remove(issuerHost, realm string) bool

	// List must return a list of all currently cached public key keys in a map with a structure of
	// {"issuer": {"realm1": time.Time(expiry)}}
	// if the returned time.Time instance is zero, then it must be assumed the entry will never expire.
	List() map[string]map[string]time.Time

	// Flush must immediately render all cached public keys defunct, blocking until cache has been flushed.
	Flush()
}

var (
	globalPublicKeyCache *TimedPublicKeyCache
)

func init() {
	globalPublicKeyCache = NewTimedPublicKeyCache(
		DefaultZerologLogger().With().Str("component", "aaa-global-pk-cache").Logger(),
	)
}

type debugPublicKeyCache struct {
	mu sync.RWMutex
	m  map[string]interface{}
}

// NewDebugPublicKeyCache will return an implementation that ignores all TTL values, storing items indefinitely in an
// internal map.  Recommended only for use during debugging.
func NewDebugPublicKeyCache() PublicKeyCache {
	dbg := new(debugPublicKeyCache)
	dbg.Flush()
	return dbg
}

// Load will attempt to return an existing parsed key entry for the provided issuer and realm
func (pkc *debugPublicKeyCache) Load(issuerHost, realm string) (interface{}, bool) {
	pkc.mu.RLock()
	pk, ok := pkc.m[buildPKCacheKey(issuerHost, realm)]
	pkc.mu.RUnlock()
	return pk, ok
}

// Store will persist the provided parsed public key for the issuer and realm
func (pkc *debugPublicKeyCache) Store(issuerHost, realm string, pk interface{}, _ time.Duration) {
	pkc.mu.Lock()
	pkc.m[buildPKCacheKey(issuerHost, realm)] = pk
	pkc.mu.Unlock()
}

// Remove will attempt to remove a stored parsed public key for the provided issuer and realm, returning true if an item
// was indeed removed
func (pkc *debugPublicKeyCache) Remove(issuerHost, realm string) bool {
	pkc.mu.Lock()
	defer pkc.mu.Unlock()

	var (
		ok bool

		n      = make(map[string]interface{})
		target = buildPKCacheKey(issuerHost, realm)
	)

	// rebuilding map prevents memory leak described https://github.com/golang/go/issues/20135

	for k, v := range pkc.m {
		if k == target {
			ok = true
			continue
		}
		n[k] = v
	}

	pkc.m = n

	return ok
}

// List returns a map of all currently stored issuer realm public keys, and their expiration time
func (pkc *debugPublicKeyCache) List() map[string]map[string]time.Time {
	pkc.mu.RLock()
	defer pkc.mu.RUnlock()

	var (
		issuerHost, realm string
		ok                bool

		m = make(map[string]map[string]time.Time)
	)

	for k := range pkc.m {
		issuerHost, realm = parsePKCacheKey(k)
		if _, ok = m[issuerHost]; !ok {
			m[issuerHost] = make(map[string]time.Time)
		}
		m[issuerHost][realm] = time.Time{}
	}

	return m
}

// Flush will immediately remove all stored parsed public keys from this cache
func (pkc *debugPublicKeyCache) Flush() {
	pkc.mu.Lock()
	defer pkc.mu.Unlock()

	pkc.m = make(map[string]interface{})
}

// TimedPublicKeyCache
//
// This is an implementation of a PublicKeyCache that utilizes a timed cached backend
type TimedPublicKeyCache struct {
	cache *sclg.TimedCache
	log   zerolog.Logger
}

// DefaultTimedConfigMutator is always passed to the underlying sclg.TimedCache constructor as the first mutator.  If
// you wish to further modify the config, pass your own sclg.TimedCacheConfigMutator funcs to the
// NewTimedPublicKeyCache constructor
func defaultTimedCacheConfigMutator(pkc *TimedPublicKeyCache) sclg.TimedCacheConfigMutator {
	return func(c *sclg.TimedCacheConfig) {
		c.Comparator = pkCacheEquivalencyTest
		c.StoredEventCallback = pkCacheEventCallback(pkc)
		c.RemovedEventCallback = pkCacheEventCallback(pkc)
	}
}

// NewTimedPublicKeyCache will return a new PublicKeyCache using sclg.TimedCache as its backend
func NewTimedPublicKeyCache(log zerolog.Logger, timedCacheMutators ...sclg.TimedCacheConfigMutator) *TimedPublicKeyCache {
	pkc := new(TimedPublicKeyCache)
	pkc.log = log
	if timedCacheMutators == nil {
		timedCacheMutators = make([]sclg.TimedCacheConfigMutator, 0)
	}
	timedCacheMutators = append([]sclg.TimedCacheConfigMutator{defaultTimedCacheConfigMutator(pkc)}, timedCacheMutators...)
	pkc.cache = sclg.NewTimedCache(nil, timedCacheMutators...)
	return pkc
}

// Load will attempt to pull the specified cache item from the underlying TimedCache instance
func (pkc *TimedPublicKeyCache) Load(issuerHost, realm string) (interface{}, bool) {
	if v, ok := pkc.cache.Load(buildPKCacheKey(issuerHost, realm)); ok {
		return v.(interface{}), true
	}
	return nil, false
}

// Store will permanently persist the provided public key into the underlying TimedCache instance, overwriting any
// existing entry
func (pkc *TimedPublicKeyCache) Store(issuerHost, realm string, pk interface{}, ttl time.Duration) {
	pkc.cache.StoreFor(buildPKCacheKey(issuerHost, realm), pk, ttl)
}

// Remove will delete a cached parsed public key from the underlying TimedCache instance, returning true if an item was
// actually deleted
func (pkc *TimedPublicKeyCache) Remove(issuerHost, realm string) bool {
	return pkc.cache.Remove(buildPKCacheKey(issuerHost, realm))
}

// List will return a map of all issuer hostnames with their associated realm's that have a public key cached.  The
// time value is the deadline after which the key will be removed from the cache.  A zero-val time.Time instance must be
// interpreted as never-expiring entry.
func (pkc *TimedPublicKeyCache) List() map[string]map[string]time.Time {
	var (
		issuer, realm string
		ok            bool

		m = make(map[string]map[string]time.Time)
	)
	for k, v := range pkc.cache.List() {
		issuer, realm = parsePKCacheKey(k)
		if _, ok = m[issuer]; !ok {
			m[issuer] = make(map[string]time.Time)
		}
		m[issuer][realm] = v
	}
	return m
}
func (pkc *TimedPublicKeyCache) Flush() {
	pkc.cache.Flush()
}

// GlobalPublicKeyCache returns the instance of the global public key cache used by default when creating clients
func GlobalPublicKeyCache() PublicKeyCache {
	return globalPublicKeyCache
}

// SetGlobalPublicKeyCacheLogger allows you to specify a different logger for the global public key cache instance
func SetGlobalPublicKeyCacheLogger(log zerolog.Logger) {
	globalPublicKeyCache.log = log
}

// FlushGlobalPublicKeyCache will immediately flush all entries in the global public key cache, blocking until they have
// been successfully flushed.
func FlushGlobalPublicKeyCache() {
	globalPublicKeyCache.Flush()
}
