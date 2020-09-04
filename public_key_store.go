package keycloak

import (
	"time"
)

type PublicKeyStore interface {
	Store(authServerURL, realm, keyID string, publicKey interface{}, deadline time.Time)
	Load(authServerURL, realm, keyID string) (interface{}, bool)
	Delete(authServerURL, realm, keyID string)
	Flush() int
}

type publicKeyStore struct {
	cache CacheBackend
}

func NewPublicKeyStore(be CacheBackend) PublicKeyStore {
	if be == nil {
		be = globalCache
	}
	cs := new(publicKeyStore)
	cs.cache = be
	return cs
}

// Store persists a public key for a realm in the underlying cache for 1/2 the difference between now
// and the provided expiration time.
func (cs *publicKeyStore) Store(authServerURL, realm, keyID string, publicKey interface{}, deadline time.Time) {
	cs.cache.StoreUntil(
		buildPKCacheKey(authServerURL, realm, keyID),
		publicKey,
		deadline.Add(time.Duration(deadline.Sub(time.Now()).Nanoseconds()/2)),
	)
}

// Load will attempt to return a cached public key
func (cs *publicKeyStore) Load(authServerURL, realm, keyID string) (interface{}, bool) {
	return cs.cache.Load(buildPKCacheKey(authServerURL, realm, keyID))
}

// Delete will block until the public key for the provided parameters has been deleted, if it exists in cache
func (cs *publicKeyStore) Delete(authServerURL, realm, keyID string) {
	cs.cache.Delete(buildPKCacheKey(authServerURL, realm, keyID))
}

// Flush will immediately remove all currently stored public keys from the cache
func (cs *publicKeyStore) Flush() int {
	return cs.cache.Flush()
}
