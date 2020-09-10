package keycloak

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dcarbone/sclg/v3"
	"github.com/google/go-cmp/cmp"
)

type CacheBackend interface {
	Load(key interface{}) (value interface{}, ok bool)
	StoreUntil(key, value interface{}, deadline time.Time)
	Delete(key interface{})
	Flush() int
}

var (
	globalCache *sclg.TimedCache
)

func init() {
	conf := new(sclg.TimedCacheConfig)
	conf.Comparator = globalCacheEquivalencyTest
	globalCache = sclg.NewTimedCache(conf)
}

type noopCacheImpl struct{}

var noopCacheInst = noopCacheImpl{}

// NewNoopCache will return to you a cache instance that will entirely disable all caching within the client. Not
// recommended for production use
func NewNoopCache() CacheBackend {
	return noopCacheInst
}

func (noopCacheImpl) Load(_ interface{}) (interface{}, bool)   { return nil, false }
func (noopCacheImpl) StoreUntil(_, _ interface{}, _ time.Time) {}
func (noopCacheImpl) Delete(_ interface{})                     {}
func (noopCacheImpl) Flush() int                               { return 0 }

type persistentCacheImpl struct {
	*sync.Map
}

// NewPersistentCache returns a CacheBackend implementation that stores items indefinitely until explicitly deleted. Not
// recommended for production use.
func NewPersistentCache() CacheBackend {
	cb := new(persistentCacheImpl)
	cb.Map = new(sync.Map)
	return cb
}

func (p *persistentCacheImpl) StoreUntil(key, value interface{}, _ time.Time) {
	p.Store(key, value)
}

func (p *persistentCacheImpl) Flush() int {
	cnt := 0
	p.Range(func(key, _ interface{}) bool {
		p.Delete(key)
		cnt++
		return true
	})
	return cnt
}

func globalCacheEquivalencyTest(_, current, new interface{}) bool {
	return cmp.Equal(current, new)
}

// buildPKCacheKey creates the public key cache entry keys.
func buildPKCacheKey(authServerURL, realm, keyID string) string {
	return fmt.Sprintf(pkKeyFormat, authServerURL, realm, keyID)
}

// parsePKCacheKey splits a cache key into authServerURL : realm : keyID
func parsePKCacheKey(key interface{}) (string, string, string) {
	str, ok := key.(string)
	if !ok {
		return "", "", ""
	}
	s := strings.SplitN("\n", str, 4)
	if len(s) != 4 || s[0] != pkKeyPrefix {
		return "", "", ""
	}
	return s[1], s[2], s[3]
}

func buildRealmEnvCacheKey(authServerURL, realm string) string {
	return fmt.Sprintf(reKeyFormat, authServerURL, realm)
}

func parseRealmEnvCacheKey(key interface{}) (string, string) {
	str, ok := key.(string)
	if !ok {
		return "", ""
	}
	s := strings.SplitN(str, "\n", 3)
	if len(s) != 3 || s[0] != reKeyPrefix {
		return "", ""
	}
	return s[1], s[2]
}
