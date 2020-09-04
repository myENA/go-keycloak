package keycloak

import (
	"fmt"
	"strings"
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
