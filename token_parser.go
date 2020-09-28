package keycloak

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go/v4"
)

// TokenParser
type TokenParser interface {
	// Parse must attempt to validate the provided token was signed using the mechanism expected by the realm's issuer
	//
	// The context provided to this method will contain at least the following two keys:
	//	- keycloak_realm
	//	- issuer_address
	Parse(context.Context, *APIClient, *jwt.Token) (pk interface{}, err error)
}

type X509TokenParser struct {
	mu       sync.Mutex
	cacheTTL time.Duration
}

func NewX509TokenParser(cacheTTL time.Duration) *X509TokenParser {
	xtp := new(X509TokenParser)
	if cacheTTL > 0 {
		xtp.cacheTTL = cacheTTL
	} else {
		xtp.cacheTTL = 24 * time.Hour
	}
	return xtp
}

func (xtp *X509TokenParser) Parse(ctx context.Context, client *APIClient, token *jwt.Token) (interface{}, error) {
	xtp.mu.Lock()
	defer xtp.mu.Unlock()

	var (
		issuer string
		realm  string
		pub    interface{}
		rpk    *rsa.PublicKey
		epk    *ecdsa.PublicKey
		ok     bool
		err    error
	)

	// extract expected values from context
	if issuer, ok = ContextIssuerAddress(ctx); !ok {
		return nil, fmt.Errorf("context is missing %q key", ContextKeyIssuerAddress)
	}
	if realm, ok = ContextRealm(ctx); !ok {
		return nil, fmt.Errorf("context is missing %q key", ContextKeyRealm)
	}

	// first attempt to retrieve previously parsed public key for this issuer : realm combination
	if pub, ok = globalPublicKeyCache.Load(issuer, realm); !ok {
		var (
			conf    *RealmIssuerConfiguration
			decoded []byte
		)

		// if not found, attempt to realm's public key from issuer configuration
		if conf, err = client.AuthService().RealmIssuerConfiguration(ctx); err != nil {
			return "", fmt.Errorf("error fetching public configuration: %w", err)
		}

		// attempt to decode
		if decoded, err = base64.StdEncoding.DecodeString(conf.PublicKey); err != nil {
			return nil, fmt.Errorf("error decoding public key: %w", err)
		}

		// attempt to parse x509 public key
		if pub, err = x509.ParsePKIXPublicKey(decoded); err != nil {
			return nil, fmt.Errorf("error parsing public key: %w", err)
		}

		// if successful, add entry to cache
		globalPublicKeyCache.Store(issuer, realm, pub, xtp.cacheTTL)
	}

	// perform some basic type assertions
	if rpk, ok = pub.(*rsa.PublicKey); ok {
		if _, ok = token.Method.(*jwt.SigningMethodRSA); ok {
			return rpk, nil
		} else if _, ok = token.Method.(*jwt.SigningMethodRSAPSS); ok {
			return rpk, nil
		}
	} else if epk, ok = pub.(*ecdsa.PublicKey); ok {
		if _, ok = token.Method.(*jwt.SigningMethodECDSA); ok {
			return epk, nil
		}
	}

	return nil, fmt.Errorf("cannot validate token with alg %q against public key of type %T", token.Method.Alg(), pub)
}
