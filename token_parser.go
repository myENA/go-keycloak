package keycloak

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// TokenParser represents any type that can handle parsing and persisting a range of certificate types
type TokenParser interface {
	// Parse must attempt to validate the provided token was signed using the mechanism expected by the realm's issuer
	Parse(context.Context, *APIClient, *jwt.Token) (pk interface{}, err error)
	SupportedAlgorithms() []string
}

type X509TokenParser struct {
	mu   sync.RWMutex
	dttl time.Duration
}

// NewX509TokenParser will return to you a token parser capable of handling most RSA & ECDSA signed tokens and keys
func NewX509TokenParser(cacheTTL time.Duration) *X509TokenParser {
	xtp := new(X509TokenParser)
	xtp.dttl = cacheTTL
	return xtp
}

func (tp *X509TokenParser) Parse(ctx context.Context, client *APIClient, token *jwt.Token) (interface{}, error) {
	var (
		kid      string
		cacheKey string
		pub      interface{}
		rpk      *rsa.PublicKey
		epk      *ecdsa.PublicKey
		expires  *time.Time
		ok       bool
		err      error

		authServerURL = client.AuthServerURL()
		realmName     = client.RealmName()
	)

	if token == nil {
		return nil, errors.New("token is nil")
	}

	if !tp.supports(token.Method.Alg()) {
		return nil, fmt.Errorf("cannot validate token with alg %q against public key of type %T", token.Method.Alg(), pub)
	}

	if v, ok := token.Header["kid"]; !ok {
		return nil, errors.New("unable to locate \"kid\" field in token header")
	} else if kid, ok = v.(string); !ok {
		return nil, fmt.Errorf("token header key \"kid\" has non-string value: %v (%[1]T)", v)
	}

	cacheKey = buildPKCacheKey(authServerURL, realmName, kid)

	tp.mu.RLock()
	if pub, ok = client.CacheBackend().Load(cacheKey); !ok {
		tp.mu.RUnlock()
		tp.mu.Lock()
		defer tp.mu.Unlock()
		if pub, ok = client.CacheBackend().Load(cacheKey); !ok {
			if pub, expires, err = tp.fetchPK(ctx, client, kid); err != nil {
				return nil, fmt.Errorf("error loading public key: %w", err)
			}
			client.CacheBackend().StoreUntil(cacheKey, pub, *expires)
		}
	} else {
		defer tp.mu.RUnlock()
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

	// todo: should not be possible?
	return nil, fmt.Errorf("cannot validate token with alg %q against public key of type %T", token.Method.Alg(), pub)
}

func (*X509TokenParser) SupportedAlgorithms() []string {
	return []string{
		"RS256",
		"RS384",
		"RS512",
		"PS256",
		"PS384",
		"PS512",
		"ES256",
		"ES384",
		"ES512",
	}
}

func (tp *X509TokenParser) supports(alg string) bool {
	for _, a := range tp.SupportedAlgorithms() {
		if a == alg {
			return true
		}
	}
	return false
}

func (tp *X509TokenParser) fetchPKLegacy(ctx context.Context, client *APIClient) (interface{}, *time.Time, error) {
	var (
		conf *RealmIssuerConfiguration
		b    []byte
		pub  interface{}
		err  error
	)
	if conf, err = client.RealmIssuerConfiguration(ctx); err != nil {
		return nil, nil, fmt.Errorf("error attempting to fetch public key from legacy realm info endpoint: %w", err)
	}
	if b, err = base64.StdEncoding.DecodeString(conf.PublicKey); err != nil {
		return nil, nil, fmt.Errorf("error decoding public key from legacy realm info endpoint: %w", err)
	}
	if pub, err = x509.ParsePKIXPublicKey(b); err != nil {
		return nil, nil, fmt.Errorf("error parsing public key from legacy realm info endpoint: %w", err)
	}
	exp := time.Now().Add(tp.dttl)
	return pub, &exp, nil
}

func (tp *X509TokenParser) fetchPKByID(ctx context.Context, client *APIClient, kid string) (interface{}, *time.Time, error) {
	var (
		b    []byte
		jwks *JSONWebKeySet
		jwk  *JSONWebKey
		cert *x509.Certificate
		err  error
	)
	if jwks, err = client.JSONWebKeys(ctx); err != nil {
		return nil, nil, fmt.Errorf("error fetching json web keys: %w", err)
	}
	if jwk = jwks.KeychainByID(kid); jwk == nil {
		return nil, nil, fmt.Errorf("issuer %q realm %q has no key with id %q", client.AuthServerURL(), client.RealmName(), kid)
	}
	// todo: use full chain
	if len(jwk.X509CertificateChain) == 0 {
		return nil, nil, errors.New("no certificates returned from json web keys endpoint")
	}
	if b, err = base64.StdEncoding.DecodeString(jwk.X509CertificateChain[0]); err != nil {
		return nil, nil, fmt.Errorf("error decoding certificate %q: %w", kid, err)
	}
	if cert, err = x509.ParseCertificate(b); err != nil {
		return nil, nil, fmt.Errorf("error parsing certificate %q: %w", kid, err)
	}
	return cert.PublicKey, &cert.NotAfter, nil
}

func (tp *X509TokenParser) fetchPK(ctx context.Context, client *APIClient, keyID string) (interface{}, *time.Time, error) {
	env, err := client.RealmEnvironment(ctx)
	if err != nil {
		return nil, nil, err
	}
	if env.SupportsUMA2() {
		if pk, deadline, err := tp.fetchPKByID(ctx, client, keyID); err == nil {
			return pk, deadline, nil
		}
	}
	return tp.fetchPKLegacy(ctx, client)
}
