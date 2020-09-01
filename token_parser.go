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

	"github.com/dgrijalva/jwt-go"
)

// TokenParser
type TokenParser interface {
	// Parse must attempt to validate the provided token was signed using the mechanism expected by the realm's issuer
	Parse(context.Context, *RealmAPIClient, *jwt.Token) (pk interface{}, err error)
	SupportedAlgorithms() []string
}

var (
	tokenParsers   map[string]TokenParser
	tokenParsersMu sync.RWMutex
)

func init() {
	tokenParsers = make(map[string]TokenParser)
	RegisterTokenParser(NewX509TokenParser(NewPublicKeyCache()))
}

func RegisterTokenParser(tp TokenParser) {
	tokenParsersMu.Lock()
	defer tokenParsersMu.Unlock()
	for _, n := range tp.SupportedAlgorithms() {
		tokenParsers[n] = tp
	}
}

func AlgTokenParser(alg string) (TokenParser, bool) {
	tokenParsersMu.RLock()
	defer tokenParsersMu.RUnlock()
	tp, ok := tokenParsers[alg]
	return tp, ok
}

type X509TokenParser struct {
	pkc PublicKeyCache
}

func NewX509TokenParser(pkc PublicKeyCache) *X509TokenParser {
	if pkc == nil {
		panic(fmt.Sprintf("must provide key cache"))
	}
	xtp := new(X509TokenParser)
	xtp.pkc = pkc
	return xtp
}

func (tp *X509TokenParser) Parse(ctx context.Context, client *RealmAPIClient, token *jwt.Token) (interface{}, error) {
	var (
		kid string
		pub interface{}
		rpk *rsa.PublicKey
		epk *ecdsa.PublicKey
		ok  bool
		err error

		iss = client.Environment().IssuerAddress()
		rn  = client.RealmName()
	)

	if client == nil {
		return nil, errors.New("client is nil")
	}
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

	if pub, ok = tp.pkc.Load(iss, rn, kid); !ok {
		if pub, err = tp.fetchKeyByID(ctx, client, kid); err != nil {
			return nil, err
		}
		tp.pkc.Store(iss, rn, kid, pub)
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

func (tp *X509TokenParser) fetchKeyByID(ctx context.Context, client *RealmAPIClient, kid string) (interface{}, error) {
	var (
		b    []byte
		jwks *JSONWebKeySet
		jwk  *JSONWebKey
		cert *x509.Certificate
		err  error
	)
	if jwks, err = client.JSONWebKeys(ctx); err != nil {
		return nil, fmt.Errorf("error fetching json web keys: %w", err)
	}
	if jwk = jwks.KeychainByID(kid); jwk == nil {
		return nil, fmt.Errorf("issuer %q realm %q has no key with id %q", client.Environment().IssuerAddress(), client.RealmName(), kid)
	}
	// todo: use full chain
	if b, err = base64.StdEncoding.DecodeString(jwk.X509CertificateChain[0]); err != nil {
		return nil, fmt.Errorf("error decoding certificate %q: %w", kid, err)
	}
	if cert, err = x509.ParseCertificate(b); err != nil {
		return nil, fmt.Errorf("error parsing certificate %q: %w", kid, err)
	}
	return cert.PublicKey, nil
}
