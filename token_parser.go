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

	"github.com/dgrijalva/jwt-go"
)

// TokenParser
type TokenParser interface {
	// Parse must attempt to validate the provided token was signed using the mechanism expected by the realm's issuer
	//
	// The context provided to this method will contain at least the following two keys:
	//	- keycloak_realm
	//	- issuer_address
	Parse(RealmIssuerConfiguration, *jwt.Token) (pk interface{}, err error)
}

type X509TokenParser struct {
	mu sync.Mutex
}

func NewX509TokenParser() *X509TokenParser {
	xtp := new(X509TokenParser)
	return xtp
}

func (xtp *X509TokenParser) Parse(conf RealmIssuerConfiguration, token *jwt.Token) (interface{}, error) {
	xtp.mu.Lock()
	defer xtp.mu.Unlock()

	var (
		decoded []byte
		pub     interface{}
		rpk     *rsa.PublicKey
		epk     *ecdsa.PublicKey
		ok      bool
		err     error
	)

	// attempt to decode
	if decoded, err = base64.StdEncoding.DecodeString(conf.PublicKey); err != nil {
		return nil, fmt.Errorf("error decoding public key: %w", err)
	}

	// attempt to parse x509 public key
	if pub, err = x509.ParsePKIXPublicKey(decoded); err != nil {
		return nil, fmt.Errorf("error parsing public key: %w", err)
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
