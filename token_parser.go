package keycloak

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

// TokenParser
type TokenParser interface {
	// Parse must return an error if the provided token does not match the expected signature type for the
	// provided context
	Parse(context.Context, *APIClient, *jwt.Token) (pk interface{}, err error)
}

type baseTokenParser struct{}

func (baseTokenParser) fetchPK(ctx context.Context, client *APIClient) (interface{}, error) {
	var (
		conf    *RealmIssuerConfiguration
		decoded []byte
		pub     interface{}
		err     error
	)

	// attempt to load pk
	if conf, err = client.AuthService().RealmIssuerConfiguration(ctx); err != nil {
		return "", fmt.Errorf("error fetching public configuration: %w", err)
	}

	if decoded, err = base64.StdEncoding.DecodeString(conf.PublicKey); err != nil {
		return nil, fmt.Errorf("error decoding public key: %w", err)
	}

	if pub, err = x509.ParsePKIXPublicKey(decoded); err != nil {
		return nil, fmt.Errorf("error parsing public key: %w", err)
	}

	return pub, nil
}

type RSATokenParser struct {
	bkp baseTokenParser
}

func (rpk *RSATokenParser) Parse(ctx context.Context, client *APIClient, token *jwt.Token) (interface{}, error) {
	var (
		pub interface{}
		pk  *rsa.PublicKey
		ok  bool
		err error
	)

	if pub, err = rpk.bkp.fetchPK(ctx, client); err != nil {
		return nil, err
	}

	if pk, ok = pub.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("expected parsed public key to be %T, saw %T", pk, pub)
	}

	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}

	return pk, nil
}

type ECDSATokenParser struct {
	bkp baseTokenParser
}

func (epk *ECDSATokenParser) Parse(ctx context.Context, client *APIClient, token *jwt.Token) (interface{}, error) {
	var (
		pub interface{}
		pk  *ecdsa.PublicKey
		ok  bool
		err error
	)

	if pub, err = epk.bkp.fetchPK(ctx, client); err != nil {
		return nil, err
	}

	if pk, ok = pub.(*ecdsa.PublicKey); !ok {
		return nil, fmt.Errorf("expected parsed public key to be %T, saw %T", pk, pub)
	}

	if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}

	return pk, nil
}
