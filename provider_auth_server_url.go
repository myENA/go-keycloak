package keycloak

import (
	"net/url"
	"os"
)

// AuthServerURLProvider defines a single-user provider that is called once during client initialization, and is
// expected to return the full address and any path prefix for the target keycloak server.
//
// For example, if your hostname is example.com and you have keycloak behind a proxy that looks for the "/auth" path,
// the value returned from this must be "https://example.com/auth", or an error.
type AuthServerURLProvider interface {
	// IssuerAddress must set the key defined by ContextKeyIssuerAddress in the context, returning a descriptive
	// error if it was unable to do so
	AuthServerURL() (string, error)
}

type authServerURLProvider string

func (ip authServerURLProvider) AuthServerURL() (string, error) {
	return string(ip), nil
}

// NewAuthServerURLProvider builds an AuthServerURLProvider that will set the issuer address value provided to this constructor,
// unless the context provided to the setter already contains an an issuer address key
func NewAuthServerURLProvider(authServerURL string) AuthServerURLProvider {
	return authServerURLProvider(authServerURL)
}

// NewAuthServerURLProviderWithURL will construct a new authServerURLProvider using the provided *url.URL
func NewAuthServerURLProviderWithURL(purl *url.URL) AuthServerURLProvider {
	if purl == nil {
		panic("why did you pass me a nil *url.URL...")
	}
	return NewAuthServerURLProvider(purl.String())
}

// NewEnvironmentIssuerProvider will attempt to read the specified variable from the environment
func NewEnvironmentIssuerProvider(varName string) AuthServerURLProvider {
	return NewAuthServerURLProvider(os.Getenv(varName))
}

func defaultIssuerProvider() AuthServerURLProvider {
	return NewAuthServerURLProvider("http://127.0.0.1/auth")
}
