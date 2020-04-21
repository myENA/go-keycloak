package keycloak

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// IssuerProvider defines a single-use provider that is used during the APIClient construction process and then discarded.
// It must return a usable HTTP address to execute API calls against or an error describing why it couldn't.
//
// This provider is used once, and no references to it are kept around in the resulting client instance.
type IssuerProvider interface {
	// IssuerAddress must set the key defined by ContextKeyIssuerAddress in the context, returning a descriptive
	// error if it was unable to do so
	IssuerAddress() (string, error)
}

// StaticIssuerProvider
//
// This IssuerProvider implementation always sets the same issuer address in each request, unless the context provided
// to the setter already contains an issuer address key
type StaticIssuerProvider string

// NewStaticIssuerProvider builds an IssuerProvider that will set the issuer address value provided to this constructor,
// unless the context provided to the setter already contains an an issuer address key
func NewStaticIssuerProvider(issuerAddress string) StaticIssuerProvider {
	return StaticIssuerProvider(issuerAddress)
}

// NewStaticIssuerProviderWithURL will construct a new StaticIssuerProvider using the provided *url.URL
func NewStaticIssuerProviderWithURL(purl *url.URL) StaticIssuerProvider {
	if purl == nil {
		panic("why did you pass me a nil *url.URL...")
	}
	return NewStaticIssuerProvider(purl.String())
}

// IssuerAddress will always set the issuer address to the value the StaticIssuerProvider was constructed with,
// unless the provided context already has an address value defined
func (ip StaticIssuerProvider) IssuerAddress() (string, error) {
	var (
		addr string
		err  error
	)
	if addr, err = ParseAddr(string(ip), false); err != nil {
		return "", fmt.Errorf("error parsing %q as url: %w", ip, err)
	}
	return addr, nil
}

type EnvironmentIssuerProvider struct {
	varName  string
	insecure bool
}

// NewEnvironmentIssuerProvider will attempt to read the specified variable from the environment
func NewEnvironmentIssuerProvider(varName string, insecure bool) *EnvironmentIssuerProvider {
	ip := new(EnvironmentIssuerProvider)
	ip.varName = varName
	ip.insecure = insecure
	return ip
}

// IssuerAddress will attempt to locate the environment variable set at construction time.  If found, the value will be
// parsed as a url.  Errors will be returned if the env var is not defined, is empty, or contains a non-url-parseable
// value.
func (ip *EnvironmentIssuerProvider) IssuerAddress() (string, error) {
	var (
		addr string
		err  error
	)
	if addr = strings.TrimSpace(os.Getenv(ip.varName)); addr == "" {
		return "", fmt.Errorf("env var %q not defined or is empty", ip.varName)
	}
	if addr, err = ParseAddr(addr, ip.insecure); err != nil {
		return "", fmt.Errorf("env var %q value %q was unable to be parsed as url: %w", ip.varName, addr, err)
	}
	return addr, nil
}

func defaultIssuerProvider() StaticIssuerProvider {
	return NewStaticIssuerProvider("http://127.0.0.1")
}
