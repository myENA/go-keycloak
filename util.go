package keycloak

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// RequestBearerToken attempts to extract the encoded "Bearer" token from the provided request's "Authorization" header
func RequestBearerToken(request *http.Request) (string, bool) {
	if request == nil {
		return "", false
	}
	for _, v := range request.Header.Values(httpHeaderAuthorization) {
		if strings.HasPrefix(v, httpHeaderAuthorizationBearerPrefix) {
			return strings.TrimPrefix(v, httpHeaderAuthorizationBearerPrefix+" "), true
		}
	}
	return "", false
}

func ParseAddr(addr string, insecure bool) (string, error) {
	var (
		purl *url.URL
		err  error
	)
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", errors.New("addr is empty")
	}
	if !strings.HasPrefix(strings.ToLower(addr), "http") {
		clean := strings.Trim(addr, ":/")
		if insecure {
			addr = fmt.Sprintf("http://%s", clean)
		} else {
			addr = fmt.Sprintf("https://%s", clean)
		}
	}
	if purl, err = url.Parse(addr); err != nil {
		return "", err
	}
	return fmt.Sprintf(addressFormat, purl.Scheme, purl.Host), nil
}

func defaultZerologWriter(w *zerolog.ConsoleWriter) {
	w.NoColor = false
	w.TimeFormat = time.Stamp
	w.Out = os.Stdout
}

// DefaultZerologLogger returns a default logger to be used with this package.  No guarantee is made of consistency
// between releases.
func DefaultZerologLogger() zerolog.Logger {
	return zerolog.New(zerolog.NewConsoleWriter(defaultZerologWriter)).
		With().
		Str("component", "keycloak-client").
		Timestamp().
		Logger()
}

// buildPKCacheKey creates the public key cache entry keys.
func buildPKCacheKey(issuerHost, realm, keyID string) string {
	return fmt.Sprintf(pkKeyFormat, issuerHost, realm, keyID)
}

// parsePKCacheKey splits a cache key into issuer : realm
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

func parseResponseLocations(resp *http.Response) ([]string, error) {
	locations, ok := resp.Header[httpHeaderLocationKey]
	if !ok {
		return nil, errors.New("unable to locate new ID in response")
	}
	if ll := len(locations); ll == 0 {
		return nil, errors.New("unable to locate new ID in response")
	}
	return locations, nil
}

func parseAndReturnLocations(resp *http.Response) ([]string, error) {
	locations, err := parseResponseLocations(resp)
	if err != nil {
		return nil, err
	}
	return locations, nil
}

func compileBaseConfig(provided *APIClientConfig, mutators ...ConfigMutator) *APIClientConfig {
	actual := DefaultAPIClientConfig(nil)

	// ensure we have something to compare with
	if provided == nil {
		provided = DefaultAPIClientConfig(nil)
	}

	// execute mutators
	for _, fn := range mutators {
		fn(provided)
	}

	// to ensure we have something resembling a usable config...

	// issuer stuff
	if provided.IssuerProvider != nil {
		actual.IssuerProvider = provided.IssuerProvider
	}

	// url paths
	if provided.PathPrefix != "" {
		actual.PathPrefix = provided.PathPrefix
	}

	// misc clients
	if provided.HTTPClient != nil {
		actual.HTTPClient = provided.HTTPClient
	}

	// logging
	actual.Logger = provided.Logger

	// debug options
	actual.Debug = provided.Debug

	return actual
}

func verifyAudience(auds []string, cmp string, required bool) bool {
	if len(auds) == 0 {
		return !required
	}
	for _, aud := range auds {
		if aud == "" {
			return !required
		}
		if subtle.ConstantTimeCompare([]byte(aud), []byte(cmp)) != 0 {
			return true
		}
	}
	return false
}

func cleanupHTTPResponseBody(hp *http.Response) {
	if hp == nil {
		return
	}
	_, _ = io.Copy(ioutil.Discard, hp.Body)
	_ = hp.Body.Close()
}

func handleResponse(httpResp *http.Response, successCode int, modelPtr interface{}, sourceErr error) error {
	var finalErr error

	defer cleanupHTTPResponseBody(httpResp)

	if sourceErr != nil {
		return sourceErr
	}

	if httpResp.StatusCode != successCode {
		return newAPIError(httpResp)
	}

	if modelPtr != nil {
		if w, ok := modelPtr.(io.Writer); ok {
			if _, err := io.Copy(w, httpResp.Body); err != nil {
				finalErr = fmt.Errorf("error copying bytes from response to provided writer: %w", err)
			}
		} else if b, ok := modelPtr.(*[]byte); ok {
			if tmp, err := ioutil.ReadAll(httpResp.Body); err != nil && err != io.EOF {
				finalErr = fmt.Errorf("error reading bytes from response: %w", err)
			} else {
				*b = tmp
			}
		} else if err := json.NewDecoder(httpResp.Body).Decode(modelPtr); err != nil && err != io.EOF {
			// ... and this query has a modeled response, attempt to unmarshal into that type
			finalErr = fmt.Errorf("error unmarshalling response body into %T: %w", modelPtr, err)
		}
	}

	return finalErr
}

func copyStrs(src []string) []string {
	var dst []string
	if l := len(src); l > 0 {
		dst = make([]string, l, l)
		copy(dst, src)
	}
	return dst
}

func addMutators(root []RequestMutator, m ...RequestMutator) []RequestMutator {
	if root == nil {
		root = make([]RequestMutator, 0)
	}
	return append(root, m...)
}
