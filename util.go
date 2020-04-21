package keycloak

import (
	"bytes"
	"context"
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

	"github.com/dcarbone/sclg/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/rs/zerolog"
)

type ctxProvider int

var contextProvider = new(ctxProvider)

// SetRealmValue will attempt to verify that the correct realm key is set in the provided context, returning an error if
// not found
func (*ctxProvider) SetRealmValue(ctx context.Context) (context.Context, error) {
	if _, ok := contextStringValue(ctx, ContextKeyRealm); ok {
		return ctx, nil
	}
	return ctx, fmt.Errorf("context did not have %q key present", ContextKeyRealm)
}

// SetTokenValue will attempt to verify that the correct token key is set on the provided context, returning an error if
// not found
func (ctxProvider) SetTokenValue(ctx context.Context, _ *APIClient) (context.Context, error) {
	if _, ok := ContextToken(ctx); ok {
		return ctx, nil
	}
	return ctx, fmt.Errorf("context did not have key %q populated", ContextKeyToken)
}

// ContextRealmProvider
//
// This is the simplest and default RealmProvider.  It simply checks for the existence of the realm key on the given
// context, returning an error if it does not exist.  This requires that you define the realm in the context yourself.
func ContextRealmProvider() RealmProvider { return contextProvider }

// ContextTokenProvider
//
// This is the simplest and default TokenProvider.  It simply checks for the existence of the token key on the given
// context, returning an error if it does not exist.  This requires that you define the token in the context yourself.
func ContextTokenProvider() TokenProvider { return contextProvider }

// RealmContext will create a new context chained from the provided parent with the appropriate realm key set
func RealmContext(parent context.Context, realm string) context.Context {
	return context.WithValue(parent, ContextKeyRealm, realm)
}

// BackgroundRealmContext will return a context with a background parent, adding the appropriate realm key
func BackgroundRealmContext(realm string) context.Context {
	return RealmContext(context.Background(), realm)
}

// RealmContextWithTimeout will return a new context and cancel func with the realm value key defined and the provided
// ttl set as the timeout
func RealmContextWithTimeout(parent context.Context, realm string, ttl time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(RealmContext(parent, realm), ttl)
}

// TokenContext will create a new context chained from the provided parent with the appropriate token key set
func TokenContext(parent context.Context, token string) context.Context {
	return context.WithValue(parent, ContextKeyToken, token)
}

// BackgroundTokenContext will return a context with a background parent, adding the appropriate token key
func BackgroundTokenContext(token string) context.Context {
	return TokenContext(context.Background(), token)
}

// TokenContextWithTimeout will return a new context and cancel func with the token value key defined and the provided
// ttl set as the timeout
func TokenContextWithTimeout(parent context.Context, token string, ttl time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(TokenContext(parent, token), ttl)
}

// RealmTokenContext will return a new context chained from the provided parent with both realm and token keys set
func RealmTokenContext(parent context.Context, realm, token string) context.Context {
	return TokenContext(RealmContext(parent, realm), token)
}

// BackgroundRealmTokenContext will return a context with a background parent, adding the appropriate realm and token
// keys
func BackgroundRealmTokenContext(realm, token string) context.Context {
	return TokenContext(BackgroundRealmContext(realm), token)
}

// RealmTokenContextWithTimeout will return a new context and cancel func with the realm and token value keys defined,
// and the provided ttl set as the timeout
func RealmTokenContextWithTimeout(parent context.Context, realm, token string, ttl time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(TokenContext(RealmContext(parent, realm), token), ttl)
}

// IssuerAddressContext will return a new context chained from the provided parent with the appropriate issuer address
// key set
func IssuerAddressContext(parent context.Context, issuerAddress string) context.Context {
	return context.WithValue(parent, ContextKeyIssuerAddress, issuerAddress)
}

// ContextRealm attempts to extract and return the provided context's realm key value
func ContextRealm(ctx context.Context) (string, bool) {
	return contextStringValue(ctx, ContextKeyRealm)
}

// ContextToken attempts to extract and return the provided context's token key value
func ContextToken(ctx context.Context) (string, bool) {
	return contextStringValue(ctx, ContextKeyToken)
}

// ContextIssuerAddress attempts to extract and return the provided context's issuer address.  This is rarely used.
func ContextIssuerAddress(ctx context.Context) (string, bool) {
	return contextStringValue(ctx, ContextKeyIssuerAddress)
}

// RequestBearerToken attempts to extract the encoded "Bearer" token from the provided requests "Authorization" header
func RequestBearerToken(request *http.Request) (string, bool) {
	if v := request.Header[httpHeaderAuthorization]; len(v) == 1 && strings.HasPrefix(v[0], httpHeaderAuthorizationBearerPrefix) {
		return strings.TrimPrefix(v[0], httpHeaderAuthorizationBearerPrefix), true
	}
	return "", false
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
func buildPKCacheKey(issuerHost, realm string) string {
	return fmt.Sprintf(pkKeyFormat, issuerHost, realm)
}

// parsePKCacheKey splits a cache key into issuer : realm
func parsePKCacheKey(key interface{}) (string, string) {
	str, ok := key.(string)
	if !ok {
		return "", ""
	}
	s := strings.SplitN("\n", str, 2)
	if len(s) != 2 {
		return "", ""
	}
	return s[0], s[1]
}

func httpRequestBuildErr(requestPath string, err error) error {
	return fmt.Errorf("error buidling *http.Request against %q: %w", requestPath, err)
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

// buildRequest attempts to build an *http.Request type using values present in the provided context
func buildRequest(ctx context.Context, method, requestURL string, body interface{}, runner requestMutatorRunner, mutators ...RequestMutator) (*Request, error) {
	var bodyReader io.Reader

	// populate body reader, if necessary
	if body != nil {
		if _, ok := body.(RequestMutator); ok {
			return nil, errors.New("cannot provide a func of type RequestMutator as the request body")
		}
		if asReader, ok := body.(io.Reader); ok { // if the body is already a reader of some sort
			bodyReader = asReader
		} else if b, err := json.Marshal(body); err == nil { // otherwise, attempt to json-marshal body
			mutators = append(mutators, HeaderMutator("Content-Type", "application/json", true))
			bodyReader = bytes.NewReader(b)
		} else { // if there was an error during json serialization, return
			return nil, fmt.Errorf("unable to marshal body of type %T: %w", body, err)
		}
	}

	// build http request
	req, err := NewRequestWithContext(ctx, method, requestURL, bodyReader)
	if err != nil {
		return nil, err
	}

	// apply any mutators
	if i, err := runner(req, mutators...); err != nil {
		return nil, fmt.Errorf("mutator %d returned error: %w", i, err)
	}

	// specifically set accept header
	req.Header.Set(httpHeaderAccept, httpHeaderValueJSON)

	return req, nil
}

func contextStringValue(ctx context.Context, key string) (string, bool) {
	if v := ctx.Value(key); v != nil {
		if s, ok := v.(string); ok && s != "" {
			return s, true
		}
	}
	return "", false
}

func parseAddr(addr string, insecure bool) (string, error) {
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

func compileConfig(provided *APIClientConfig, mutators ...ConfigMutator) *APIClientConfig {
	actual := DefaultAPIClientConfig()

	// ensure we have something to compare with
	if provided == nil {
		provided = DefaultAPIClientConfig()
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

	// providers
	if provided.RealmProvider != nil {
		actual.RealmProvider = provided.RealmProvider
	}
	if provided.TokenProvider != nil {
		actual.TokenProvider = provided.TokenProvider
	}
	if provided.TokenParser != nil {
		actual.TokenParser = provided.TokenParser
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

func pkCacheEquivalencyTest(_, current, new interface{}) bool {
	return cmp.Equal(current, new)
}

func pkCacheEventCallback(pkc *TimedPublicKeyCache) sclg.TimedCacheEventCallback {
	return func(ev sclg.TimedCacheEvent, _ interface{}, message string) {
		pkc.log.Debug().Str("event", ev.String()).Str("event-message", message).Msg("Event seen")
	}
}

func handleResponse(resp *http.Response, modelPtr interface{}) error {
	// queue up body close
	defer func() { _ = resp.Body.Close() }()

	if modelPtr != nil {
		if err := json.NewDecoder(resp.Body).Decode(modelPtr); err != nil {
			return fmt.Errorf("error unmarshalling response into type %T: %w", modelPtr, err)
		}
	} else {
		_, _ = io.Copy(ioutil.Discard, resp.Body)
	}

	return nil
}
