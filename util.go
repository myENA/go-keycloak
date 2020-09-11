package keycloak

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
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

func parseResponseLocations(resp *http.Response) ([]string, error) {
	locations, ok := resp.Header[httpHeaderLocationKey]
	if !ok {
		return nil, errors.New("unable to locate new InstallDocument in response")
	}
	if ll := len(locations); ll == 0 {
		return nil, errors.New("unable to locate new InstallDocument in response")
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

func CompileAPIClientConfig(provided *APIClientConfig, mutators ...ConfigMutator) *APIClientConfig {
	actual := DefaultAPIClientConfig()

	// ensure we have something to compare with
	if provided == nil {
		provided = new(APIClientConfig)
	}

	// execute mutators
	for _, fn := range mutators {
		fn(provided)
	}

	// to ensure we have something resembling a usable config...

	if provided.AuthServerURLProvider != nil {
		actual.AuthServerURLProvider = provided.AuthServerURLProvider
	}
	if provided.RealmProvider != nil {
		actual.RealmProvider = provided.RealmProvider
	}
	if provided.AuthProvider != nil {
		actual.AuthProvider = provided.AuthProvider
	}
	if provided.CacheBackend != nil {
		actual.CacheBackend = provided.CacheBackend
	}
	if provided.HTTPClient != nil {
		actual.HTTPClient = provided.HTTPClient
	}
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

func appendRequestMutators(root []APIRequestMutator, m ...APIRequestMutator) []APIRequestMutator {
	if root == nil {
		root = make([]APIRequestMutator, 0)
	}
	return append(root, m...)
}
