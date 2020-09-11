package keycloak

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"strconv"
)

const (
	ParameterDestinationQuery  = "query"
	ParameterDestinationHeader = "header"
)

// ConfigMutator
//
// ConfigMutator provides some flexibility when constructing an api client
type ConfigMutator func(*APIClientConfig)

// APIRequestMutator
//
// This callback func type allows you to modify any *http.Request executed by the client in this package once it has
// been built.
type APIRequestMutator func(*APIRequest) error

// ValuedParameterFormatter
//
// This func is called inside the ValuedQueryMutator func to determine if and how the provided value will be added to
// a given request's query parameter string.
type ValuedParameterFormatterFunc func(destination, name string, value interface{}) (formatted string, use bool)

// ValuedParameterFormatter is called by the ValuedQueryParameter and ValuedHeaderFormatter funcs when determining
// if and how values should be added to a given request
var ValuedParameterFormatter ValuedParameterFormatterFunc = DefaultValuedParameterFormatter

// DefaultValuedParameterFormatter provides some baseline value-to-string conversions, skipping zero-vals.
func DefaultValuedParameterFormatter(_, _ string, v interface{}) (string, bool) {
	// if provided is nil, immediately return
	if v == nil {
		return "", false
	}

	// some basic type tests
	switch v.(type) {
	case string:
		if sv := v.(string); sv != "" {
			return sv, true
		}

	case int:
		if iv := v.(int); iv != 0 {
			return strconv.Itoa(v.(int)), true
		}

	case int64:
		if iv := v.(int64); iv != 0 {
			return strconv.FormatInt(v.(int64), 10), true
		}

	case float64:
		if fv := v.(float64); fv != 0 {
			return strconv.FormatFloat(v.(float64), 'f', 8, 64), true
		}

	case uint64:
		if uv := v.(uint64); uv != 0 {
			return strconv.FormatUint(uv, 10), true
		}

	case bool:
		if bv := v.(bool); bv {
			return strconv.FormatBool(bv), true
		}

	default:
		// ideally this will very rarely / never be hit, but may as well leave it here as a catch-all.
		if reflect.ValueOf(v).IsZero() {
			return "", false
		}
		return fmt.Sprintf("%v", v), true
	}

	// if we reach here, assume zeroval of switch case
	return "", false
}

// QueryMutator will return a APIRequestMutator that either sets or adds a query parameter and value
func QueryMutator(k, v string, override bool) APIRequestMutator {
	return func(r *APIRequest) error {
		if override {
			r.SetQueryParameter(k, []string{v})
		} else {
			r.AddQueryParameter(k, []string{v})
		}
		return nil
	}
}

// ValuedQueryMutator will return a APIRequestMutator only if v is a non-zero value of its type
func ValuedQueryMutator(k string, v interface{}, override bool) APIRequestMutator {
	if sv, ok := ValuedParameterFormatter(ParameterDestinationQuery, k, v); ok {
		return QueryMutator(k, sv, override)
	}
	return nil
}

// HeaderMutator returns a APIRequestMutator that will add or override a value in the header of the request
func HeaderMutator(k, v string, override bool) APIRequestMutator {
	return func(r *APIRequest) error {
		if override {
			r.SetHeader(k, v)
		} else {
			r.AddHeader(k, v)
		}
		return nil
	}
}

// ValuedHeaderMutator returns a APIRequestMutator that will add or override a value in the header of a request, given the
// provided value is "valued"
func ValuedHeaderMutator(k string, v interface{}, override bool) APIRequestMutator {
	if sv, ok := ValuedParameterFormatter(ParameterDestinationHeader, k, v); ok {
		return HeaderMutator(k, sv, override)
	}
	return nil
}

func BearerAuthRequestMutator(rawToken string) APIRequestMutator {
	return func(r *APIRequest) error {
		if rawToken != "" {
			r.SetHeader(httpHeaderAuthorization, fmt.Sprintf(httpHeaderAuthValueFormat, httpHeaderAuthorizationBearerPrefix, rawToken))
		}
		return nil
	}
}

func BasicAuthRequestMutator(username, password string) APIRequestMutator {
	return func(r *APIRequest) error {
		r.SetHeader(
			httpHeaderAuthorization,
			fmt.Sprintf(
				httpHeaderAuthValueFormat,
				httpHeaderAuthorizationBasicPrefix,
				base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password))),
			),
		)
		return nil
	}
}

type requestMutatorRunner func(req *APIRequest, mutators ...APIRequestMutator) (int, error)

func baseRequestMutatorRunner(req *APIRequest, mutators ...APIRequestMutator) (int, error) {
	if len(mutators) == 0 {
		return 0, nil
	}
	var (
		i   int
		m   APIRequestMutator
		err error
	)
	for i, m = range mutators {
		if m == nil {
			continue
		}
		if err = m(req); err != nil {
			return i, err
		}
	}
	return i, nil
}

func debugRequestMutatorRunner(c *DebugConfig) requestMutatorRunner {
	var (
		pre       []APIRequestMutator
		post      []APIRequestMutator
		staticLen int
	)

	if l := len(c.BaseRequestMutators); l > 0 {
		pre = make([]APIRequestMutator, l, l)
		copy(pre, c.BaseRequestMutators)
		staticLen = l
	}
	if l := len(c.FinalRequestMutators); l > 0 {
		post = make([]APIRequestMutator, l, l)
		copy(post, c.FinalRequestMutators)
		staticLen += l
	}

	return func(req *APIRequest, mutators ...APIRequestMutator) (int, error) {
		var (
			m APIRequestMutator
			i int

			l    = staticLen + len(mutators)
			muts = make([]APIRequestMutator, l, l)
		)
		for _, m = range pre {
			muts[i] = m
			i++
		}
		for _, m = range mutators {
			muts[i] = m
			i++
		}
		for _, m = range post {
			muts[i] = m
			i++
		}
		return baseRequestMutatorRunner(req, muts...)
	}
}

func buildRequestMutatorRunner(c *DebugConfig) requestMutatorRunner {
	if c == nil || (len(c.BaseRequestMutators) == 0 && len(c.FinalRequestMutators) == 0) {
		return baseRequestMutatorRunner
	}
	return debugRequestMutatorRunner(c)
}
