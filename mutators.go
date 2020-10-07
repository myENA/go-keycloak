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

// ParameterFormatter
//
// This func is called when creating request mutators to determine if and how the provided value will be added to
// a given request's query parameter string.
type ParameterFormatterFunc func(location, name string, value interface{}) (formatted string, valued bool)

// ParameterFormatter is called when creating request mutators
var ParameterFormatter ParameterFormatterFunc = DefaultParameterFormatter

// DefaultParameterFormatter provides some baseline value-to-string conversions.  The 2nd argument must indicate whether
// the value is a zero-val of that type or not
func DefaultParameterFormatter(_, _ string, v interface{}) (value string, valued bool) {
	// if provided is nil, immediately return
	if v == nil {
		return "", false
	}

	// some basic type tests
	switch v.(type) {
	case string:
		sv := v.(string)
		return sv, sv != ""

	case int:
		iv := v.(int)
		return strconv.Itoa(v.(int)), iv != 0

	case int64:
		iv := v.(int64)
		return strconv.FormatInt(v.(int64), 10), iv != 0

	case float64:
		fv := v.(float64)
		return strconv.FormatFloat(v.(float64), 'f', 8, 64), fv != 0

	case uint64:
		uv := v.(uint64)
		return strconv.FormatUint(uv, 10), uv != 0

	case bool:
		bv := v.(bool)
		return strconv.FormatBool(bv), bv

	default:
		// ideally this will very rarely / never be hit, but may as well leave it here as a catch-all.
		return fmt.Sprintf("%v", v), reflect.ValueOf(v).IsZero()
	}
}

func buildQueryMutator(k string, v, def interface{}, override, requiredValued bool) APIRequestMutator {
	return func(r *APIRequest) error {
		value, valued := DefaultParameterFormatter(ParameterDestinationQuery, k, v)
		if !valued && def != nil {
			value, valued = DefaultParameterFormatter(ParameterDestinationQuery, k, def)
		}
		if requiredValued && !valued {
			return nil
		}
		if override {
			r.SetQueryParameter(k, value)
		} else {
			r.AddQueryParameter(k, value)
		}
		return nil
	}
}

// QueryMutator will return a APIRequestMutator that either sets or adds a query parameter and value
func QueryMutator(key string, value interface{}, override bool) APIRequestMutator {
	return buildQueryMutator(key, value, nil, override, false)
}

// NonZeroQueryMutator will return a APIRequestMutator only if v is a non-zero value of its type
func NonZeroQueryMutator(key string, value, defaultValue interface{}, override bool) APIRequestMutator {
	return buildQueryMutator(key, value, defaultValue, override, true)
}

func buildHeaderMutator(k string, v, def interface{}, override, requiredValued bool) APIRequestMutator {
	return func(r *APIRequest) error {
		value, valued := DefaultParameterFormatter(ParameterDestinationQuery, k, v)
		if !valued && def != nil {
			value, valued = DefaultParameterFormatter(ParameterDestinationQuery, k, def)
		}
		if requiredValued && !valued {
			return nil
		}
		if override {
			r.SetHeader(k, value)
		} else {
			r.AddHeader(k, value)
		}
		return nil
	}
}

// HeaderMutator returns a APIRequestMutator that will add or override a value in the header of the request
func HeaderMutator(k, v string, override bool) APIRequestMutator {
	return buildHeaderMutator(k, v, nil, override, false)
}

// NonZeroHeaderMutator returns a APIRequestMutator that will add or override a value in the header of a request if v
// is a non-zero value of its type
func NonZeroHeaderMutator(k string, v, def interface{}, override bool) APIRequestMutator {
	return buildHeaderMutator(k, v, def, override, true)
}

func BearerAuthRequestMutator(rawToken string) APIRequestMutator {
	return func(r *APIRequest) error {
		if rawToken != "" {
			r.SetHeader(HTTPpHeaderAuthorization, fmt.Sprintf(httpHeaderAuthValueFormat, httpHeaderAuthorizationBearerPrefix, rawToken))
		}
		return nil
	}
}

func BasicAuthRequestMutator(username, password string) APIRequestMutator {
	return func(r *APIRequest) error {
		r.SetHeader(
			HTTPpHeaderAuthorization,
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
