package keycloak

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/rs/zerolog"
)

const (
	// API Context value keys
	ContextKeyIssuerAddress = "issuer_address"
	ContextKeyToken         = "token"
	ContextKeyRealm         = "keycloak_realm"

	// config defaults for
	DefaultPathPrefix        = "auth"
	DefaultPublicKeyCacheTTL = 24 * time.Hour

	// public key cache stuff
	pkKeyFormat = "%s\n%s"

	// common
	httpHeaderAccept                    = "Accept"
	httpHeaderContentType               = "Content-Type"
	httpHeaderValueJSON                 = "application/json"
	httpHeaderValueFormURLEncoded       = "application/x-www-form-urlencoded"
	httpHeaderAuthorization             = "Authorization"
	httpHeaderAuthorizationBearerPrefix = "Bearer "
	httpHeaderAuthValueFormat           = httpHeaderAuthorizationBearerPrefix + "%s"
	httpHeaderLocationKey               = "Location"

	// url structures
	addressFormat = "%s://%s/"
	apiPathFormat = "%s/%s"

	// ks api paths
	kcURLPathRealmsFormat      = "%s/realms/%s/%s"
	kcURLPathAdminRealmsFormat = "%s/admin/realms/%s/%s"
	kcPathOIDC                 = ".well-known/openid-configuration"
	kcPathUMA2C                = ".well-known/uma2-configuration"
	kcPathPrefixEntitlement    = "authz/entitlement"
	kcPathPartAvailable        = "available"
	kcPathPartClients          = "clients"
	kcPathPartComposites       = "composites"
	kcPathPartCount            = "count"
	kcPathPartGroups           = "groups"
	kcPathPartMembers          = "members"
	kcPathPartRealm            = "realm"
	kcPathPartRoleMappings     = "role-mappings"
	kcPathPartRoles            = "roles"
	kcPathPartUsers            = "users"
)

// DebugConfig
//
// This type contains configuration options that provide additional utility during testing or development, but should
// not be configured when in production use.
type DebugConfig struct {
	// BaseRequestMutators [optional]
	//
	// Optional list of request mutators that will always be run before any other mutators
	BaseRequestMutators []RequestMutator

	// FinalRequestMutators [optional]
	//
	// Optional list of request mutators that will always be run after any other mutators
	FinalRequestMutators []RequestMutator
}

// APIClientConfig
//
// This is the configuration container for a APIClient.  See individual comments on fields for more details.
type APIClientConfig struct {
	// IssuerProvider [optional]
	//
	// The IssuerProvider is called ONCE during client construction to determine the address of the  instance
	// to connect to.  It is never called again, and no reference to it is kept in the client.
	//
	// If left blank, a provider will be created that will attempt to fetch the issuer address from Consul via the kv
	// path defined by the DefaultTokenIssuer constant in this package.
	//
	// See "provider_issuer.go" for available providers.
	IssuerProvider IssuerProvider

	// RealmProvider [optional]
	//
	// The RealmProvider will be called on a per-request basis, depending on if that request needs to have the realm
	// injected into the context.
	//
	// This is used in a few key ways:
	// -  Public Key retrieval and caching
	// -  URL construction (i.e. /auth/realms/{realm}/.well-known/openid-configuration)
	// -  Token validation
	//
	// The above is not a comprehensive list, but generally speaking the overwhelming majority of requests require the
	// realm value to defined.
	//
	// See "provider_realm.go" for implementation details.  If you construct a config using DefaultAPIClientConfig(),
	// you will be expected to provide a context with the realm already defined with each request
	RealmProvider RealmProvider

	// TokenProvider [optional]
	//
	// The TokenProvider will be called on a per-request basis, as it is needed.  Not all requests require a bearer
	// token.  For example, the OpenID Configuration and Realm Issuer Configuration endpoints are open and simply
	// require a Realm value.
	//
	// As a general rule, however, all  "admin" endpoints (i.e. /auth/admin/realms/{realm}/users) will require
	// a token.
	//
	// See "token_provider.go" for implementation details.  If you construct a config using DefaultAPIClientConfig(),
	// you will be expected to provide a context with a token already defined with each request
	TokenProvider TokenProvider

	// TokenParser [optional]
	//
	// The TokenParser will be called any time the client needs a realm's public key.  This is primarily used to
	// validate access and bearer tokens
	TokenParser TokenParser

	// PathPrefix [optional]
	//
	// URL Path prefix.  Defaults to value of DefaultPathPrefix.
	PathPrefix string

	// HTTPClient [optional]
	//
	// Set if you wish to use a specific http client configuration.  Otherwise, one will be created using
	// cleanhttp.DefaultClient()
	HTTPClient *http.Client

	// Logger [optional]
	//
	// Optionally provide a logger instance to use
	Logger zerolog.Logger

	// Debug [optional]
	//
	// Optional configurations aimed to ease debugging
	Debug *DebugConfig
}

// DefaultAPIClientConfig will return a config populated with useful default values where the realm and token are
// expected to be manually defined in the context provided to each request.
func DefaultAPIClientConfig() *APIClientConfig {
	c := APIClientConfig{
		PathPrefix:     DefaultPathPrefix,
		IssuerProvider: defaultIssuerProvider(),
		RealmProvider:  ContextRealmProvider(),
		TokenProvider:  ContextTokenProvider(),
		TokenParser:    NewX509TokenParser(0),
		HTTPClient:     cleanhttp.DefaultClient(),
		Logger:         DefaultZerologLogger(),
		Debug:          new(DebugConfig),
	}
	return &c
}

// DefaultAPIClientConfigWithRealm returns a new config with all defaults except that the RealmProvider is replaced with
// a StaticRealmProvider
func DefaultAPIClientConfigWithRealm(realm string) *APIClientConfig {
	c := DefaultAPIClientConfig()
	c.RealmProvider = NewStaticRealmProvider(realm)
	return c
}

// APIClient
//
// The APIClient is the root of the entire package.
type APIClient struct {
	log zerolog.Logger

	issAddr    string
	pathPrefix string

	mr requestMutatorRunner

	realmProvider RealmProvider
	tokenProvider TokenProvider
	tokenParser   TokenParser

	hc *http.Client
}

// NewAPIClient will attempt to construct and return a APIClient to you
func NewAPIClient(config *APIClientConfig, mutators ...ConfigMutator) (*APIClient, error) {
	var (
		cc  *APIClientConfig
		err error

		cl = new(APIClient)
	)

	// try to ensure we have a sane-ish config
	cc = compileConfig(config, mutators...)

	// attempt to set issuer address
	if cl.issAddr, err = cc.IssuerProvider.IssuerAddress(); err != nil {
		return nil, err
	}

	// set paths
	cl.pathPrefix = cc.PathPrefix

	// set http client
	cl.hc = cc.HTTPClient

	// set providers
	cl.realmProvider = cc.RealmProvider
	cl.tokenProvider = cc.TokenProvider
	cl.tokenParser = cc.TokenParser

	// set logger and debug mode
	cl.log = cc.Logger

	// build request mutator runner
	cl.mr = buildRequestMutatorRunner(cc.Debug)

	return cl, nil
}

// NewAPIClientWithIssuerAddress is a shortcut constructor that only requires you provide the address of the keycloak
// instance this client will be executing calls against
func NewAPIClientWithIssuerAddress(issuerAddress string, mutators ...ConfigMutator) (*APIClient, error) {
	conf := DefaultAPIClientConfig()
	conf.IssuerProvider = NewStaticIssuerProvider(issuerAddress)
	return NewAPIClient(conf, mutators...)
}

func (c *APIClient) PathPrefix() string {
	return c.pathPrefix
}

// IssuerAddress will return the address of the issuer this client is targeting
func (c *APIClient) IssuerAddress() string {
	return c.issAddr
}

// RealmProvider will return the RealmProvider defined at client construction
func (c *APIClient) RealmProvider() RealmProvider {
	return c.realmProvider
}

// TokenProvider will return the TokenProvider defined at client construction
func (c *APIClient) TokenProvider() TokenProvider {
	return c.tokenProvider
}

// TokenParser will return the token parser defined at client construction
func (c *APIClient) TokenParser() TokenParser {
	return c.tokenParser
}

// AuthService contains modeled api calls for auth API requests
func (c *APIClient) AuthService() *AuthService {
	return NewAuthService(c)
}

// AdminService contains modeled api calls for admin API requests
func (c *APIClient) AdminService() *AdminService {
	return NewAdminService(c)
}

// RequestAccessToken attempts to extract the encoded bearer token from the provided request and parse it into a modeled
// access token type
func (c *APIClient) RequestAccessToken(ctx context.Context, request *http.Request, claimsType jwt.Claims) (*jwt.Token, error) {
	if bt, ok := RequestBearerToken(request); ok {
		return c.AuthService().ParseToken(ctx, bt, claimsType)
	}
	return nil, errors.New("bearer token not found in request")
}

// Call will attempt to execute an arbitrary request against the issuer provided at client creation
//
// All API requests flow through this method.
//
// It does the following in this order:
//	1. Compiles full URL against client issuer with provided request path
//	2. Constructs *http.Request from provided variables
//	3. Executes, in order, any and all provided RequestMutators
// 	4. Executes request using internal *http.APIClient instance
//
//	Parameters:
//		- ctx:			This must be provided by you.  This call only directly optionally requires token values
//		- method: 		This must be an HTTP request method (GET, POST, PUT, etc.)
//		- requestPath: 	This must be the API request path relative to the root of the IssuerHostname provided at client construction (i.e. "/auth/admin/realms/customer/groups/")
//		- body:			This must either be nil, an io.Reader implementation, or a json-serializable type that will be set as the body of the constructed *http.Request
//		- mutators:		This may be zero or more funcs adhering to the RequestMutator type.  These funcs will be executed in order provided.
//
// 	Response:
//		- *http.Response:	The raw HTTP response seen.  Body will NOT have been read by this point.
//		- error:		Any error seen during the execution of this func.
func (c *APIClient) Call(ctx context.Context, method, requestPath string, body interface{}, mutators ...RequestMutator) (*http.Response, error) {
	var (
		requestURL string
		req        *Request
		httpReq    *http.Request
		err        error
	)

	// build url
	requestURL = fmt.Sprintf("%s%s", c.issAddr, strings.TrimLeft(requestPath, "/"))

	// ensure we've got an actual slice here
	if mutators == nil {
		mutators = make([]RequestMutator, 0)
	}

	// if this request has a bearer token associated with it,
	if token, ok := contextStringValue(ctx, ContextKeyToken); ok {
		mutators = append(mutators, bearerTokenMutator(token))
	}

	// test context sanity before we even do the rest of this stuff.
	if err = ctx.Err(); err != nil {
		return nil, err
	}

	// build request
	req, err = buildRequest(ctx, method, requestURL, body, c.mr, mutators...)
	if err != nil {
		return nil, httpRequestBuildErr(requestPath, err)
	}

	httpReq = req.build()

	c.log.Debug().
		Str("request-method", method).
		Str("request-url", httpReq.URL.String()).
		Str("request-body-type", fmt.Sprintf("%T", body)).
		Int("request-mutators", len(mutators)).
		Msg("Preparing to execute new request...")

	return c.hc.Do(httpReq)
}

// CallRequireOK is a convenience method that will return an error if the seen response code was anything other than
// 200 OK.  If the response was OK and the "model" parameter was defined, it will attempt to json.Unmarshal the response
// body into this model.
func (c *APIClient) CallRequireOK(ctx context.Context, method, requestPath string, body interface{}, mutators ...RequestMutator) (*http.Response, error) {
	var (
		resp *http.Response
		err  error
	)

	// execute request and determine if we have an error
	if resp, err = c.Call(ctx, method, requestPath, body, mutators...); err != nil {
		return resp, fmt.Errorf("error executing request %q: %w", requestPath, err)
	}

	// test for 200
	if resp.StatusCode != http.StatusOK {
		return resp, fmt.Errorf("received non-200 from request \"%s %s\": %d (%s)", method, requestPath, resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	return resp, nil
}

func (c *APIClient) requireRealm(ctx context.Context) (context.Context, error) {
	return c.RealmProvider().SetRealmValue(ctx)
}

func (c *APIClient) requireToken(ctx context.Context) (context.Context, error) {
	return c.TokenProvider().SetTokenValue(ctx, c)
}

func (c *APIClient) requireAllContextValues(ctx context.Context) (context.Context, error) {
	if ctx, err := c.requireRealm(ctx); err != nil {
		return nil, err
	} else if ctx, err = c.requireToken(ctx); err != nil {
		return nil, err
	} else {
		return ctx, nil
	}
}
