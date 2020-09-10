package keycloak

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/go-querystring/query"
	"github.com/hashicorp/go-cleanhttp"
)

const (
	// grant type values
	GrantTypeCode              = "code"
	GrantTypeUMA2Ticket        = "urn:ietf:params:oauth:grant-type:uma-ticket"
	GrantTypeClientCredentials = "client_credentials"

	// token type hint values
	TokenTypeHintRequestingPartyToken = "requesting_party_token"

	// response modes
	UMA2ResponseModeDecision    = "decision"
	UMA2ResponseModePermissions = "permissions"

	// cache stuff
	pkKeyPrefix = "pk"
	pkKeyFormat = pkKeyPrefix + "\n%s\n%s\n%s"
	reKeyPrefix = "re"
	reKeyFormat = reKeyPrefix + "\n%s\n%s"

	// common
	httpHeaderAccept                    = "Accept"
	httpHeaderContentType               = "Content-Type"
	httpHeaderValueJSON                 = "application/json"
	httpHeaderValueFormURLEncoded       = "application/x-www-form-urlencoded"
	httpHeaderAuthorization             = "Authorization"
	httpHeaderAuthorizationBearerPrefix = "Bearer"
	httpHeaderAuthValueFormat           = httpHeaderAuthorizationBearerPrefix + " %s"
	httpHeaderLocationKey               = "Location"

	// permissions params
	paramTokenTypeHint = "token_type_hint"
	paramTypeToken     = "token"

	// url structures
	authServerURLFormat = "%s://%s/%s"
	apiPathFormat       = "%s/%s"

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
	// AuthServerURLProvider [required]
	//
	// This is called once during client initialization to determine the target keycloak instance
	AuthServerURLProvider AuthServerURLProvider

	// RealmProvider [required]
	//
	// This is called once during client initialization to determine which realm to scope queries against
	RealmProvider RealmProvider

	// BearerTokenProvider [optional]
	//
	// This is only required if you wish to execute queries against endpoints that require authentication.
	BearerTokenProvider BearerTokenProvider

	// RealmEnvironmentProvider [optional]
	//
	// This provides the built client with environment details about the target keycloak realm for this client
	RealmEnvironmentProvider RealmEnvironmentProvider

	// TokenParsers [required]
	//
	// List of token parser implementations to support with this client.
	TokenParsers []TokenParser

	// CacheBackend [optional]
	//
	// Optionally provide your own cache implementation.  This cache is used, by default, for realm environment and
	// parsed public key data.
	CacheBackend CacheBackend

	// HTTPClient [optional]
	//
	// Set if you wish to use a specific http client configuration.  Otherwise, one will be created using
	// cleanhttp.DefaultClient()
	HTTPClient *http.Client

	// Debug [optional]
	//
	// Optional configurations aimed to ease debugging
	Debug *DebugConfig
}

func DefaultAPIClientConfig() *APIClientConfig {
	c := APIClientConfig{
		AuthServerURLProvider:    defaultAuthServerURLProvider(),
		RealmProvider:            NewStaticRealmProvider("master"),
		RealmEnvironmentProvider: NewCachedRealmEnvironmentProvider(time.Hour),
		CacheBackend:             globalCache,
		TokenParsers:             []TokenParser{NewX509TokenParser(time.Hour)},
		HTTPClient:               cleanhttp.DefaultClient(),
		Debug:                    new(DebugConfig),
	}
	return &c
}

// APIClient
//
// This is the base client for interacting with a Keycloak instance
type APIClient struct {
	authServerURL string

	cache CacheBackend
	mr    requestMutatorRunner
	hc    *http.Client

	realmName string

	btp BearerTokenProvider
	rep RealmEnvironmentProvider

	tokenParsers   map[string]TokenParser
	tokenParsersMu sync.RWMutex
}

// NewAPIClient will attempt to construct and return a APIClient to you
func NewAPIClient(config *APIClientConfig, mutators ...ConfigMutator) (*APIClient, error) {
	var (
		cc  *APIClientConfig
		err error

		cl = new(APIClient)
	)

	cc = CompileAPIClientConfig(config, mutators...)

	// set and cleanup auth server url
	if cl.authServerURL, err = cc.AuthServerURLProvider.AuthServerURL(); err != nil {
		return nil, err
	}
	cl.authServerURL = strings.TrimRight(cl.authServerURL, "/")

	if cl.realmName, err = cc.RealmProvider.RealmName(); err != nil {
		return nil, err
	}

	if len(cc.TokenParsers) == 0 {
		return nil, errors.New("must provide at least one token parser")
	}

	cl.cache = cc.CacheBackend
	cl.tokenParsers = make(map[string]TokenParser)
	cl.RegisterTokenParsers(cc.TokenParsers...)
	cl.hc = cc.HTTPClient
	cl.mr = buildRequestMutatorRunner(cc.Debug)
	cl.rep = cc.RealmEnvironmentProvider
	cl.btp = cc.BearerTokenProvider

	return cl, nil
}

// NewClientWithProvider will construct a new APIClient using a combined provider, such as a
// ConfidentialClientTokenProvider
func NewClientWithProvider(cp CombinedProvider, mutators ...ConfigMutator) (*APIClient, error) {
	conf := DefaultAPIClientConfig()
	conf.AuthServerURLProvider = cp
	conf.RealmProvider = cp
	conf.BearerTokenProvider = cp
	return NewAPIClient(conf, mutators...)
}

// NewClientWithInstallDocument will construct an APIClient from an InstallDocument
func NewClientWithInstallDocument(id *InstallDocument, mutators ...ConfigMutator) (*APIClient, error) {
	// todo: support ID's for things other than a confidential client
	ctp, err := NewConfidentialClientTokenProvider(&ConfidentialClientTokenProviderConfig{InstallDocument: id})
	if err != nil {
		return nil, err
	}
	return NewClientWithProvider(ctp, mutators...)
}

// NewClientWithBearerToken will construct a new APIClient with a bearer token
func NewClientWithBearerToken(token string, mutators ...ConfigMutator) (*APIClient, error) {
	claims := new(StandardClaims)
	_, _, err := (new(jwt.Parser)).ParseUnverified(token, claims)
	if err != nil {
		return nil, err
	}
	split := strings.SplitN(claims.Issuer, "/realms/", 2)
	if len(split) != 2 {
		return nil, fmt.Errorf("unable to split token issuer %q into url : realm", claims.Issuer)
	}
	config := DefaultAPIClientConfig()
	config.AuthServerURLProvider = NewAuthServerURLProvider(split[0])
	config.RealmProvider = NewStaticRealmProvider(strings.Trim(split[1], "/"))
	config.BearerTokenProvider = NewStaticBearerTokenProvider(token)
	return NewAPIClient(config, mutators...)
}

// AuthServerURL will return the address of the issuer this client is targeting
func (c *APIClient) AuthServerURL() string {
	return c.authServerURL
}

func (c *APIClient) RealmName() string {
	return c.realmName
}

func (c *APIClient) CacheBackend() CacheBackend {
	return c.cache
}

func (c *APIClient) TokenParser(alg string) (TokenParser, bool) {
	c.tokenParsersMu.RLock()
	defer c.tokenParsersMu.RUnlock()
	tp, ok := c.tokenParsers[alg]
	return tp, ok
}

func (c *APIClient) RegisterTokenParsers(tps ...TokenParser) {
	c.tokenParsersMu.Lock()
	defer c.tokenParsersMu.Unlock()
	for _, tp := range tps {
		for _, alg := range tp.SupportedAlgorithms() {
			c.tokenParsers[alg] = tp
		}
	}
}

func (c *APIClient) RealmEnvironment(ctx context.Context) (*RealmEnvironment, error) {
	if c.rep == nil {
		return nil, errors.New("no realm environment provider configured with client")
	}
	return c.rep.RealmEnvironment(ctx, c)
}

func (c *APIClient) BearerTokenProvider() (BearerTokenProvider, error) {
	if c.btp == nil {
		return nil, errors.New("no bearer token provider configured with client")
	}
	return c.btp, nil
}

func (c *APIClient) Admin() *AdminAPIClient {
	return &AdminAPIClient{c}
}

// realmsURL builds a request path under the /realms/{realm}/... path
func (c *APIClient) realmsURL(bits ...string) string {
	return fmt.Sprintf(kcURLPathRealmsFormat, c.authServerURL, c.realmName, path.Join(bits...))
}

func (c *APIClient) callRealms(ctx context.Context, authenticated bool, method, requestPath string, body interface{}, mutators ...RequestMutator) (*http.Response, error) {
	return c.Call(ctx, authenticated, method, c.realmsURL(requestPath), body, mutators...)
}

func (c *APIClient) Do(ctx context.Context, req *APIRequest, mutators ...RequestMutator) (*http.Response, error) {
	var (
		httpRequest  *http.Request
		httpResponse *http.Response
		err          error
	)

	// apply any mutators
	if i, err := c.mr(req, mutators...); err != nil {
		return nil, fmt.Errorf("mutator %d returned error: %w", i, err)
	}

	// construct http request
	if httpRequest, err = req.ToHTTP(ctx); err != nil {
		return nil, err
	}

	// execute
	httpResponse, err = c.hc.Do(httpRequest)
	return httpResponse, err
}

// Call is a helper method that wraps the creation of an *APIRequest type and executes it.
func (c *APIClient) Call(ctx context.Context, authenticated bool, method, requestURL string, body interface{}, mutators ...RequestMutator) (*http.Response, error) {
	var (
		req *APIRequest
		err error
	)

	// ensure we've got an actual slice here
	if mutators == nil {
		mutators = make([]RequestMutator, 0)
	}

	if authenticated {
		if c.btp == nil {
			return nil, fmt.Errorf("cannot execute \"%s %s\" as it requires authentication but no bearer token provider was configured with client", method, requestURL)
		}
		var (
			token string
			err   error
		)
		if token, err = c.btp.BearerToken(); err != nil {
			if !IsTokenExpiredErr(err) {
				return nil, fmt.Errorf("error fetching bearer token: %w", err)
			}
			// attempt renew
			if rtp, ok := c.btp.(RenewableBearerTokenProvider); !ok {
				return nil, fmt.Errorf("token is expired, but provided BearerTokenProvider %T does not implement the renewable interface: %w", c.btp, err)
			} else if err = rtp.RenewBearerToken(ctx, c, false); err != nil {
				return nil, fmt.Errorf("error during token renew: %w", err)
			} else if token, err = c.btp.BearerToken(); err != nil {
				return nil, fmt.Errorf("error fetching bearer token after successful refresh: %w", err)
			}
		}
		mutators = appendRequestMutators(mutators, BearerTokenMutator(token))
	}

	req = NewAPIRequest(method, requestURL)
	if err = req.SetBody(body); err != nil {
		return nil, err
	}

	return c.Do(ctx, req, mutators...)
}

// RealmIssuerConfiguration returns metadata about the keycloak realm instance being connected to, such as the public
// key for token signing.
func (c *APIClient) RealmIssuerConfiguration(ctx context.Context, mutators ...RequestMutator) (*RealmIssuerConfiguration, error) {
	var (
		resp *http.Response
		ic   *RealmIssuerConfiguration
		err  error
	)
	resp, err = c.Call(ctx, false, http.MethodGet, c.realmsURL(), nil, mutators...)
	ic = new(RealmIssuerConfiguration)
	if err = handleResponse(resp, http.StatusOK, ic, err); err != nil {
		return nil, err
	}
	return ic, nil
}

// OpenIDConfiguration returns well-known open-id configuration values for the provided realm
func (c *APIClient) OpenIDConfiguration(ctx context.Context, mutators ...RequestMutator) (*OpenIDConfiguration, error) {
	var (
		resp *http.Response
		oidc *OpenIDConfiguration
		err  error
	)
	resp, err = c.Call(ctx, false, http.MethodGet, c.realmsURL(kcPathOIDC), nil, mutators...)
	oidc = new(OpenIDConfiguration)
	if err = handleResponse(resp, http.StatusOK, oidc, err); err != nil {
		return nil, err
	}
	return oidc, nil
}

// UMA2Configuration returns well-known uma2 configuration values for the provided realm, assuming you are running
// keycloak > 3.4
func (c *APIClient) UMA2Configuration(ctx context.Context, mutators ...RequestMutator) (*UMA2Configuration, error) {
	var (
		resp *http.Response
		uma2 *UMA2Configuration
		err  error
	)
	resp, err = c.Call(ctx, false, http.MethodGet, c.realmsURL(kcPathUMA2C), nil, mutators...)
	uma2 = new(UMA2Configuration)
	if err = handleResponse(resp, http.StatusOK, uma2, err); err != nil {
		return nil, err
	}
	return uma2, nil
}

func (c *APIClient) JSONWebKeys(ctx context.Context, mutators ...RequestMutator) (*JSONWebKeySet, error) {
	var (
		resp *http.Response
		jwks *JSONWebKeySet
		env  *RealmEnvironment
		err  error
	)
	if env, err = c.RealmEnvironment(ctx); err != nil {
		return nil, err
	}
	resp, err = c.Call(ctx, false, http.MethodGet, env.JSONWebKeysEndpoint(), nil, mutators...)
	jwks = new(JSONWebKeySet)
	if err = handleResponse(resp, http.StatusOK, jwks, err); err != nil {
		return nil, err
	}
	return jwks, nil
}

func (c *APIClient) Login(ctx context.Context, req *OpenIDConnectTokenRequest, mutators ...RequestMutator) (*OpenIDConnectToken, error) {
	var (
		res   interface{}
		token *OpenIDConnectToken
		ok    bool
		err   error
	)
	req.ResponseMode = nil
	if res, err = c.openIDConnectToken(ctx, false, req, mutators...); err != nil {
		return nil, err
	}
	if token, ok = res.(*OpenIDConnectToken); !ok {
		return nil, fmt.Errorf("expected response to be %T, saw %T", token, res)
	}
	return token, nil
}

// ParseRequestToken attempts to extract the encoded bearer token from the provided request and parse it into a modeled
// access token type
func (c *APIClient) ParseRequestToken(ctx context.Context, request *http.Request, claimsType jwt.Claims) (*jwt.Token, error) {
	if bt, ok := RequestBearerToken(request); ok {
		return c.ParseToken(ctx, bt, claimsType)
	}
	return nil, errors.New("bearer token not found in request")
}

// ParseToken will attempt to parse and validate a raw token into a modeled type.  If this method does not return
// an error, you can safely assume the provided raw token is safe for use.
func (c *APIClient) ParseToken(ctx context.Context, rawToken string, claimsType jwt.Claims) (*jwt.Token, error) {
	var (
		jwtToken *jwt.Token
		err      error
	)
	if claimsType == nil {
		claimsType = new(StandardClaims)
	}
	if jwtToken, err = jwt.ParseWithClaims(rawToken, claimsType, c.keyFunc(ctx)); err != nil {
		return nil, fmt.Errorf("error parsing raw token into %T: %w", claimsType, err)
	}
	return jwtToken, nil
}

func (c *APIClient) keyFunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		var (
			tp TokenParser
			ok bool
		)
		if tp, ok = c.TokenParser(token.Method.Alg()); !ok {
			return nil, fmt.Errorf("no token parser registered to handle %q", token.Method.Alg())
		}
		return tp.Parse(ctx, c, token)
	}
}

func (c *APIClient) TokenProvider() BearerTokenProvider {
	return c.btp
}

func (c *APIClient) openIDConnectToken(ctx context.Context, authenticated bool, req *OpenIDConnectTokenRequest, mutators ...RequestMutator) (interface{}, error) {
	var (
		body  url.Values
		resp  *http.Response
		env   *RealmEnvironment
		model interface{}
		err   error
	)
	if env, err = c.RealmEnvironment(ctx); err != nil {
		return nil, err
	}
	if body, err = query.Values(req); err != nil {
		return nil, fmt.Errorf("error encoding request: %w", err)
	}
	resp, err = c.Call(
		ctx,
		authenticated,
		http.MethodPost,
		env.TokenEndpoint(),
		body,
		appendRequestMutators(mutators, HeaderMutator(httpHeaderContentType, httpHeaderValueFormURLEncoded, true))...,
	)
	if req.ResponseMode == nil {
		model = new(OpenIDConnectToken)
	} else {
		switch *req.ResponseMode {
		case UMA2ResponseModeDecision:
			model = new(PermissionDecisionResponse)
		case UMA2ResponseModePermissions:
			model = make(EvaluatedPermissions, 0)

		default:
			model = new(OpenIDConnectToken)
		}
	}
	if err = handleResponse(resp, http.StatusOK, model, err); err != nil {
		return nil, err
	}
	return model, nil
}

// AdminAPIClient is a simple extension of the base APIClient, adding /admin api calls
type AdminAPIClient struct {
	*APIClient
}

func NewAdminAPIClient(config *APIClientConfig, mutators ...ConfigMutator) (*AdminAPIClient, error) {
	var (
		c   *APIClient
		err error
	)
	if c, err = NewAPIClient(config, mutators...); err != nil {
		return nil, err
	}
	return c.Admin(), nil
}

func NewAdminClientWithProvider(cp CombinedProvider, mutators ...ConfigMutator) (*AdminAPIClient, error) {
	c, err := NewClientWithProvider(cp)
	if err != nil {
		return nil, err
	}
	return c.Admin(), nil
}

func NewAdminClientWithInstallDocument(id *InstallDocument, mutators ...ConfigMutator) (*AdminAPIClient, error) {
	c, err := NewClientWithInstallDocument(id, mutators...)
	if err != nil {
		return nil, err
	}
	return c.Admin(), nil
}

// adminRealmsURL builds a request path under the /admin/realms/{realm}/... path
func (c *AdminAPIClient) adminRealmsURL(bits ...string) string {
	return fmt.Sprintf(kcURLPathAdminRealmsFormat, c.authServerURL, c.realmName, path.Join(bits...))
}

func (c *AdminAPIClient) callAdminRealms(ctx context.Context, method, requestPath string, body interface{}, mutators ...RequestMutator) (*http.Response, error) {
	return c.Call(ctx, true, method, c.adminRealmsURL(requestPath), body, mutators...)
}
