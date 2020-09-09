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
	// The AuthServerURLProvider is called ONCE during client construction to determine the address of the  instance
	// to connect to.  It is never called again, and no reference to it is kept in the client.
	//
	// If left blank, a provider will be created that will attempt to fetch the issuer address from Consul via the kv
	// path defined by the DefaultTokenIssuer constant in this package.
	//
	// See "providers.go" for available providers.
	AuthServerURLProvider AuthServerURLProvider

	// TokenParsers [required]
	//
	// List of token parser implementations to support with this client.  These will be used for all realm clients
	// created by this client instance
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
		AuthServerURLProvider: defaultIssuerProvider(),
		CacheBackend:          globalCache,
		TokenParsers:          []TokenParser{NewX509TokenParser(time.Hour)},
		HTTPClient:            cleanhttp.DefaultClient(),
		Debug:                 new(DebugConfig),
	}
	return &c
}

// APIClient
//
// This is the base client for interacting with a Keycloak instance
type APIClient struct {
	authServerURL string

	cache CacheBackend

	mr requestMutatorRunner
	hc *http.Client

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

	if len(cc.TokenParsers) == 0 {
		return nil, errors.New("must provide at least one token parser")
	}

	cl.cache = cc.CacheBackend
	cl.tokenParsers = make(map[string]TokenParser)
	cl.RegisterTokenParsers(cc.TokenParsers...)
	cl.hc = cc.HTTPClient
	cl.mr = buildRequestMutatorRunner(cc.Debug)

	return cl, nil
}

// NewAPIClientWithIssuerAddress is a shortcut constructor that only requires you provide the address of the keycloak
// instance this client will be executing calls against
func NewAPIClientWithIssuerAddress(issuerAddress string, mutators ...ConfigMutator) (*APIClient, error) {
	conf := DefaultAPIClientConfig()
	conf.AuthServerURLProvider = NewAuthServerURLProvider(issuerAddress)
	return NewAPIClient(conf, mutators...)
}

// AuthServerURL will return the address of the issuer this client is targeting
func (c *APIClient) AuthServerURL() string {
	return c.authServerURL
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

func (c *APIClient) CacheBackend() CacheBackend {
	return c.cache
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
func (c *APIClient) Call(ctx context.Context, method, requestURL string, body interface{}, mutators ...RequestMutator) (*http.Response, error) {
	var (
		req *APIRequest
		err error
	)

	// ensure we've got an actual slice here
	if mutators == nil {
		mutators = make([]RequestMutator, 0)
	}

	req = NewAPIRequest(method, requestURL)
	if err = req.SetBody(body); err != nil {
		return nil, err
	}

	return c.Do(ctx, req, mutators...)
}

// RealmIssuerConfiguration returns metadata about the keycloak realm instance being connected to, such as the public
// key for token signing.
func (c *APIClient) RealmIssuerConfiguration(ctx context.Context, realmName string, mutators ...RequestMutator) (*RealmIssuerConfiguration, error) {
	var (
		resp *http.Response
		ic   *RealmIssuerConfiguration
		err  error
	)
	resp, err = c.Call(ctx, http.MethodGet, c.realmsURL(realmName), nil, mutators...)
	ic = new(RealmIssuerConfiguration)
	if err = handleResponse(resp, http.StatusOK, ic, err); err != nil {
		return nil, err
	}
	return ic, nil
}

// OpenIDConfiguration returns well-known open-id configuration values for the provided realm
func (c *APIClient) OpenIDConfiguration(ctx context.Context, realmName string, mutators ...RequestMutator) (*OpenIDConfiguration, error) {
	var (
		resp *http.Response
		oidc *OpenIDConfiguration
		err  error
	)
	resp, err = c.Call(ctx, http.MethodGet, c.realmsURL(realmName, kcPathOIDC), nil, mutators...)
	oidc = new(OpenIDConfiguration)
	if err = handleResponse(resp, http.StatusOK, oidc, err); err != nil {
		return nil, err
	}
	return oidc, nil
}

// UMA2Configuration returns well-known uma2 configuration values for the provided realm, assuming you are running
// keycloak > 3.4
func (c *APIClient) UMA2Configuration(ctx context.Context, realmName string, mutators ...RequestMutator) (*UMA2Configuration, error) {
	var (
		resp *http.Response
		uma2 *UMA2Configuration
		err  error
	)
	resp, err = c.Call(ctx, http.MethodGet, c.realmsURL(realmName, kcPathUMA2C), nil, mutators...)
	uma2 = new(UMA2Configuration)
	if err = handleResponse(resp, http.StatusOK, uma2, err); err != nil {
		return nil, err
	}
	return uma2, nil
}

func (c *APIClient) OpenIDConnectToken(ctx context.Context, env *RealmEnvironment, oidcRequest *OpenIDConnectTokenRequest, mutators ...RequestMutator) (*OpenIDConnectToken, error) {
	var (
		body  url.Values
		resp  *http.Response
		token *OpenIDConnectToken
		err   error
	)
	if body, err = query.Values(oidcRequest); err != nil {
		return nil, fmt.Errorf("error encoding request: %w", err)
	}
	resp, err = c.Call(
		ctx,
		http.MethodPost,
		env.TokenEndpoint(),
		strings.NewReader(body.Encode()),
		appendRequestMutators(mutators, HeaderMutator(httpHeaderContentType, httpHeaderValueFormURLEncoded, true))...,
	)
	token = new(OpenIDConnectToken)
	if err = handleResponse(resp, http.StatusOK, token, err); err != nil {
		return nil, err
	}
	return token, nil
}

func (c *APIClient) JSONWebKeys(ctx context.Context, env *RealmEnvironment, mutators ...RequestMutator) (*JSONWebKeySet, error) {
	var (
		resp *http.Response
		jwks *JSONWebKeySet
		err  error
	)
	resp, err = c.Call(ctx, http.MethodGet, env.JSONWebKeysEndpoint(), nil, mutators...)
	jwks = new(JSONWebKeySet)
	if err = handleResponse(resp, http.StatusOK, jwks, err); err != nil {
		return nil, err
	}
	return jwks, nil
}

// realmsURL builds a request path under the /realms/{realm}/... path
func (c *APIClient) realmsURL(realm string, bits ...string) string {
	return fmt.Sprintf(kcURLPathRealmsFormat, c.authServerURL, realm, path.Join(bits...))
}

// adminRealmsURL builds a request path under the /admin/realms/{realm}/... path
func (c *APIClient) adminRealmsURL(realm string, bits ...string) string {
	return fmt.Sprintf(kcURLPathAdminRealmsFormat, c.authServerURL, realm, path.Join(bits...))
}

type TokenAPIClientConfig struct {
	// RealmProvider [required]
	//
	// This is used during token client initialization to retrieve the name and metadata of the realm this client is
	// interacting with
	RealmProvider RealmEnvironmentProvider

	// BearerTokenProvider [required]
	//
	// This is used, where appropriate, to automatically decorate an outbound request with an Authorization header
	BearerTokenProvider BearerTokenProvider
}

// TokenAPIClient
type TokenAPIClient struct {
	*APIClient
	realmName string
	realmEnv  *RealmEnvironment
	btp       BearerTokenProvider
}

// AdminTokenAPIClient represents a TokenAPIClient that can be used to administer a realm in Keycloak
type AdminTokenAPIClient struct {
	*TokenAPIClient
}

func (c *APIClient) TokenAPIClient(ctx context.Context, conf *TokenAPIClientConfig) (*TokenAPIClient, error) {
	var (
		err error

		tc = new(TokenAPIClient)
	)
	if conf == nil {
		return nil, errors.New("conf cannot be nil")
	}
	if conf.RealmProvider == nil {
		return nil, errors.New("conf.RealmEnvironmentProvider cannot be nil")
	}
	if conf.BearerTokenProvider == nil {
		return nil, errors.New("conf.BearerTokenProvider cannot be nil")
	}
	tc.APIClient = c
	tc.btp = conf.BearerTokenProvider
	if tc.realmName, err = conf.RealmProvider.RealmName(); err != nil {
		return nil, fmt.Errorf("error fetching realm name: %w", err)
	}
	if tc.realmEnv, err = conf.RealmProvider.RealmEnvironment(ctx, c); err != nil {
		return nil, fmt.Errorf("error fetching realm %q environment: %w", tc.realmName, err)
	}
	return tc, nil
}

func (c *APIClient) AdminTokenAPIClient(ctx context.Context, conf *TokenAPIClientConfig) (*AdminTokenAPIClient, error) {
	var (
		tc  *TokenAPIClient
		err error
	)
	if tc, err = c.TokenAPIClient(ctx, conf); err != nil {
		return nil, err
	}
	return &AdminTokenAPIClient{tc}, nil
}

func NewTokenAPIClientWithProvider(ctx context.Context, conf *APIClientConfig, prov CombinedEnvironmentProvider) (*TokenAPIClient, error) {
	var (
		cl  *APIClient
		err error
	)
	if cl, err = NewAPIClient(conf, func(config *APIClientConfig) {
		config.AuthServerURLProvider = prov
	}); err != nil {
		return nil, err
	}
	return cl.TokenAPIClient(ctx, &TokenAPIClientConfig{prov, prov})
}

func NewAdminTokenAPIClientWithProvider(ctx context.Context, conf *APIClientConfig, prov CombinedEnvironmentProvider) (*AdminTokenAPIClient, error) {
	var (
		cl  *APIClient
		err error
	)
	if cl, err = NewAPIClient(conf, func(config *APIClientConfig) {
		config.AuthServerURLProvider = prov
	}); err != nil {
		return nil, err
	}
	return cl.AdminTokenAPIClient(ctx, &TokenAPIClientConfig{prov, prov})
}

// RealmName returns the realm this client instance is scoped to
func (tc *TokenAPIClient) RealmName() string {
	return tc.realmName
}

func (tc *TokenAPIClient) RealmEnvironment() *RealmEnvironment {
	return tc.realmEnv
}

func (tc *TokenAPIClient) realmsURL(bits ...string) string {
	return tc.APIClient.realmsURL(tc.realmName, bits...)
}

func (tc *TokenAPIClient) adminRealmsURL(bits ...string) string {
	return tc.APIClient.adminRealmsURL(tc.realmName, bits...)
}

func (tc *TokenAPIClient) callRealms(ctx context.Context, method, requestPath string, body interface{}, mutators ...RequestMutator) (*http.Response, error) {
	return tc.Call(ctx, method, tc.realmsURL(requestPath), body, mutators...)
}

func (tc *TokenAPIClient) callAdminRealms(ctx context.Context, method, requestPath string, body interface{}, mutators ...RequestMutator) (*http.Response, error) {
	return tc.Call(ctx, method, tc.adminRealmsURL(requestPath), body, mutators...)
}

func (tc *TokenAPIClient) RealmIssuerConfiguration(ctx context.Context, mutators ...RequestMutator) (*RealmIssuerConfiguration, error) {
	return tc.APIClient.RealmIssuerConfiguration(ctx, tc.realmName, mutators...)
}

func (tc *TokenAPIClient) TokensNotBeforeTime(ctx context.Context, mutators ...RequestMutator) (time.Time, error) {
	if conf, err := tc.RealmIssuerConfiguration(ctx, mutators...); err != nil {
		return time.Time{}, err
	} else {
		return time.Unix(int64(conf.TokensNotBefore)*int64(time.Second), 0), nil
	}
}

func (tc *TokenAPIClient) OpenIDConfiguration(ctx context.Context, mutators ...RequestMutator) (*OpenIDConfiguration, error) {
	return tc.APIClient.OpenIDConfiguration(ctx, tc.realmName, mutators...)
}

func (tc *TokenAPIClient) UMA2Configuration(ctx context.Context, mutators ...RequestMutator) (*UMA2Configuration, error) {
	return tc.APIClient.UMA2Configuration(ctx, tc.realmName, mutators...)
}

func (tc *TokenAPIClient) JSONWebKeys(ctx context.Context, mutators ...RequestMutator) (*JSONWebKeySet, error) {
	return tc.APIClient.JSONWebKeys(ctx, tc.realmEnv, mutators...)
}

func (tc *TokenAPIClient) IntrospectRequestingPartyToken(ctx context.Context, rawRPT string, mutators ...RequestMutator) (*TokenIntrospectionResults, error) {
	var (
		body    url.Values
		resp    *http.Response
		results *TokenIntrospectionResults
		err     error
	)
	body = make(url.Values)
	body.Add(paramTokenTypeHint, TokenTypeHintRequestingPartyToken)
	body.Add(paramTypeToken, rawRPT)
	resp, err = tc.APIClient.Call(
		ctx,
		http.MethodPost,
		tc.realmEnv.IntrospectionEndpoint(),
		strings.NewReader(body.Encode()),
		appendRequestMutators(mutators, HeaderMutator(httpHeaderContentType, httpHeaderValueFormURLEncoded, true))...,
	)
	results = new(TokenIntrospectionResults)
	if err = handleResponse(resp, http.StatusOK, results, err); err != nil {
		return nil, err
	}
	return results, nil
}

// ParseRequestToken attempts to extract the encoded bearer token from the provided request and parse it into a modeled
// access token type
func (tc *TokenAPIClient) ParseRequestToken(ctx context.Context, request *http.Request, claimsType jwt.Claims) (*jwt.Token, error) {
	if bt, ok := RequestBearerToken(request); ok {
		return tc.ParseToken(ctx, bt, claimsType)
	}
	return nil, errors.New("bearer token not found in request")
}

// ParseToken will attempt to parse and validate a raw token into a modeled type.  If this method does not return
// an error, you can safely assume the provided raw token is safe for use.
func (tc *TokenAPIClient) ParseToken(ctx context.Context, rawToken string, claimsType jwt.Claims) (*jwt.Token, error) {
	var (
		jwtToken *jwt.Token
		err      error
	)
	if claimsType == nil {
		claimsType = new(StandardClaims)
	}
	if jwtToken, err = jwt.ParseWithClaims(rawToken, claimsType, tc.keyFunc(ctx)); err != nil {
		return nil, fmt.Errorf("error parsing raw token into %T: %w", claimsType, err)
	}
	return jwtToken, nil
}

func (tc *TokenAPIClient) keyFunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		var (
			tp TokenParser
			ok bool
		)
		if tp, ok = tc.TokenParser(token.Method.Alg()); !ok {
			return nil, fmt.Errorf("no token parser registered to handle %q", token.Method.Alg())
		}
		return tp.Parse(ctx, tc, token)
	}
}

func (tc *TokenAPIClient) TokenProvider() BearerTokenProvider {
	return tc.btp
}

func (tc *TokenAPIClient) Call(ctx context.Context, method, requestPath string, body interface{}, mutators ...RequestMutator) (*http.Response, error) {
	var (
		token string
		err   error
	)
	if token, err = tc.btp.Current(); err != nil {
		if !IsTokenExpiredErr(err) {
			return nil, fmt.Errorf("error fetching bearer token: %w", err)
		}
		// attempt renew
		if rtp, ok := tc.btp.(RenewableBearerTokenProvider); !ok {
			return nil, fmt.Errorf("token is expired, but provided BearerTokenProvider %T does not implement the renewable interface: %w", tc.btp, err)
		} else if err = rtp.Renew(ctx, tc, false); err != nil {
			return nil, fmt.Errorf("error during token renew: %w", err)
		} else if token, err = tc.btp.Current(); err != nil {
			return nil, fmt.Errorf("error fetching bearer token after successful refresh: %w", err)
		}
	}
	mutators = appendRequestMutators(mutators, BearerTokenMutator(token))
	return tc.APIClient.Call(ctx, method, requestPath, body, mutators...)
}

// ClientEntitlement will attempt to call the pre-uma2 entitlement endpoint to return a Requesting Party Token
// containing details about what aspects of the provided clientID the token for this request has access to, if any.
// DEPRECATED: use the newer introspection workflow for  instances newer than 3.4
func (tc *TokenAPIClient) ClientEntitlement(ctx context.Context, clientID string, claimsType jwt.Claims, mutators ...RequestMutator) (*jwt.Token, error) {
	var (
		resp *http.Response
		err  error

		rptResp = new(struct {
			RPT string `json:"rpt"`
		})
	)
	resp, err = tc.Call(ctx, http.MethodGet, tc.realmsURL(kcPathPrefixEntitlement, clientID), nil, mutators...)
	if err = handleResponse(resp, http.StatusOK, rptResp, err); err != nil {
		return nil, err
	}
	return tc.ParseToken(ctx, rptResp.RPT, claimsType)
}

func (tc *TokenAPIClient) OpenIDConnectToken(ctx context.Context, req *OpenIDConnectTokenRequest, mutators ...RequestMutator) (*OpenIDConnectToken, error) {
	var (
		body  url.Values
		resp  *http.Response
		token *OpenIDConnectToken
		err   error
	)
	if body, err = query.Values(req); err != nil {
		return nil, fmt.Errorf("error encoding request: %w", err)
	}
	resp, err = tc.Call(
		ctx,
		http.MethodPost,
		tc.realmEnv.TokenEndpoint(),
		body,
		appendRequestMutators(mutators, HeaderMutator(httpHeaderContentType, httpHeaderValueFormURLEncoded, true))...,
	)
	token = new(OpenIDConnectToken)
	if err = handleResponse(resp, http.StatusOK, token, err); err != nil {
		return nil, err
	}
	return token, nil
}

// RequestingPartyToken is a convenience method that attempts to first retrieve an RPT via UMA2 and falling back to
// legacy Keycloak Entitlement api if uma2 support not detected.
func (tc *TokenAPIClient) RequestingPartyToken(ctx context.Context, aud string, claimsType jwt.Claims, mutators ...RequestMutator) (*jwt.Token, error) {
	if tc.RealmEnvironment().SupportsUMA2() {
		req := NewOpenIDConnectTokenRequest(GrantTypeUMA2Ticket)
		req.Audience = aud
		return tc.PermissionsService().RequestingPartyToken(ctx, req, claimsType, mutators...)
	}
	return tc.ClientEntitlement(ctx, aud, claimsType, mutators...)
}
