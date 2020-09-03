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
	"github.com/rs/zerolog"
)

const (
	// config defaults
	DefaultPathPrefix        = "auth"
	DefaultPublicKeyCacheTTL = 24 * time.Hour

	// grant type values
	GrantTypeCode              = "code"
	GrantTypeUMA2Ticket        = "urn:ietf:params:oauth:grant-type:uma-ticket"
	GrantTypeClientCredentials = "client_credentials"

	// token type hint values
	TokenTypeHintRequestingPartyToken = "requesting_party_token"

	// response modes
	ResponseModeDecision    = "decision"
	ResponseModePermissions = "permissions"

	// public key cache stuff
	pkKeyPrefix = "pk"
	pkKeyFormat = pkKeyPrefix + "\n%s\n%s\n%s"

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
	paramResponseMode  = "response_mode"
	paramTokenTypeHint = "token_type_hint"
	paramTypeToken     = "token"

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

	// TokenParsers [required]
	//
	// List of token parser implementations to support with this client.  These will be used for all realm clients
	// created by this client instance
	TokenParsers []TokenParser

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

func DefaultAPIClientConfig() *APIClientConfig {
	c := APIClientConfig{
		PathPrefix:     DefaultPathPrefix,
		IssuerProvider: defaultIssuerProvider(),
		TokenParsers:   []TokenParser{NewX509TokenParser(NewPublicKeyCache())},
		HTTPClient:     cleanhttp.DefaultClient(),
		Logger:         DefaultZerologLogger(),
		Debug:          new(DebugConfig),
	}
	return &c
}

type (
	apiCallFunc func(ctx context.Context, method, requestPath string, body interface{}, mutators ...RequestMutator) (*http.Response, error)

	apiClient struct {
		log zerolog.Logger

		issAddr    string
		pathPrefix string

		tokenParsers   map[string]TokenParser
		tokenParsersMu sync.RWMutex

		mr requestMutatorRunner

		hc *http.Client

		callFn apiCallFunc
	}

	// APIClient
	//
	// This is the base client for interacting with a Keycloak instance
	APIClient struct {
		*apiClient
	}
)

// NewAPIClient will attempt to construct and return a APIClient to you
func NewAPIClient(config *APIClientConfig, mutators ...ConfigMutator) (*APIClient, error) {
	var (
		cc  *APIClientConfig
		err error

		cl = new(APIClient)
	)

	cl.apiClient = new(apiClient)
	cl.apiClient.callFn = cl.Call

	cc = compileAPIClientConfig(config, mutators...)

	if cl.issAddr, err = cc.IssuerProvider.IssuerAddress(); err != nil {
		return nil, err
	}

	if len(cc.TokenParsers) == 0 {
		return nil, errors.New("must provide at least one token parser")
	}

	cl.pathPrefix = cc.PathPrefix
	cl.tokenParsers = make(map[string]TokenParser)
	cl.RegisterTokenParsers(cc.TokenParsers...)
	cl.hc = cc.HTTPClient
	cl.log = cc.Logger
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

func (c *apiClient) PathPrefix() string {
	return c.pathPrefix
}

// IssuerAddress will return the address of the issuer this client is targeting
func (c *apiClient) IssuerAddress() string {
	return c.issAddr
}

func (c *apiClient) TokenParser(alg string) (TokenParser, bool) {
	c.tokenParsersMu.RLock()
	defer c.tokenParsersMu.RUnlock()
	tp, ok := c.tokenParsers[alg]
	return tp, ok
}

func (c *apiClient) RegisterTokenParsers(tps ...TokenParser) {
	c.tokenParsersMu.Lock()
	defer c.tokenParsersMu.Unlock()
	for _, tp := range tps {
		for _, alg := range tp.SupportedAlgorithms() {
			c.tokenParsers[alg] = tp
		}
	}
}

func (c *apiClient) Do(ctx context.Context, req *APIRequest, mutators ...RequestMutator) (*http.Response, error) {
	var (
		httpRequest  *http.Request
		httpResponse *http.Response
		err          error
	)

	// apply any mutators
	if i, err := c.mr(req, mutators...); err != nil {
		return nil, fmt.Errorf("mutator %d returned error: %w", i, err)
	}

	c.log.Debug().Object("request", req).Int("mutators", len(mutators)).Msg("Preparing to execute new query...")

	// construct http request
	if httpRequest, err = req.ToHTTP(ctx, c.issAddr); err != nil {
		return nil, err
	}

	// execute
	httpResponse, err = c.hc.Do(httpRequest)
	return httpResponse, err
}

// Call is a helper method that
func (c *APIClient) Call(ctx context.Context, method, requestPath string, body interface{}, mutators ...RequestMutator) (*http.Response, error) {
	var (
		req *APIRequest
		err error
	)

	// ensure we've got an actual slice here
	if mutators == nil {
		mutators = make([]RequestMutator, 0)
	}

	req = NewAPIRequest(method, requestPath)
	if err = req.SetBody(body); err != nil {
		return nil, err
	}

	return c.Do(ctx, req, mutators...)
}

// RealmIssuerConfiguration returns metadata about the keycloak realm instance being connected to, such as the public
// key for token signing.
func (c *apiClient) RealmIssuerConfiguration(ctx context.Context, realmName string, mutators ...RequestMutator) (*RealmIssuerConfiguration, error) {
	var (
		resp *http.Response
		ic   *RealmIssuerConfiguration
		err  error
	)
	resp, err = c.callFn(ctx, http.MethodGet, c.realmsPath(realmName), nil, mutators...)
	ic = new(RealmIssuerConfiguration)
	if err = handleResponse(resp, http.StatusOK, ic, err); err != nil {
		return nil, err
	}
	return ic, nil
}

// OpenIDConfiguration returns well-known open-id configuration values for the provided realm
func (c *apiClient) OpenIDConfiguration(ctx context.Context, realmName string, mutators ...RequestMutator) (*OpenIDConfiguration, error) {
	var (
		resp *http.Response
		oidc *OpenIDConfiguration
		err  error
	)
	resp, err = c.callFn(ctx, http.MethodGet, c.realmsPath(realmName, kcPathOIDC), nil, mutators...)
	oidc = new(OpenIDConfiguration)
	if err = handleResponse(resp, http.StatusOK, oidc, err); err != nil {
		return nil, err
	}
	return oidc, nil
}

// UMA2Configuration returns well-known uma2 configuration values for the provided realm, assuming you are running
// keycloak > 3.4
func (c *apiClient) UMA2Configuration(ctx context.Context, realmName string, mutators ...RequestMutator) (*UMA2Configuration, error) {
	var (
		resp *http.Response
		uma2 *UMA2Configuration
		err  error
	)
	resp, err = c.callFn(ctx, http.MethodGet, c.realmsPath(realmName, kcPathUMA2C), nil, mutators...)
	uma2 = new(UMA2Configuration)
	if err = handleResponse(resp, http.StatusOK, uma2, err); err != nil {
		return nil, err
	}
	return uma2, nil
}

// basePath builds a request path under the configured prefix... path
func (c *apiClient) basePath(bits ...string) string {
	if len(bits) == 0 {
		return c.pathPrefix
	}
	return fmt.Sprintf(apiPathFormat, c.pathPrefix, path.Join(bits...))
}

// realmsPath builds a request path under the /realms/{realm}/... path
func (c *apiClient) realmsPath(realm string, bits ...string) string {
	return fmt.Sprintf(kcURLPathRealmsFormat, c.pathPrefix, realm, path.Join(bits...))
}

// adminRealmsPath builds a request path under the /admin/realms/{realm}/... path
func (c *apiClient) adminRealmsPath(realm string, bits ...string) (string, error) {
	return fmt.Sprintf(kcURLPathAdminRealmsFormat, c.pathPrefix, realm, path.Join(bits...)), nil
}

type RealmEnvConfig struct {
	oidc  *OpenIDConfiguration
	uma2c *UMA2Configuration
}

// common configuration entries

func (e *RealmEnvConfig) SupportsUMA2() bool {
	return e.uma2c != nil
}

func (e *RealmEnvConfig) IssuerAddress() string {
	if e.uma2c != nil {
		return e.uma2c.Issuer
	} else {
		return e.oidc.Issuer
	}
}

func (e *RealmEnvConfig) AuthorizationEndpoint() string {
	if e.uma2c != nil {
		return e.uma2c.AuthorizationEndpoint
	} else {
		return e.oidc.AuthorizationEndpoint
	}
}

func (e *RealmEnvConfig) TokenEndpoint() string {
	if e.uma2c != nil {
		return e.uma2c.TokenEndpoint
	} else {
		return e.oidc.TokenEndpoint
	}
}

func (e *RealmEnvConfig) IntrospectionEndpoint() string {
	if e.uma2c != nil {
		return e.uma2c.IntrospectionEndpoint
	} else {
		return e.oidc.IntrospectionEndpoint
	}
}

func (e *RealmEnvConfig) EndSessionEndpoint() string {
	if e.uma2c != nil {
		return e.uma2c.EndSessionEndpoint
	} else {
		return e.oidc.EndSessionEndpoint
	}
}

func (e *RealmEnvConfig) JSONWebKeysEndpoint() string {
	if e.uma2c != nil {
		return e.uma2c.JwksURI
	} else {
		return e.oidc.JSONWebKeysEndpoint
	}
}

func (e *RealmEnvConfig) RegistrationEndpoint() string {
	if e.uma2c != nil {
		return e.uma2c.RegistrationEndpoint
	} else {
		return e.oidc.RegistrationEndpoint
	}
}

func (e *RealmEnvConfig) GrantTypesSupported() []string {
	if e.uma2c != nil {
		return copyStrs(e.uma2c.GrantTypesSupported)
	} else {
		return copyStrs(e.oidc.GrantTypesSupported)
	}
}

func (e *RealmEnvConfig) ResponseTypesSupported() []string {
	if e.uma2c != nil {
		return copyStrs(e.uma2c.ResponseTypesSupported)
	} else {
		return copyStrs(e.oidc.ResponseTypesSupported)
	}
}

func (e *RealmEnvConfig) ResponseModesSupported() []string {
	if e.uma2c != nil {
		return copyStrs(e.uma2c.ResponseModesSupported)
	} else {
		return copyStrs(e.oidc.ResponseModesSupported)
	}
}

func (e *RealmEnvConfig) TokenEndpointAuthMethodsSupported() []string {
	if e.uma2c != nil {
		return copyStrs(e.uma2c.TokenEndpointAuthMethodsSupported)
	} else {
		return copyStrs(e.oidc.TokenEndpointAuthMethodsSupported)
	}
}

func (e *RealmEnvConfig) TokenEndpointAuthSigningAlgValuesSupported() []string {
	if e.uma2c != nil {
		return copyStrs(e.uma2c.TokenEndpointAuthSigningAlgValuesSupported)
	} else {
		return copyStrs(e.oidc.TokenEndpointAuthSigningAlgValuesSupported)
	}
}

func (e *RealmEnvConfig) ScopesSupported() []string {
	if e.uma2c != nil {
		return copyStrs(e.uma2c.ScopesSupported)
	} else {
		return copyStrs(e.oidc.ScopesSupported)
	}
}

// oidc configuration entries

func (e *RealmEnvConfig) UserInfoEndpoint() string {
	return e.oidc.UserInfoEndpoint
}

func (e *RealmEnvConfig) CheckSessionIframe() string {
	return e.oidc.CheckSessionIframe
}

func (e *RealmEnvConfig) SubjectTypesSupported() []string {
	return copyStrs(e.oidc.SubjectTypesSupported)
}

func (e *RealmEnvConfig) IDTokenSigningAlgValuesSupported() []string {
	return copyStrs(e.oidc.IDTokenSigningAlgValuesSupported)
}

func (e *RealmEnvConfig) IDTokenEncryptionAlgValuesSupported() []string {
	return copyStrs(e.oidc.IDTokenEncryptionAlgValuesSupported)
}

func (e *RealmEnvConfig) IDTokenEncryptionEncValuesSupported() []string {
	return copyStrs(e.oidc.IDTokenEncryptionEncValuesSupported)
}

func (e *RealmEnvConfig) UserInfoSigningAlgValuesSupported() []string {
	return copyStrs(e.oidc.UserinfoSigningAlgValuesSupported)
}

func (e *RealmEnvConfig) RequestObjectSigningAlgValuesSupported() []string {
	return copyStrs(e.oidc.RequestObjectSigningAlgValuesSupported)
}

func (e *RealmEnvConfig) ClaimsSupported() []string {
	return copyStrs(e.oidc.ClaimsSupported)
}

func (e *RealmEnvConfig) ClaimTypesSupported() []string {
	return copyStrs(e.oidc.ClaimTypesSupported)
}

func (e *RealmEnvConfig) ClaimsParameterSupported() bool {
	return e.oidc.ClaimsParameterSupported
}

func (e *RealmEnvConfig) RequestParameterSupported() bool {
	return e.oidc.RequestParameterSupported
}

func (e *RealmEnvConfig) RequestURIParameterSupported() bool {
	return e.oidc.RequestURIParameterSupported
}

func (e *RealmEnvConfig) CodeChallengeMethodsSupported() []string {
	return copyStrs(e.oidc.CodeChallengeMethodsSupported)
}

func (e *RealmEnvConfig) TLSClientCertificateBoundAccessTokens() bool {
	return e.oidc.TLSClientCertificateBoundAccessToken
}

// uma2 configuration entries

func (e *RealmEnvConfig) ResourceRegistrationEndpoint() (string, bool) {
	if e.uma2c != nil {
		return e.uma2c.ResourceRegistrationEndpoint, true
	}
	return "", false
}

func (e *RealmEnvConfig) PermissionEndpoint() (string, bool) {
	if e.uma2c != nil {
		return e.uma2c.PermissionEndpoint, true
	}
	return "", false
}

func (e *RealmEnvConfig) PolicyEndpoint() (string, bool) {
	if e.uma2c != nil {
		return e.uma2c.PermissionEndpoint, true
	}
	return "", false
}

type (
	realmAPICallFunc func(ctx context.Context, tp TokenProvider, method, requestPath string, body interface{}, mutators ...RequestMutator) (*http.Response, error)

	realmAPIKeyFunc func(context.Context) jwt.Keyfunc

	realmAPIClient struct {
		*apiClient
		log zerolog.Logger
		rn  string
		env *RealmEnvConfig

		callFn realmAPICallFunc
		keyFn  realmAPIKeyFunc
	}

	// RealmAPIClient is intended for use against a singular realm within your Keycloak instance. All internal calls will
	// be scoped to the provided realm
	RealmAPIClient struct {
		*realmAPIClient
	}
)

func (c *APIClient) RealmAPIClient(ctx context.Context, realmName string, mutators ...RequestMutator) (*RealmAPIClient, error) {
	var (
		err error

		rc = new(RealmAPIClient)
	)
	rc.realmAPIClient = new(realmAPIClient)
	rc.apiClient = c.apiClient
	rc.callFn = rc.Call
	rc.keyFn = rc.keyFunc

	rc.log = rc.apiClient.log.With().Str("keycloak_realm", realmName).Logger()
	rc.rn = realmName
	rc.env = new(RealmEnvConfig)

	// attempt to build env details
	if rc.env.oidc, err = c.OpenIDConfiguration(ctx, realmName, mutators...); err != nil {
		return nil, fmt.Errorf("error fetching OpenID configuration: %w", err)
	}
	// this is allowed to fail, as uma2 support in keycloak is "new"
	if rc.env.uma2c, err = c.UMA2Configuration(ctx, realmName, mutators...); err != nil {
		c.log.Error().Err(err).Msg("Error fetching UMA2 configuration")
	}

	return rc, nil
}

// RealmName returns the realm this client instance is scoped to
func (rc *realmAPIClient) RealmName() string {
	return rc.rn
}

func (rc *realmAPIClient) Environment() *RealmEnvConfig {
	return rc.env
}

func (rc *realmAPIClient) realmsPath(bits ...string) string {
	return rc.apiClient.realmsPath(rc.rn, bits...)
}

func (rc *RealmAPIClient) Call(ctx context.Context, tp TokenProvider, method, requestPath string, body interface{}, mutators ...RequestMutator) (*http.Response, error) {
	if tp != nil {
		var (
			token string
			err   error
		)
		if token, err = tp.BearerToken(); err != nil {
			rc.log.Error().Err(err).Msg("Error fetching bearer token for request")
			if !IsTokenExpiredErr(err) {
				return nil, err
			}
			// check for a renewable provider
			if rtp, ok := tp.(RenewableTokenProvider); ok {
				// attempt renewal
				if err = rtp.Renew(ctx, rc, false); err == nil {
					// attempt re-fetch
					token, err = tp.BearerToken()
				}
			}
			// if either the renew or subsequent fetch fails, immediately fail.
			if err != nil {
				rc.log.Error().Err(err).Msg("Token fetch errored during renew attempt")
				return nil, err
			}
			rc.log.Debug().Msg("Token successfully renewed")
		}
		if mutators == nil {
			mutators = make([]RequestMutator, 0)
		}
		mutators = append(mutators, BearerTokenMutator(token))
	}
	return rc.apiClient.callFn(ctx, method, requestPath, body, mutators...)
}

func (rc *realmAPIClient) callRealms(ctx context.Context, tp TokenProvider, method, requestPath string, body interface{}, mutators ...RequestMutator) (*http.Response, error) {
	return rc.callFn(ctx, tp, method, rc.realmsPath(requestPath), body, mutators...)
}

func (rc *realmAPIClient) RealmIssuerConfiguration(ctx context.Context, mutators ...RequestMutator) (*RealmIssuerConfiguration, error) {
	return rc.apiClient.RealmIssuerConfiguration(ctx, rc.rn, mutators...)
}

func (rc *realmAPIClient) EncodedPublicKey(ctx context.Context, mutators ...RequestMutator) (string, error) {
	if conf, err := rc.RealmIssuerConfiguration(ctx, mutators...); err != nil {
		return "", err
	} else {
		return conf.PublicKey, nil
	}
}

func (rc *realmAPIClient) TokenServiceURL(ctx context.Context, mutators ...RequestMutator) (string, error) {
	if conf, err := rc.RealmIssuerConfiguration(ctx, mutators...); err != nil {
		return "", err
	} else {
		return conf.TokenService, nil
	}
}

func (rc *realmAPIClient) AccountServiceURL(ctx context.Context, mutators ...RequestMutator) (string, error) {
	if conf, err := rc.RealmIssuerConfiguration(ctx, mutators...); err != nil {
		return "", err
	} else {
		return conf.AccountService, nil
	}
}

func (rc *realmAPIClient) TokensNotBeforeTime(ctx context.Context, mutators ...RequestMutator) (time.Time, error) {
	if conf, err := rc.RealmIssuerConfiguration(ctx, mutators...); err != nil {
		return time.Time{}, err
	} else {
		return time.Unix(int64(conf.TokensNotBefore)*int64(time.Second), 0), nil
	}
}

func (rc *realmAPIClient) OpenIDConfiguration(ctx context.Context, mutators ...RequestMutator) (*OpenIDConfiguration, error) {
	return rc.apiClient.OpenIDConfiguration(ctx, rc.rn, mutators...)
}

func (rc *realmAPIClient) UMA2Configuration(ctx context.Context, mutators ...RequestMutator) (*UMA2Configuration, error) {
	return rc.apiClient.UMA2Configuration(ctx, rc.rn, mutators...)
}

func (rc *realmAPIClient) JSONWebKeys(ctx context.Context, mutators ...RequestMutator) (*JSONWebKeySet, error) {
	var (
		resp *http.Response
		jwks *JSONWebKeySet
		err  error
	)
	resp, err = rc.callFn(ctx, nil, http.MethodGet, rc.env.JSONWebKeysEndpoint(), nil, mutators...)
	jwks = new(JSONWebKeySet)
	if err = handleResponse(resp, http.StatusOK, jwks, err); err != nil {
		return nil, err
	}
	return jwks, nil
}

func (rc *realmAPIClient) OpenIDConnectToken(ctx context.Context, tp TokenProvider, req *OpenIDConnectTokenRequest, mutators ...RequestMutator) (*OpenIDConnectToken, error) {
	var (
		body  url.Values
		resp  *http.Response
		token *OpenIDConnectToken
		err   error
	)
	if body, err = query.Values(req); err != nil {
		return nil, fmt.Errorf("error encoding request: %w", err)
	}
	resp, err = rc.callFn(
		ctx,
		tp,
		http.MethodPost,
		rc.env.TokenEndpoint(),
		strings.NewReader(body.Encode()),
		addMutators(mutators, HeaderMutator(httpHeaderContentType, httpHeaderValueFormURLEncoded, true))...,
	)
	token = new(OpenIDConnectToken)
	if err = handleResponse(resp, http.StatusOK, token, err); err != nil {
		return nil, err
	}
	return token, nil
}

func (rc *realmAPIClient) IntrospectRequestingPartyToken(ctx context.Context, rawRPT string) (*TokenIntrospectionResults, error) {
	var (
		body    url.Values
		resp    *http.Response
		results *TokenIntrospectionResults
		err     error
	)
	body = make(url.Values)
	body.Add(paramTokenTypeHint, TokenTypeHintRequestingPartyToken)
	body.Add(paramTypeToken, rawRPT)
	resp, err = rc.callFn(
		ctx,
		nil,
		http.MethodPost,
		rc.env.IntrospectionEndpoint(),
		strings.NewReader(body.Encode()),
		HeaderMutator(httpHeaderContentType, httpHeaderValueFormURLEncoded, true))
	results = new(TokenIntrospectionResults)
	if err = handleResponse(resp, http.StatusOK, results, err); err != nil {
		return nil, err
	}
	return results, nil
}

// RequestAccessToken attempts to extract the encoded bearer token from the provided request and parse it into a modeled
// access token type
func (rc *realmAPIClient) RequestAccessToken(ctx context.Context, request *http.Request, claimsType jwt.Claims) (*jwt.Token, error) {
	if bt, ok := RequestBearerToken(request); ok {
		return rc.ParseToken(ctx, bt, claimsType)
	}
	return nil, errors.New("bearer token not found in request")
}

// ParseToken will attempt to parse and validate a raw token into a modeled type.  If this method does not return
// an error, you can safely assume the provided raw token is safe for use.
func (rc *realmAPIClient) ParseToken(ctx context.Context, rawToken string, claimsType jwt.Claims) (*jwt.Token, error) {
	var (
		jwtToken *jwt.Token
		err      error
	)
	if claimsType == nil {
		claimsType = new(StandardClaims)
	}
	if jwtToken, err = jwt.ParseWithClaims(rawToken, claimsType, rc.keyFn(ctx)); err != nil {
		return nil, fmt.Errorf("error parsing raw token into %T: %w", claimsType, err)
	}
	return jwtToken, nil
}

func (rc *RealmAPIClient) keyFunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		var (
			tp TokenParser
			ok bool
		)
		if tp, ok = rc.apiClient.TokenParser(token.Method.Alg()); !ok {
			return nil, fmt.Errorf("no token parser registered to handle %q", token.Method.Alg())
		}
		return tp.Parse(ctx, rc, token)
	}
}

type (
	tokenAPIClient struct {
		*realmAPIClient
		tp     TokenProvider
		callFn apiCallFunc
	}

	// TokenAPIClient
	//
	// This is an extension of the RealmAPIClient that is further scoped by a single TokenProvider, where all requests will
	// have the provided token sent in the Authorization header.
	TokenAPIClient struct {
		*tokenAPIClient
	}
)

func (rc *RealmAPIClient) TokenAPIClient(tp TokenProvider) (*TokenAPIClient, error) {
	if tp == nil {
		return nil, errors.New("token provider cannot be nil")
	}
	tc := new(TokenAPIClient)
	tc.tokenAPIClient = new(tokenAPIClient)
	tc.realmAPIClient = rc.realmAPIClient
	tc.callFn = tc.Call
	tc.tp = tp
	return tc, nil
}

func (c *APIClient) TokenAPIClient(ctx context.Context, realmName string, tp TokenProvider, mutators ...RequestMutator) (*TokenAPIClient, error) {
	var (
		rc  *RealmAPIClient
		err error
	)
	if rc, err = c.RealmAPIClient(ctx, realmName, mutators...); err != nil {
		return nil, err
	}
	return rc.TokenAPIClient(tp)
}

func (c *APIClient) TokenAPIClientWithProvider(ctx context.Context, tp FullStateTokenProvider, mutators ...RequestMutator) (*TokenAPIClient, error) {
	var (
		rc  *RealmAPIClient
		err error
	)
	if rc, err = c.RealmAPIClient(ctx, tp.TargetRealm(), mutators...); err != nil {
		return nil, err
	}
	return rc.TokenAPIClient(tp)
}

func NewTokenAPIClientWithProvider(ctx context.Context, conf *APIClientConfig, tp FullStateTokenProvider, mutators ...RequestMutator) (*TokenAPIClient, error) {
	var (
		cl  *APIClient
		err error
	)

	if cl, err = NewAPIClient(conf, func(config *APIClientConfig) {
		config.IssuerProvider = tp
	}); err != nil {
		return nil, err
	}
	return cl.TokenAPIClientWithProvider(ctx, tp, mutators...)
}

func NewTokenAPIClientForConfidentialClient(ctx context.Context, conf *APIClientConfig, tpConf *ConfidentialClientTokenProviderConfig, mutators ...RequestMutator) (*TokenAPIClient, error) {
	var (
		tp  *ConfidentialClientTokenProvider
		err error
	)
	if tp, err = NewConfidentialClientTokenProvider(tpConf); err != nil {
		return nil, err
	}
	return NewTokenAPIClientWithProvider(ctx, conf, tp, mutators...)
}

func (tc *tokenAPIClient) TokenProvider() TokenProvider {
	return tc.tp
}

func (tc *TokenAPIClient) Call(ctx context.Context, method, requestPath string, body interface{}, mutators ...RequestMutator) (*http.Response, error) {
	return tc.realmAPIClient.callFn(ctx, tc.tp, method, requestPath, body, mutators...)
}

func (tc *tokenAPIClient) callRealms(ctx context.Context, method, requestPath string, body interface{}, mutators ...RequestMutator) (*http.Response, error) {
	return tc.callFn(ctx, method, tc.realmsPath(requestPath), body, mutators...)
}

// ClientEntitlement will attempt to call the pre-uma2 entitlement endpoint to return a Requesting Party Token
// containing details about what aspects of the provided clientID the token for this request has access to, if any.
// DEPRECATED: use the newer introspection workflow for  instances newer than 3.4
func (tc *tokenAPIClient) ClientEntitlement(ctx context.Context, clientID string, claimsType jwt.Claims, mutators ...RequestMutator) (*jwt.Token, error) {
	var (
		resp *http.Response
		err  error

		rptResp = new(struct {
			RPT string `json:"rpt"`
		})
	)
	resp, err = tc.callFn(ctx, http.MethodGet, tc.realmsPath(kcPathPrefixEntitlement, clientID), nil, mutators...)
	if err = handleResponse(resp, http.StatusOK, rptResp, err); err != nil {
		return nil, err
	}
	return tc.ParseToken(ctx, rptResp.RPT, claimsType)
}

func (tc *tokenAPIClient) OpenIDConnectToken(ctx context.Context, req *OpenIDConnectTokenRequest, mutators ...RequestMutator) (*OpenIDConnectToken, error) {
	var (
		body  url.Values
		resp  *http.Response
		token *OpenIDConnectToken
		err   error
	)
	if body, err = query.Values(req); err != nil {
		return nil, fmt.Errorf("error encoding request: %w", err)
	}
	resp, err = tc.callFn(
		ctx,
		http.MethodPost,
		tc.env.TokenEndpoint(),
		body,
		addMutators(mutators, HeaderMutator(httpHeaderContentType, httpHeaderValueFormURLEncoded, true))...,
	)
	token = new(OpenIDConnectToken)
	if err = handleResponse(resp, http.StatusOK, token, err); err != nil {
		return nil, err
	}
	return token, nil
}

// RequestingPartyToken is a convenience method that attempts to first retrieve an RPT via UMA2 and falling back to
// legacy Keycloak Entitlement api if uma2 support not detected.
func (tc *tokenAPIClient) RequestingPartyToken(ctx context.Context, aud string, claimsType jwt.Claims, mutators ...RequestMutator) (*jwt.Token, error) {
	if tc.Environment().SupportsUMA2() {
		req := NewOpenIDConnectTokenRequest(GrantTypeUMA2Ticket)
		req.Audience = aud
		return tc.PermissionsService().RequestingPartyToken(ctx, req, claimsType, mutators...)
	}
	return tc.ClientEntitlement(ctx, aud, claimsType, mutators...)
}
