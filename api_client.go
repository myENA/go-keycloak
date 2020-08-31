package keycloak

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"time"

	"github.com/dgrijalva/jwt-go"
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
	pkKeyFormat = "%s\n%s"

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

	// RealmConfigProvider [optional]
	//
	// The RealmConfigProvider will be called on a per-request basis, depending on if that request needs to have the realm
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
	// See "provider_realm_config.go" for implementation details.
	RealmConfigProvider RealmConfigurationProvider

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
		PathPrefix:          DefaultPathPrefix,
		IssuerProvider:      defaultIssuerProvider(),
		RealmConfigProvider: NewGlobalRealmConfigProvider(),
		HTTPClient:          cleanhttp.DefaultClient(),
		Logger:              DefaultZerologLogger(),
		Debug:               new(DebugConfig),
	}
	return &c
}

// APIClient
//
// The APIClient is the root of the entire package.
type APIClient struct {
	log zerolog.Logger

	issAddr    string
	pathPrefix string

	realmConfigProvider RealmConfigurationProvider

	mr requestMutatorRunner

	hc *http.Client
}

// NewAPIClient will attempt to construct and return a APIClient to you
func NewAPIClient(config *APIClientConfig, mutators ...ConfigMutator) (*APIClient, error) {
	var (
		cc  *APIClientConfig
		err error

		cl = new(APIClient)
	)

	cc = compileBaseConfig(config, mutators...)

	if cl.issAddr, err = cc.IssuerProvider.IssuerAddress(); err != nil {
		return nil, err
	}

	cl.realmConfigProvider = cc.RealmConfigProvider
	cl.pathPrefix = cc.PathPrefix
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

func (c *APIClient) PathPrefix() string {
	return c.pathPrefix
}

// IssuerAddress will return the address of the issuer this client is targeting
func (c *APIClient) IssuerAddress() string {
	return c.issAddr
}

func (c *APIClient) RealmConfigProvider() RealmConfigurationProvider {
	return c.realmConfigProvider
}

// RealmIssuerConfiguration returns metadata about the keycloak realm instance being connected to, such as the public
// key for token signing.
func (c *APIClient) RealmIssuerConfiguration(ctx context.Context, name string, mutators ...RequestMutator) (RealmIssuerConfiguration, error) {
	var (
		resp *http.Response
		ic   *RealmIssuerConfiguration
		err  error
	)
	resp, err = c.Call(ctx, http.MethodGet, c.realmsPath(name), nil, mutators...)
	ic = new(RealmIssuerConfiguration)
	if err = handleResponse(resp, http.StatusOK, &ic, err); err != nil {
		return *ic, err
	}
	return *ic, nil
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
	if httpRequest, err = req.ToHTTP(ctx, c.issAddr); err != nil {
		return nil, err
	}

	c.log.Debug().
		Str("request-method", httpRequest.Method).
		Str("request-url", httpRequest.URL.String()).
		Str("request-body-type", req.BodyType()).
		Int("request-mutators", len(mutators)).
		Msg("Preparing to execute new request...")

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

// basePath builds a request path under the configured prefix... path
func (c *APIClient) basePath(bits ...string) string {
	if len(bits) == 0 {
		return c.pathPrefix
	}
	return fmt.Sprintf(apiPathFormat, c.pathPrefix, path.Join(bits...))
}

// realmsPath builds a request path under the /realms/{realm}/... path
func (c *APIClient) realmsPath(realm string, bits ...string) string {
	return fmt.Sprintf(kcURLPathRealmsFormat, c.pathPrefix, realm, path.Join(bits...))
}

// adminRealmsPath builds a request path under the /admin/realms/{realm}/... path
func (c *APIClient) adminRealmsPath(realm string, bits ...string) (string, error) {
	return fmt.Sprintf(kcURLPathAdminRealmsFormat, c.pathPrefix, realm, path.Join(bits...)), nil
}

type RealmAPIClientConfig struct {
	// RealmName [required]
	//
	// This is the name of the realm the client will be scoped too
	RealmName string

	// TokenProvider [required]
	//
	// See "token_provider.go" for implementation details.  If you construct a config using DefaultAPIClientConfig(),
	// you will be expected to provide a context with a token already defined with each request
	TokenProvider TokenProvider

	// TokenParser [required]
	//
	// The TokenParser will be called any time the client needs a realm's public key.  This is primarily used to
	// validate access and bearer tokens
	TokenParser TokenParser
}

type RealmAPIClient struct {
	*APIClient

	tokenProvider TokenProvider
	tokenParser   TokenParser

	realmName string
}

func (c *APIClient) RealmAPIClient(ctx context.Context, conf *RealmAPIClientConfig) (*RealmAPIClient, error) {
	rc := new(RealmAPIClient)

	if conf == nil {
		return nil, errors.New("config cannot be nil")
	}
	if conf.RealmName == "" {
		return nil, errors.New("realm name cannot be empty")
	}
	if conf.TokenProvider == nil {
		return nil, errors.New("token provide cannot be nil")
	}
	if conf.TokenParser == nil {
		return nil, errors.New("token parser cannot be nil")
	}

	rc.APIClient = c
	rc.realmName = conf.RealmName
	rc.tokenProvider = conf.TokenProvider
	rc.tokenParser = conf.TokenParser

	return rc, nil
}

// RealmName returns the realm this client instance is scoped to
func (rc *RealmAPIClient) RealmName() string {
	return rc.realmName
}

// TokenProvider will return the TokenProvider defined at client construction
func (rc *RealmAPIClient) TokenProvider() TokenProvider {
	return rc.tokenProvider
}

// TokenParser will return the token parser defined at client construction
func (rc *RealmAPIClient) TokenParser() TokenParser {
	return rc.tokenParser
}

// RealmIssuerConfiguration will either return the current cached version of this client's realm config or attempt to
// refresh it should no cache version be found.
func (rc *RealmAPIClient) RealmIssuerConfiguration(ctx context.Context) (RealmIssuerConfiguration, error) {
	return rc.RealmConfigProvider().RealmConfiguration(ctx, rc.APIClient, rc.realmName)
}

func (rc *RealmAPIClient) EncodedPublicKey(ctx context.Context) (string, error) {
	if conf, err := rc.RealmIssuerConfiguration(ctx); err != nil {
		return "", err
	} else {
		return conf.PublicKey, nil
	}
}

func (rc *RealmAPIClient) TokenServiceURL(ctx context.Context) (string, error) {
	if conf, err := rc.RealmIssuerConfiguration(ctx); err != nil {
		return "", err
	} else {
		return conf.TokenService, nil
	}
}

func (rc *RealmAPIClient) AccountServiceURL(ctx context.Context) (string, error) {
	if conf, err := rc.RealmIssuerConfiguration(ctx); err != nil {
		return "", err
	} else {
		return conf.AccountService, nil
	}
}

func (rc *RealmAPIClient) TokensNotBeforeTime(ctx context.Context) (time.Time, error) {
	if conf, err := rc.RealmIssuerConfiguration(ctx); err != nil {
		return time.Time{}, err
	} else {
		return time.Unix(int64(conf.TokensNotBefore)*int64(time.Second), 0), nil
	}
}

// RequestAccessToken attempts to extract the encoded bearer token from the provided request and parse it into a modeled
// access token type
func (rc *RealmAPIClient) RequestAccessToken(ctx context.Context, request *http.Request, claimsType jwt.Claims) (*jwt.Token, error) {
	if bt, ok := RequestBearerToken(request); ok {
		return rc.ParseToken(ctx, bt, claimsType)
	}
	return nil, errors.New("bearer token not found in request")
}

// ParseToken will attempt to parse and validate a raw token into a modeled type.  If this method does not return
// an error, you can safely assume the provided raw token is safe for use.
func (rc *RealmAPIClient) ParseToken(ctx context.Context, rawToken string, claimsType jwt.Claims) (*jwt.Token, error) {
	var (
		jwtToken *jwt.Token
		err      error
	)
	if claimsType == nil {
		claimsType = new(StandardClaims)
	}
	if jwtToken, err = jwt.ParseWithClaims(rawToken, claimsType, rc.keyFunc(ctx)); err != nil {
		return nil, fmt.Errorf("error parsing raw token into %T: %w", claimsType, err)
	}
	return jwtToken, nil
}

func (rc *RealmAPIClient) keyFunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		if conf, err := rc.RealmIssuerConfiguration(ctx); err != nil {
			return nil, err
		} else {
			return rc.TokenParser().Parse(conf, token)
		}
	}
}
