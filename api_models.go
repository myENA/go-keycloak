package keycloak

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

type KeyValueMap map[string]string
type KeyValuesMap map[string][]string

type MicrosecondTime time.Time

func (t *MicrosecondTime) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	i, err := strconv.Atoi(string(b))
	if err != nil {
		return fmt.Errorf("error converting %q to int: %w", string(b), err)
	}
	*t = MicrosecondTime(time.Unix(0, int64(i)*int64(time.Microsecond)))
	return nil
}

func (t *MicrosecondTime) MarshalJSON() ([]byte, error) {
	if t == nil {
		return nil, nil
	}
	if time.Time(*t).IsZero() {
		return []byte("0"), nil
	}
	return []byte(strconv.FormatInt(time.Time(*t).UnixNano()/int64(time.Microsecond), 10)), nil
}

type PolicyTime time.Time

const PolicyTimeFormat = "2006-01-02 15:04:05"

func (t *PolicyTime) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	tmp, err := time.Parse(PolicyTimeFormat, string(b))
	if err != nil {
		return err
	}
	*t = PolicyTime(tmp)
	return nil
}

func (t PolicyTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(t).Format(PolicyTimeFormat))
}

type AdminCreateResponse struct {
	ID string `json:"_id"`
}

type ClientProtocolMapperConfig struct {
	AccessTokenClaim   string `json:"access.token.claim"`
	ClaimName          string `json:"claim.name"`
	IDTokenClaim       string `json:"id.token.claim"`
	JSONTypeLabel      string `json:"jsonType.label"`
	UserAttribute      string `json:"user.attribute"`
	UserInfoTokenClaim string `json:"userinfo.token.claim"`
}

type ClientProtocolMapper struct {
	Config          ClientProtocolMapperConfig `json:"config"`
	ConsentRequired bool                       `json:"consentRequired"`
	ConsentText     string                     `json:"consentText"`
	ID              string                     `json:"id"`
	Name            string                     `json:"name"`
	Protocol        string                     `json:"protocol"`
	ProtocolMapper  string                     `json:"protocolMapper"`
}

type ClientAccess struct {
	View      bool `json:"view,omitempty"`
	Configure bool `json:"configure,omitempty"`
	Manage    bool `json:"manage,omitempty"`
}

type Client struct {
	Access                       ClientAccess           `json:"access"`
	AdminURL                     string                 `json:"adminUrl"`
	Attributes                   KeyValueMap            `json:"attributes"`
	AuthorizationServicesEnabled bool                   `json:"authorizationServicesEnabled"`
	BearerOnly                   bool                   `json:"bearerOnly"`
	ClientAuthenticatorType      string                 `json:"clientAuthenticatorType"`
	ClientID                     string                 `json:"clientId"`
	ConsentRequired              bool                   `json:"consentRequired"`
	Description                  string                 `json:"description"`
	DirectAccessGrantsEnabled    bool                   `json:"directAccessGrantsEnabled"`
	Enabled                      bool                   `json:"enabled"`
	FrontChannelLogout           bool                   `json:"frontchannelLogout"`
	FullScopeAllowed             bool                   `json:"fullScopeAllowed"`
	ID                           string                 `json:"id"`
	ImplicitFlowEnabled          bool                   `json:"implicitFlowEnabled"`
	Name                         string                 `json:"name"`
	NodeReRegistrationTimeout    int                    `json:"nodeReRegistrationTimeout"`
	NotBefore                    int                    `json:"notBefore"`
	Protocol                     string                 `json:"protocol"`
	ProtocolMappers              []ClientProtocolMapper `json:"protocolMappers"`
	PublicClient                 bool                   `json:"publicClient"`
	RedirectURIs                 []string               `json:"redirectUris"`
	RootURL                      string                 `json:"rootUrl"`
	ServiceAccountsEnabled       bool                   `json:"serviceAccountsEnabled"`
	StandardFlowEnabled          bool                   `json:"standardFlowEnabled"`
	SurrogateAuthRequired        bool                   `json:"surrogateAuthRequired"`
	WebOrigins                   []string               `json:"webOrigins"`

	// todo: this fields cause 3.4 to fail spectacularly
	//AlwaysDisplayInConsole       bool                   `json:"alwaysDisplayInConsole,omitempty"`
	//DefaultClientScopes []string `json:"defaultClientScopes"`
	//OptionalClientScopes         []string               `json:"optionalClientScopes"`
	//AuthenticationFlowBindings   interface{}            `json:"authenticationFlowBindings"`
}

type ClientCreateRequest struct {
	ClientID     string   `json:"clientId"`
	Enabled      bool     `json:"enabled"`
	Protocol     string   `json:"protocol"`
	RedirectUris []string `json:"redirectUris"`
	RootURL      string   `json:"rootURL"`
}

type Clients []*Client

type OpenIDConfiguration struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint"`
	UserInfoEndpoint                           string   `json:"userinfo_endpoint"`
	EndSessionEndpoint                         string   `json:"end_session_endpoint"`
	JSONWebKeysEndpoint                        string   `json:"jwks_uri"`
	CheckSessionIframe                         string   `json:"check_session_iframe"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	IDTokenEncryptionAlgValuesSupported        []string `json:"id_token_encryption_alg_values_supported"`
	IDTokenEncryptionEncValuesSupported        []string `json:"id_token_encryption_enc_values_supported"`
	UserinfoSigningAlgValuesSupported          []string `json:"userinfo_signing_alg_values_supported"`
	RequestObjectSigningAlgValuesSupported     []string `json:"request_object_signing_alg_values_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	RegistrationEndpoint                       string   `json:"registration_endpoint"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	ClaimsSupported                            []string `json:"claims_supported"`
	ClaimTypesSupported                        []string `json:"claim_types_supported"`
	ClaimsParameterSupported                   bool     `json:"claims_parameter_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	RequestParameterSupported                  bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported               bool     `json:"request_uri_parameter_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	TLSClientCertificateBoundAccessToken       bool     `json:"tls_client_certificate_bound_access_token"`
}

type UMA2Configuration struct {
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	EndSessionEndpoint                         string   `json:"end_session_endpoint"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint"`
	Issuer                                     string   `json:"issuer"`
	JwksURI                                    string   `json:"jwks_uri"`
	PermissionEndpoint                         string   `json:"permission_endpoint"`
	PolicyEndpoint                             string   `json:"policy_endpoint"`
	RegistrationEndpoint                       string   `json:"registration_endpoint"`
	ResourceRegistrationEndpoint               string   `json:"resource_registration_endpoint"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	TokenIntrospectionEndpoint                 string   `json:"token_introspection_endpoint"`
}

type UserAccess struct {
	Impersonate           bool `json:"impersonate"`
	Manage                bool `json:"manage"`
	ManageGroupMembership bool `json:"manageGroupMembership"`
	MapRoles              bool `json:"mapRoles"`
	View                  bool `json:"view"`
}

type User struct {
	// these are editable
	Access          UserAccess   `json:"access"`
	Attributes      KeyValuesMap `json:"attributes"`
	Email           string       `json:"email"`
	EmailVerified   bool         `json:"emailVerified"`
	Enabled         bool         `json:"enabled"`
	FirstName       string       `json:"firstName"`
	LastName        string       `json:"lastName"`
	RequiredActions []string     `json:"requiredActions"`
	Username        string       `json:"username"`

	CreatedTimestamp           MicrosecondTime `json:"createdTimestamp"`
	DisableableCredentialTypes []string        `json:"disableableCredentialTypes"`
	FederatedIdentities        []interface{}   `json:"federatedIdentities"`
	ID                         string          `json:"id"`
	NotBefore                  MicrosecondTime `json:"notBefore"`
	Totp                       bool            `json:"totp"`
}

type Users []*User

type UserCreate struct {
	Attributes    KeyValuesMap `json:"attributes"`
	Email         string       `json:"email"`
	EmailVerified bool         `json:"emailVerified"`
	Enabled       bool         `json:"enabled"`
	Username      string       `json:"username"`
}

type GroupAccess struct {
	Manage           bool `json:"manage"`
	ManageMembership bool `json:"manageMembership"`
	View             bool `json:"view"`
}

type Group struct {
	Access      GroupAccess  `json:"access"`
	Attributes  KeyValuesMap `json:"attributes"`
	ClientRoles KeyValuesMap `json:"clientRoles"`
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Path        string       `json:"path"`
	RealmRoles  []string     `json:"realmRoles"`
	SubGroups   []*Group     `json:"subGroups"`
}

type Groups []*Group

type GroupCreate struct {
	Name string `json:"name"`
}

type ImpersonationRequest struct {
	Realm string `json:"realm"`
	User  string `json:"user"`
}

type ImpersonationResponse struct {
	Redirect  string `json:"redirect"`
	SameRealm bool   `json:"sameRealm"`
}

/* Standard claims: https://tools.ietf.org/html/rfc7519
aud = audience
exp = expiration time
jti = jwt id
iat = issued at
iss = issuer
nbf = not before
sub = subject
*/

type PermissionRequestPermission struct {
	Resource string
	Scope    string
}

func NewOpenIDConnectTokenPermission(resource, scope string) PermissionRequestPermission {
	return PermissionRequestPermission{resource, scope}
}

type OpenIDConnectTokenRequest struct {
	// GrantType [required] - Type of grant to evaluate
	// 	- client_credentials
	// 	- code
	// 	- urn:ietf:params:oauth:grant-type:uma-ticket
	GrantType string `json:"grant_type" url:"grant_type"`

	// ClientID [required - grant_type=client_credentials]
	ClientID string `json:"client_id,omitempty" url:"client_id,omitempty"`

	// ClientSecret [required - grant_type=client_credentials]
	ClientSecret string `json:"client_secret,omitempty" url:"client_secret,omitempty"`

	// RefreshToken [required - grant_type=refresh_token] - The value is a valid refresh token that was generated previously
	RefreshToken string `json:"refresh_token,omitempty" url:"refresh_token,omitempty"`

	// Audience [optional] - Specific client to request permission for
	Audience string `json:"audience,omitempty" url:"audience,omitempty"`

	// Ticket [optional] - PermissionEvaluation based on existing permission ticket
	Ticket string `json:"ticket,omitempty" url:"ticket,omitempty"`

	// ClaimToken [optional] - Additional claims to be considered by the server
	ClaimToken string `json:"claim_token,omitempty" url:"claim_token,omitempty"`

	// ClaimTokenFormat [optional] - Format of provided claim token
	//  Allowed values:
	// 		- urn:ietf:params:oauth:token-type:jwt (claim token is an access token)
	// 		- https://openid.net/specs/openid-connect-core-1_0.html#IDToken (claim token is an oidc token)
	ClaimTokenFormat string `json:"claim_token_format,omitempty" url:"claim_token_format,omitempty"`

	// RequestingPartyToken [optional] - Existing RPT whose permissions should be evaluated and added in a new one
	RequestingPartyToken string `json:"rpt,omitempty" url:"rpt,omitempty"`

	// Permission [optional] - PermissionEvaluation specific access to a resource and scope
	Permissions []string `json:"permission,omitempty" url:"permission,omitempty"`

	// ResponseMode [optional] - Used in some uma2 token workflows
	ResponseMode *string `json:"response_mode,omitempty" url:"response_mode,omitempty"`

	// ResponseIncludeResourceName [optional]
	ResponseIncludeResourceName *bool `json:"response_include_resource_name,omitempty" url:"response_include_resource_name,omitempty"`

	// ResponsePermissionsLimit [optional]
	ResponsePermissionsLimit *int `json:"response_permissions_limit,omitempty" url:"response_permissions_limit,omitempty"`

	// SubmitRequest [optional]
	SubmitRequest *bool `json:"submit_request,omitempty" url:"submit_request,omitempty"`
}

func NewOpenIDConnectTokenRequest(grantType string, permissions ...PermissionRequestPermission) *OpenIDConnectTokenRequest {
	r := new(OpenIDConnectTokenRequest)
	r.GrantType = grantType
	for _, perm := range permissions {
		r.AddPermission(perm.Resource, perm.Scope)
	}
	return r
}

// AddPermission is a helper method to add a permission to the request.  There is no concurrency protection, so use at
// your own risk.
func (r *OpenIDConnectTokenRequest) AddPermission(resource, scope string) *OpenIDConnectTokenRequest {
	if r.Permissions == nil {
		r.Permissions = make([]string, 0)
	}
	r.Permissions = append(r.Permissions, fmt.Sprintf("%s#%s", resource, scope))
	return r
}

type EvaluatedPermission struct {
	Scopes       []string `json:"scopes"`
	ResourceID   string   `json:"rsid"`
	ResourceName string   `json:"rsname,omitempty"`
}

type EvaluatedPermissions []*EvaluatedPermission

// Token payload returned from the TokenEndpoint
type OpenIDConnectToken struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	IdToken          string `json:"id_token"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
}

type PermissionDecisionResponse struct {
	Result bool `json:"result"`
}

type TokenIntrospectionResultsPermission struct {
	ResourceID   string `json:"resource_id"`
	ResourceName string `json:"resource_name"`
}

type TokenIntrospectionResults struct {
	Permissions []TokenIntrospectionResultsPermission `json:"permissions"`
	Expires     int                                   `json:"exp"`
	NotBefore   int                                   `json:"nbf"`
	IssuedAt    int                                   `json:"iat"`
	Audience    string                                `json:"aud"`
	Active      bool                                  `json:"active"`
}

// Expect configuration in the json format offered from ks > client > installation
type InstallDocument struct {
	Realm         string            `json:"realm"`
	AuthServerURL string            `json:"auth-server-url"`
	SSLRequired   string            `json:"ssl-required"`
	Resource      string            `json:"resource"`
	Credentials   map[string]string `json:"credentials"`
}

type RealmIssuerConfiguration struct {
	Realm           string `json:"realm"`
	PublicKey       string `json:"public_key"`
	TokenService    string `json:"token-service"`
	AccountService  string `json:"account-service"`
	AdminAPI        string `json:"admin-api"`
	TokensNotBefore int    `json:"tokens-not-before"`
}
type EventsResponseDetails struct {
	AuthMethod  string `json:"auth_method,omitempty"`
	AuthType    string `json:"auth_type,omitempty"`
	CodeID      string `json:"code_id,omitempty"`
	RedirectURI string `json:"redirect_uri,omitempty"`
	Username    string `json:"username,omitempty"`
}

type EventsResponse struct {
	ClientID  string                 `json:"clientId,omitempty"`
	Details   *EventsResponseDetails `json:"details,omitempty"`
	Error     string                 `json:"error,omitempty"`
	IPAddress string                 `json:"ipAddress,omitempty"`
	RealmID   string                 `json:"realmId,omitempty"`
	Time      int                    `json:"time,omitempty"`
	Type      string                 `json:"type,omitempty"`
	UserID    string                 `json:"userId,omitempty"`
}

type ResourceScope struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	IconURI string `json:"iconUri,omitempty"`

	// todo: breaks 3.4
	// DisplayName string `json:"displayName,omitempty"`
}

type ResourceScopes []ResourceScope

type ResourceOwner struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Resource struct {
	ID                 string         `json:"_id"`
	Type               string         `json:"type"`
	Owner              ResourceOwner  `json:"owner"`
	OwnerManagedAccess bool           `json:"ownerManagedAccess"`
	DisplayName        string         `json:"displayName"`
	Scopes             ResourceScopes `json:"scopes"`
	Name               string         `json:"name"`
	IconURI            string         `json:"icon_uri"`

	// TypedScopes - only returned with 3.4
	TypedScopes ResourceScopes `json:"typedScope"`

	// URI - only returned with 3.4
	URI string `json:"uri"`

	// URIs - only returned with 4.0+
	URIs []string `json:"uris"`

	// Attributes - only returned with 4.0+
	Attributes KeyValuesMap `json:"attributes"`
}

type Resources []*Resource

type ResourceMap map[string]*Resource

func (m ResourceMap) IDs() []string {
	list := make([]string, 0, len(m))
	for _, v := range m {
		list = append(list, v.ID)
	}
	return list
}

type ResourceCreateUpdateRequest struct {
	// ID - only used during update request
	ID string `json:"_id,omitempty"`

	IconURI string         `json:"icon_uri"`
	Name    string         `json:"name"`
	Scopes  ResourceScopes `json:"scopes"`
	Type    string         `json:"type"`

	URI *string `json:"uri,omitempty"` // used by 3.4

	// todo: breaks 3.4
	//DisplayName *string      `json:"displayName,omitempty"` // used by 4.0+
	//URIs        []string     `json:"uris,omitempty"`        // used by 4.0+
	//Attributes  KeyValuesMap `json:"attributes,omitempty"`  // used by 4.0+
}

type ResourceServerOverview struct {
	ID                            string    `json:"id"`
	ClientID                      string    `json:"clientId"`
	Name                          string    `json:"name"`
	AllowRemoteResourceManagement bool      `json:"allowRemoteResourceManagement"`
	PolicyEnforcementMode         string    `json:"policyEnforcementMode"`
	Resources                     Resources `json:"resources"`
	Policies                      Policies  `json:"policies"`
	Scopes                        Scopes    `json:"scopes"`
	DecisionStrategy              string    `json:"decisionStrategy"`
}

type RealmAttributes struct {
	XBrowserHeaderContentSecurityPolicy string `json:"_browser_header.contentSecurityPolicy,omitempty"`
	XBrowserHeaderXContentTypeOptions   string `json:"_browser_header.xContentTypeOptions,omitempty"`
	XBrowserHeaderXFrameOptions         string `json:"_browser_header.xFrameOptions,omitempty"`
	XBrowserHeaderXRobotsTag            string `json:"_browser_header.xRobotsTag,omitempty"`
	XBrowserHeaderXXSSProtection        string `json:"_browser_header.xXSSProtection,omitempty"`
	ActionTokenGeneratedByAdminLifespan string `json:"actionTokenGeneratedByAdminLifespan,omitempty"`
	ActionTokenGeneratedByUserLifespan  string `json:"actionTokenGeneratedByUserLifespan,omitempty"`
	BruteForceProtected                 string `json:"bruteForceProtected,omitempty"`
	DisplayName                         string `json:"displayName,omitempty"`
	DisplayNameHTML                     string `json:"displayNameHtml,omitempty"`
	FailureFactor                       string `json:"failureFactor,omitempty"`
	MaxDeltaTimeSeconds                 string `json:"maxDeltaTimeSeconds,omitempty"`
	MaxFailureWaitSeconds               string `json:"maxFailureWaitSeconds,omitempty"`
	MinimumQuickLoginWaitSeconds        string `json:"minimumQuickLoginWaitSeconds,omitempty"`
	PermanentLockout                    string `json:"permanentLockout,omitempty"`
	QuickLoginCheckMilliSeconds         string `json:"quickLoginCheckMilliSeconds,omitempty"`
	WaitIncrementSeconds                string `json:"waitIncrementSeconds,omitempty"`
}

type RealmBrowserSecurityHeaders struct {
	ContentSecurityPolicy string `json:"contentSecurityPolicy,omitempty"`
	XContentTypeOptions   string `json:"xContentTypeOptions,omitempty"`
	XFrameOptions         string `json:"xFrameOptions,omitempty"`
	XRobotsTag            string `json:"xRobotsTag,omitempty"`
	XXSSProtection        string `json:"xXSSProtection,omitempty"`
}

type RealmIdentityProviderConfig struct {
	AuthorizationURL     string `json:"authorizationUrl,omitempty"`
	BackchannelSupported string `json:"backchannelSupported,omitempty"`
	ClientID             string `json:"clientId,omitempty"`
	ClientSecret         string `json:"clientSecret,omitempty"`
	DefaultScope         string `json:"defaultScope,omitempty"`
	DisableUserInfo      string `json:"disableUserInfo,omitempty"`
	HideOnLoginPage      string `json:"hideOnLoginPage,omitempty"`
	LoginHint            string `json:"loginHint,omitempty"`
	TokenURL             string `json:"tokenUrl,omitempty"`
	UseJwksURL           string `json:"useJwksUrl,omitempty"`
	UserIP               string `json:"userIp,omitempty"`
	ValidateSignature    string `json:"validateSignature,omitempty"`
}

type RealmIdentityProvider struct {
	AddReadTokenRoleOnCreate    bool                         `json:"addReadTokenRoleOnCreate,omitempty"`
	Alias                       string                       `json:"alias,omitempty"`
	AuthenticateByDefault       bool                         `json:"authenticateByDefault,omitempty"`
	Config                      *RealmIdentityProviderConfig `json:"config,omitempty"`
	DisplayName                 string                       `json:"displayName,omitempty"`
	Enabled                     bool                         `json:"enabled,omitempty"`
	FirstBrokerLoginFlowAlias   string                       `json:"firstBrokerLoginFlowAlias,omitempty"`
	InternalID                  string                       `json:"internalId,omitempty"`
	LinkOnly                    bool                         `json:"linkOnly,omitempty"`
	ProviderID                  string                       `json:"providerId,omitempty"`
	StoreToken                  bool                         `json:"storeToken,omitempty"`
	TrustEmail                  bool                         `json:"trustEmail,omitempty"`
	UpdateProfileFirstLoginMode string                       `json:"updateProfileFirstLoginMode,omitempty"`
}

type RealmIdentityProviders []*RealmIdentityProvider

type RealmSMTPServer struct {
	Auth               string `json:"auth,omitempty"`
	EnvelopeFrom       string `json:"envelopeFrom,omitempty"`
	From               string `json:"from,omitempty"`
	FromDisplayName    string `json:"fromDisplayName,omitempty"`
	Host               string `json:"host,omitempty"`
	ReplyTo            string `json:"replyTo,omitempty"`
	ReplyToDisplayName string `json:"replyToDisplayName,omitempty"`
	Ssl                string `json:"ssl,omitempty"`
	Starttls           string `json:"starttls,omitempty"`
}

type Realm struct {
	AccessCodeLifespan                  int                          `json:"accessCodeLifespan,omitempty"`
	AccessCodeLifespanLogin             int                          `json:"accessCodeLifespanLogin,omitempty"`
	AccessCodeLifespanUserAction        int                          `json:"accessCodeLifespanUserAction,omitempty"`
	AccessTokenLifespan                 int                          `json:"accessTokenLifespan,omitempty"`
	AccessTokenLifespanForImplicitFlow  int                          `json:"accessTokenLifespanForImplicitFlow,omitempty"`
	AccountTheme                        string                       `json:"accountTheme,omitempty"`
	ActionTokenGeneratedByAdminLifespan int                          `json:"actionTokenGeneratedByAdminLifespan,omitempty"`
	ActionTokenGeneratedByUserLifespan  int                          `json:"actionTokenGeneratedByUserLifespan,omitempty"`
	AdminEventsDetailsEnabled           bool                         `json:"adminEventsDetailsEnabled,omitempty"`
	AdminEventsEnabled                  bool                         `json:"adminEventsEnabled,omitempty"`
	Attributes                          *RealmAttributes             `json:"attributes,omitempty"`
	BrowserFlow                         string                       `json:"browserFlow,omitempty"`
	BrowserSecurityHeaders              *RealmBrowserSecurityHeaders `json:"browserSecurityHeaders,omitempty"`
	BruteForceProtected                 bool                         `json:"bruteForceProtected,omitempty"`
	ClientAuthenticationFlow            string                       `json:"clientAuthenticationFlow,omitempty"`
	DefaultRoles                        []string                     `json:"defaultRoles,omitempty"`
	DirectGrantFlow                     string                       `json:"directGrantFlow,omitempty"`
	DisplayName                         string                       `json:"displayName,omitempty"`
	DisplayNameHTML                     string                       `json:"displayNameHtml,omitempty"`
	DockerAuthenticationFlow            string                       `json:"dockerAuthenticationFlow,omitempty"`
	DuplicateEmailsAllowed              bool                         `json:"duplicateEmailsAllowed,omitempty"`
	EditUsernameAllowed                 bool                         `json:"editUsernameAllowed,omitempty"`
	Enabled                             bool                         `json:"enabled,omitempty"`
	EnabledEventTypes                   []string                     `json:"enabledEventTypes,omitempty"`
	EventsEnabled                       bool                         `json:"eventsEnabled,omitempty"`
	EventsExpiration                    int                          `json:"eventsExpiration,omitempty"`
	EventsListeners                     []string                     `json:"eventsListeners,omitempty"`
	FailureFactor                       int                          `json:"failureFactor,omitempty"`
	ID                                  string                       `json:"id,omitempty"`
	IdentityProviders                   RealmIdentityProviders       `json:"identityProviders,omitempty"`
	InternationalizationEnabled         bool                         `json:"internationalizationEnabled,omitempty"`
	LoginTheme                          string                       `json:"loginTheme,omitempty"`
	LoginWithEmailAllowed               bool                         `json:"loginWithEmailAllowed,omitempty"`
	MaxDeltaTimeSeconds                 int                          `json:"maxDeltaTimeSeconds,omitempty"`
	MaxFailureWaitSeconds               int                          `json:"maxFailureWaitSeconds,omitempty"`
	MinimumQuickLoginWaitSeconds        int                          `json:"minimumQuickLoginWaitSeconds,omitempty"`
	NotBefore                           int                          `json:"notBefore,omitempty"`
	OfflineSessionIdleTimeout           int                          `json:"offlineSessionIdleTimeout,omitempty"`
	OtpPolicyAlgorithm                  string                       `json:"otpPolicyAlgorithm,omitempty"`
	OtpPolicyDigits                     int                          `json:"otpPolicyDigits,omitempty"`
	OtpPolicyInitialCounter             int                          `json:"otpPolicyInitialCounter,omitempty"`
	OtpPolicyLookAheadWindow            int                          `json:"otpPolicyLookAheadWindow,omitempty"`
	OtpPolicyPeriod                     int                          `json:"otpPolicyPeriod,omitempty"`
	OtpPolicyType                       string                       `json:"otpPolicyType,omitempty"`
	PermanentLockout                    bool                         `json:"permanentLockout,omitempty"`
	QuickLoginCheckMilliSeconds         int                          `json:"quickLoginCheckMilliSeconds,omitempty"`
	Realm                               string                       `json:"realm,omitempty"`
	RefreshTokenMaxReuse                int                          `json:"refreshTokenMaxReuse,omitempty"`
	RegistrationAllowed                 bool                         `json:"registrationAllowed,omitempty"`
	RegistrationEmailAsUsername         bool                         `json:"registrationEmailAsUsername,omitempty"`
	RegistrationFlow                    string                       `json:"registrationFlow,omitempty"`
	RememberMe                          bool                         `json:"rememberMe,omitempty"`
	RequiredCredentials                 []string                     `json:"requiredCredentials,omitempty"`
	ResetCredentialsFlow                string                       `json:"resetCredentialsFlow,omitempty"`
	ResetPasswordAllowed                bool                         `json:"resetPasswordAllowed,omitempty"`
	RevokeRefreshToken                  bool                         `json:"revokeRefreshToken,omitempty"`
	SMTPServer                          *RealmSMTPServer             `json:"smtpServer,omitempty"`
	SslRequired                         string                       `json:"sslRequired,omitempty"`
	SsoSessionIdleTimeout               int                          `json:"ssoSessionIdleTimeout,omitempty"`
	SsoSessionMaxLifespan               int                          `json:"ssoSessionMaxLifespan,omitempty"`
	SupportedLocales                    []string                     `json:"supportedLocales,omitempty"`
	VerifyEmail                         bool                         `json:"verifyEmail,omitempty"`
	WaitIncrementSeconds                int                          `json:"waitIncrementSeconds,omitempty"`
}

// Permission is returned by the "PermissionPath" overview call
type Permission struct {
	ID               string   `json:"id,omitempty"`
	Name             string   `json:"name"`
	Description      string   `json:"description,omitempty"`
	Type             string   `json:"type"`
	Logic            string   `json:"logic"`
	DecisionStrategy string   `json:"decisionStrategy"`
	Resources        []string `json:"resources"`
	ResourceType     string   `json:"resourceType"`
	Policies         []string `json:"policies"`
	Scopes           []string `json:"scopes"`
}

type Permissions []*Permission

type PermissionCreateUpdateRequest struct {
	// ID - only used during update request
	ID               string `json:"id,omitempty"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	Type             string `json:"type"`
	Logic            string `json:"logic"`
	DecisionStrategy string `json:"decisionStrategy"`
	// Policies - list of policy id's
	Policies []string `json:"policies"`

	// Resources - list of resource ids
	// 	- only used when type == "resource"
	//	- mutually exclusive with "resourceType"
	Resources []string `json:"resources,omitempty"`

	// ResourceType - matches against the freeform "type" field on any resources within the parent client
	//	- only used when type == "resource"
	//	- mutually exclusive with "resources"
	ResourceType *string `json:"resourceType,omitempty"`

	// Scopes - list of scope ids
	//	- only used when type == "scope" (ui lists this as "role based")
	Scopes []string `json:"scopes,omitempty"`
}

type PermissionScope struct {
	ID               string   `json:"id,omitempty"`
	Name             string   `json:"name,omitempty"`
	Description      string   `json:"description,omitempty"`
	Type             string   `json:"type,omitempty"`
	Policies         []string `json:"policies,omitempty"`
	Resources        []string `json:"resources,omitempty"`
	Scopes           []string `json:"scopes,omitempty"`
	Logic            string   `json:"logic,omitempty"`
	DecisionStrategy string   `json:"decisionStrategy,omitempty"`
}

type PolicyConfig struct {
	Roles Roles `json:"roles"`
}

// UnmarshalJSON is a custom decoder for the string-encoded json policy config payload
func (conf *PolicyConfig) UnmarshalJSON(buf []byte) error {
	ctmap := make(map[string]string)
	err := json.Unmarshal(buf, &ctmap)
	if err != nil {
		return fmt.Errorf("trouble decoding PolicyConfig: %w", err)
	}

	roleString, ok := ctmap["roles"]
	if ok {
		err = json.Unmarshal([]byte(roleString), &conf.Roles)
		if err != nil {
			return fmt.Errorf("trouble parsing roles: %w", err)
		}
	}
	return nil
}

type PolicyRole struct {
	ID       string `json:"id"`
	Required bool   `json:"required"`
}

type PolicyRoles []PolicyRole

type PolicyCreateUpdateRequest struct {
	// ID [optional] - only used during update call
	ID string `json:"id,omitempty"`

	// Type [required] - one of: role, js, time
	Type             string `json:"type"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	DecisionStrategy string `json:"decisionStrategy"`
	Logic            string `json:"logic"`

	// Roles [optional] - only used when type == "role"
	Roles PolicyRoles `json:"roles,omitempty"`

	// Code [optional] - only used when type == "js"
	Code *string `json:"code,omitempty"`

	// Clients [optional] - list of client ids, only used when type == "client"
	Clients []string `json:"clients,omitempty"`

	// -- start time policy fields
	// each of the following fields are only usable when type == "time"

	DayMonth     *int        `json:"dayMonth,omitempty"`
	DayMonthEnd  *int        `json:"dayMonthEnd,omitempty"`
	Hour         *int        `json:"hour,omitempty"`
	HourEnd      *int        `json:"hourEnd,omitempty"`
	Minute       *int        `json:"minute,omitempty"`
	MinuteEnd    *int        `json:"minuteEnd,omitempty"`
	Month        *int        `json:"month,omitempty"`
	MonthEnd     *int        `json:"monthEnd,omitempty"`
	NotBefore    *PolicyTime `json:"notBefore,omitempty"`
	NotOnOrAfter *PolicyTime `json:"notOnOrAfter,omitempty"`
	Year         *int        `json:"year,omitempty"`
	YearEnd      *int        `json:"yearEnd,omitempty"`

	// -- end time policy fields
}

type Policy struct {
	ID               string       `json:"id"`
	Type             string       `json:"type"`
	Name             string       `json:"name"`
	Description      string       `json:"description"`
	Logic            string       `json:"logic"`
	DecisionStrategy string       `json:"decisionStrategy"`
	Config           PolicyConfig `json:"config"`

	// Code - only returned when type == "js"
	Code string `json:"code"`

	// Roles - only returned when type == "role"
	Roles PolicyRoles `json:"roles"`

	// Clients - list of client ids, only returned when type == "client"
	Clients []string `json:"clients"`

	// Time policy fields

	DayMonth     string     `json:"dayMonth"`
	DayMonthEnd  string     `json:"dayMonthEnd"`
	Hour         string     `json:"hour"`
	HourEnd      string     `json:"hourEnd"`
	Minute       string     `json:"minute"`
	MinuteEnd    string     `json:"minuteEnd"`
	Month        string     `json:"month"`
	MonthEnd     string     `json:"monthEnd"`
	NotBefore    PolicyTime `json:"notBefore"`
	NotOnOrAfter PolicyTime `json:"notOnOrAfter"`
	Year         string     `json:"year"`
	YearEnd      string     `json:"yearEnd"`
}

type Policies []*Policy

// Implement sort.Interface for Policies
func (list Policies) Len() int           { return len(list) }
func (list Policies) Less(i, j int) bool { return list[i].Name < list[j].Name }
func (list Policies) Swap(i, j int)      { list[i], list[j] = list[j], list[i] }

type PolicyMap map[string]*Policy

func (m PolicyMap) IDs() []string {
	list := make([]string, 0, len(m))
	for _, v := range m {
		list = append(list, v.ID)
	}
	return list
}

type PolicyProvider struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Group string `json:"group"`
}

type PolicyProviders []*PolicyProvider

type RoleCreateRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`

	// ScopeParamRequired [optional] - seemingly only used by 3.4
	ScopeParamRequired *bool `json:"scopeParamRequired,omitempty"`
}

type Role struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Description        string `json:"description"`
	ScopeParamRequired bool   `json:"scopeParamRequired"`
	Composite          bool   `json:"composite"`
	ClientRole         bool   `json:"clientRole"`
	ContainerID        string `json:"containerId"`

	// todo: breaks 3.4
	//Parent             string       `json:"parent"`
	//Logic              string       `json:"logic"`
	//DecisionStrategy   string       `json:"decisionStrategy"`
	//Client             string       `json:"client"`
	//Type               string       `json:"type"`
	//Required           bool         `json:"required"`
	//Mappings           Roles        `json:"mappings"`
	//Attributes         KeyValuesMap `json:"attributes"`
}

type RoleMap map[string]*Role

type Roles []*Role

// Implement sort.Interface for Role
func (list Roles) Len() int           { return len(list) }
func (list Roles) Less(i, j int) bool { return list[i].Name < list[j].Name }
func (list Roles) Swap(i, j int)      { list[i], list[j] = list[j], list[i] }

type RoleMapping struct {
	RealmMappings  Roles   `json:"realmMappings,omitempty"`
	ClientMappings RoleMap `json:"clientMappings,omitempty"`
}

type Scope struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	Description string `json:"description"`
	IconURI     string `json:"iconUri"`

	DisplayName string `json:"displayName"` // used by 4.0+

	Attributes      KeyValuesMap           `json:"attributes"`
	Protocol        string                 `json:"protocol"`
	ProtocolMappers []ClientProtocolMapper `json:"protocolMappers"`
}

type ScopeCreateUpdateRequest struct {
	// ID [optional] - unused by create request, unused by 3.4 update request, but used by 4.0+ update request
	ID      string `json:"id,omitempty"`
	Name    string `json:"name"`
	IconURI string `json:"iconUri"`

	// todo: breaks 3.4
	//DisplayName string `json:"displayName,omitempty"` // used by 4.0+
}

type Scopes []*Scope

// Implement sort.Interface for Scope
func (list Scopes) Len() int           { return len(list) }
func (list Scopes) Less(i, j int) bool { return list[i].Name < list[j].Name }
func (list Scopes) Swap(i, j int)      { list[i], list[j] = list[j], list[i] }

type JSONWebKey struct {
	KeyID                string   `json:"kid"`
	KeyAlgorithm         string   `json:"alg"`
	KeyType              string   `json:"kty"`
	KeyUsage             string   `json:"use"`
	Modulus              string   `json:"n"`
	Exponent             string   `json:"e"`
	X509CertificateChain []string `json:"x5c"`
	X509Thumbprint       string   `json:"x5t"`
}

type JSONWebKeySet struct {
	Keys []*JSONWebKey `json:"keys"`
}

func (jwk *JSONWebKeySet) KeychainByID(keyID string) *JSONWebKey {
	for _, key := range jwk.Keys {
		if key.KeyID == keyID {
			return key
		}
	}
	return nil
}
