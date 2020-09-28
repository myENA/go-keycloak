package keycloak

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type KeyValuesMap map[string][]string

type Time time.Time

func (k *Time) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	i, err := strconv.Atoi(string(b))
	if err != nil {
		return fmt.Errorf("error converting %q to int: %w", string(b), err)
	}
	*k = Time(time.Unix(0, int64(i)*int64(time.Microsecond)))
	return nil
}

func (k *Time) MarshalJSON() ([]byte, error) {
	if k == nil {
		return nil, nil
	}
	if time.Time(*k).IsZero() {
		return []byte("0"), nil
	}
	return []byte(strconv.FormatInt(time.Time(*k).UnixNano()/int64(time.Microsecond), 10)), nil
}

type ClientAttributes map[string]string // TODO: is this actually just a {"key":"value"}?  not a {"key":["values"]}?

type ClientProtocolMapperConfig struct {
	AccessTokenClaim   string `json:"access.token.claim"`
	ClaimName          string `json:"claim.name"`
	IDTokenClaim       string `json:"id.token.claim"`
	JSONTypeLabel      string `json:"jsonType.label"`
	UserAttribute      string `json:"user.attribute"`
	UserInfoTokenClaim string `json:"userinfo.token.claim"`
}

type ClientProtocolMapper struct {
	Config          *ClientProtocolMapperConfig `json:"config"`
	ConsentRequired bool                        `json:"consentRequired"`
	ConsentText     string                      `json:"consentText"`
	ID              string                      `json:"id"`
	Name            string                      `json:"name"`
	Protocol        string                      `json:"protocol"`
	ProtocolMapper  string                      `json:"protocolMapper"`
}

type ClientAccess struct {
	View      bool `json:"view,omitempty"`
	Configure bool `json:"configure,omitempty"`
	Manage    bool `json:"manage,omitempty"`
}

type Client struct {
	ID                           string                  `json:"id"`
	ClientID                     string                  `json:"clientId"`
	Name                         string                  `json:"name"`
	Description                  string                  `json:"description"`
	SurrogateAuthRequired        bool                    `json:"surrogateAuthRequired"`
	Enabled                      bool                    `json:"enabled"`
	ClientAuthenticatorType      string                  `json:"clientAuthenticatorType"`
	RedirectUris                 []string                `json:"redirectUris"`
	WebOrigins                   []string                `json:"webOrigins"`
	NotBefore                    int                     `json:"notBefore"`
	BearerOnly                   bool                    `json:"bearerOnly"`
	ConsentRequired              bool                    `json:"consentRequired"`
	StandardFlowEnabled          bool                    `json:"standardFlowEnabled"`
	ImplicitFlowEnabled          bool                    `json:"implicitFlowEnabled"`
	DirectAccessGrantsEnabled    bool                    `json:"directAccessGrantsEnabled"`
	ServiceAccountsEnabled       bool                    `json:"serviceAccountsEnabled"`
	AuthorizationServicesEnabled bool                    `json:"authorizationServicesEnabled"`
	PublicClient                 bool                    `json:"publicClient"`
	FrontchannelLogout           bool                    `json:"frontchannelLogout"`
	Protocol                     string                  `json:"protocol"`
	Attributes                   ClientAttributes        `json:"attributes"`
	FullScopeAllowed             bool                    `json:"fullScopeAllowed"`
	NodeReRegistrationTimeout    int                     `json:"nodeReRegistrationTimeout"`
	ProtocolMappers              []*ClientProtocolMapper `json:"protocolMappers"`
	UseTemplateConfig            bool                    `json:"useTemplateConfig"`
	UseTemplateScope             bool                    `json:"useTemplateScope"`
	UseTemplateMappers           bool                    `json:"useTemplateMappers"`
	Access                       *ClientAccess           `json:"access"`
}

type Clients []*Client

type ClientCreate struct {
	Attributes   ClientAttributes `json:"attributes"`
	ClientID     string           `json:"clientId"`
	Enabled      bool             `json:"enabled"`
	Protocol     string           `json:"protocol"`
	RedirectUris []string         `json:"redirectUris"`
}

type OpenIDConfiguration struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	TokenIntrospectionEndpoint                 string   `json:"token_introspection_endpoint"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint"`
	EndSessionEndpoint                         string   `json:"end_session_endpoint"`
	JwksURI                                    string   `json:"jwks_uri"`
	CheckSessionIframe                         string   `json:"check_session_iframe"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
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

	CreatedTimestamp           Time          `json:"createdTimestamp"`
	DisableableCredentialTypes []string      `json:"disableableCredentialTypes"`
	FederatedIdentities        []interface{} `json:"federatedIdentities"`
	ID                         string        `json:"id"`
	NotBefore                  Time          `json:"notBefore"`
	Totp                       bool          `json:"totp"`
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

type OpenIDConnectTokenPermission struct {
	Resource string
	Scope    string
}

func NewOpenIDConnectTokenPermission(resource, scope string) OpenIDConnectTokenPermission {
	return OpenIDConnectTokenPermission{resource, scope}
}

func (p OpenIDConnectTokenPermission) MarshalText() ([]byte, error) {
	return []byte(fmt.Sprintf("%s#%s", p.Resource, p.Scope)), nil
}

func (p *OpenIDConnectTokenPermission) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if !strings.Contains(string(b), "#") {
		return fmt.Errorf("expected token \"#\" missing in %q", string(b))
	}
	s := strings.SplitN(string(b), "#", 2)
	*p = OpenIDConnectTokenPermission{s[0], s[1]}
	return nil
}

type OpenIDConnectTokenRequest struct {
	// GrantType [required]
	GrantType string `json:"grant_type,omitempty" url:"grant_type,omitempty"`

	// Permission [optional] - Request specific access to "Resource#scope[,scope...]"
	Permissions []OpenIDConnectTokenPermission `json:"permission,omitempty" url:"permission,omitempty"`

	ClientID     string `json:"client_id,omitempty" url:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty" url:"client_secret,omitempty"`

	ClientAssertionType string `json:"client_assertion_type,omitempty" url:"client_assertion_type,omitempty"`
	ClientAssertion     string `json:"client_assertion,omitempty" url:"client_assertion,omitempty"`

	SubjectToken     string `json:"subject_token,omitempty" url:"subject_token,omitempty"`
	SubjectIssuer    string `json:"subject_issuer,omitempty" url:"subject_issuer,omitempty"`
	SubjectTokenType string `json:"subject_token_type,omitempty" url:"subject_token_type,omitempty"`

	RequestedTokenType string `json:"requested_token_type,omitempty" url:"requested_token_type,omitempty"`

	Audience string `json:"audience,omitempty" url:"audience,omitempty"`

	RequestedIssuer  string `json:"requested_issuer,omitempty" url:"requested_issuer,omitempty"`
	RequestedSubject string `json:"requested_subject,omitempty" url:"requested_subject,omitempty"`

	// RequestingPartyToken - todo: what exactly does this look like...
	RequestingPartyToken string `json:"rpt,omitempty" url:"rpt,omitempty"`

	ResponseIncludeResourceName *bool `json:"response_include_resource_name,omitempty" url:"response_include_resource_name,omitempty"`

	ResponsePermissionsLimit *int `json:"response_permissions_limit,omitempty" url:"response_permissions_limit,omitempty"`

	// ResponseMode [optional] - Allowed values: ["decision", "permissions"]
	ResponseMode string `json:"response_mode,omitempty" url:"response_mode,omitempty"`

	SubmitRequest *bool `json:"submit_request,omitempty" url:"submit_request,omitempty"`
}

func NewOpenIDConnectTokenRequest(grantType string, permissions ...OpenIDConnectTokenPermission) *OpenIDConnectTokenRequest {
	r := new(OpenIDConnectTokenRequest)
	r.GrantType = grantType
	r.Permissions = permissions
	return r
}

// AddPermission is a helper method to add a permission to the request.  There is no concurrency protection, so use at
// your own risk.
func (r *OpenIDConnectTokenRequest) AddPermission(resource, scope string) *OpenIDConnectTokenRequest {
	if r.Permissions == nil {
		r.Permissions = make([]OpenIDConnectTokenPermission, 0)
	}
	r.Permissions = append(r.Permissions, NewOpenIDConnectTokenPermission(resource, scope))
	return r
}

// Token payload returned from the TokenEndpoint
type OpenIDConnectToken struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	IdToken          string `json:"id_token"`
	NotBeforePolicy  int    `json:"not_before_policy"`
	SessionState     string `json:"session_state"`
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
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type ResourceScopes []*ResourceScope

type ResourceOwner struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type Resource struct {
	Name   string         `json:"name,omitempty"`
	Type   string         `json:"type,omitempty"`
	Scopes ResourceScopes `json:"scopes"`
	Owner  *ResourceOwner `json:"owner,omitempty"`
	ID     string         `json:"_id,omitempty"`
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

type ResourceServer struct {
	ID                            string    `json:"id"`
	ClientID                      string    `json:"clientId"`
	Name                          string    `json:"name"`
	AllowRemoteResourceManagement bool      `json:"allowRemoteResourceManagement"`
	PolicyEnforcementMode         string    `json:"policyEnforcementMode"`
	Resources                     Resources `json:"resources"`
	Policies                      Policies  `json:"policies"`
	Scopes                        Scopes    `json:"scopes"`
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

// TODO: Model this
type PermissionConfig map[string]interface{}

// Permission is returned by the "PermissionPath" overview call
type Permission struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	Type             string           `json:"type"`
	Logic            string           `json:"logic"`
	DecisionStrategy string           `json:"decisionStrategy"`
	Config           PermissionConfig `json:"config"`
	Description      string           `json:"description,omitempty"`
}

type PermissionMap map[string]*Permission

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

type Policy struct {
	ID               string       `json:"id,omitempty"`
	Name             string       `json:"name,omitempty"`
	Type             string       `json:"type,omitempty"`
	Logic            string       `json:"logic,omitempty"`
	DecisionStrategy string       `json:"decisionStrategy,omitempty"`
	Config           PolicyConfig `json:"config,omitempty"`
	Description      string       `json:"description,omitempty"`
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

type Role struct {
	ID                 string `json:"id,omitempty"`
	Name               string `json:"name,omitempty"`
	Parent             string `json:"parent,omitempty"`
	Description        string `json:"description,omitempty"`
	Logic              string `json:"logic,omitempty"`
	DecisionStrategy   string `json:"decisionStrategy,omitempty"`
	ScopeParamRequired bool   `json:"scopeParamRequired"`
	Composite          bool   `json:"composite,omitempty"`
	Client             string `json:"client,omitempty"`
	ClientRole         bool   `json:"clientRole,omitempty"`
	ContainerID        string `json:"containerId,omitempty"`
	Type               string `json:"type,omitempty"`
	Required           bool   `json:"required,omitempty"`
	Mappings           Roles  `json:"mappings,omitempty"`
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
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
}

type ScopeMap map[string]*Scope

func (m ScopeMap) IDs() []string {
	list := make([]string, 0, len(m))
	for _, v := range m {
		list = append(list, v.ID)
	}
	return list
}

func (m ScopeMap) NamedIDs() ResourceScopes {
	list := make(ResourceScopes, 0, len(m))
	for _, v := range m {
		list = append(list, &ResourceScope{
			Name: v.Name,
			ID:   v.ID,
		})
	}
	return list
}

type Scopes []*Scope

// Implement sort.Interface for Scope
func (list Scopes) Len() int           { return len(list) }
func (list Scopes) Less(i, j int) bool { return list[i].Name < list[j].Name }
func (list Scopes) Swap(i, j int)      { list[i], list[j] = list[j], list[i] }
