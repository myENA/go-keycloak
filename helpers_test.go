package keycloak

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go/v4"
)

func TestHandleResponse(t *testing.T) {
	if err := handleResponse(nil, http.StatusOK, nil, errors.New("src")); err == nil || err.Error() != "src" {
		t.Fatalf("source error = %v", err)
	}
	cleanupHTTPResponseBody(nil)

	resp := recordedResponse(http.StatusOK, "hello")
	var buf bytes.Buffer
	if err := handleResponse(resp, http.StatusOK, &buf, nil); err != nil || buf.String() != "hello" {
		t.Fatalf("writer = %q, %v", buf.String(), err)
	}

	resp = recordedResponse(http.StatusOK, "abc")
	var raw []byte
	if err := handleResponse(resp, http.StatusOK, &raw, nil); err != nil || string(raw) != "abc" {
		t.Fatalf("bytes = %q, %v", raw, err)
	}

	resp = recordedResponse(http.StatusOK, "")
	var model struct{ A string }
	if err := handleResponse(resp, http.StatusOK, &model, nil); err != nil {
		t.Fatal(err)
	}
	resp = recordedResponse(http.StatusOK, "{")
	if err := handleResponse(resp, http.StatusOK, &model, nil); err == nil {
		t.Fatal("expected decode error")
	}

	resp = recordedResponse(http.StatusBadRequest, `{"error":"invalid","error_description":"nope"}`)
	err := handleResponse(resp, http.StatusOK, nil, nil)
	apiErr, ok := err.(*APIError)
	if !ok || apiErr.Err != "invalid" || apiErr.ErrDescription != "nope" || apiErr.Error() == "" {
		t.Fatalf("api error = %#v", err)
	}
	if !IsAPIError(fmt.Errorf("wrap: %w", err)) || IsAPIError(nil) || IsAPIError(errors.New("x")) {
		t.Fatal("IsAPIError")
	}
	if (&APIError{}).Error() != "" {
		t.Fatal("empty api error")
	}

	resp = recordedResponse(http.StatusBadRequest, "plain")
	err = handleResponse(resp, http.StatusOK, nil, nil)
	apiErr = err.(*APIError)
	if apiErr.ErrDescription != "plain" {
		t.Fatalf("description = %q", apiErr.ErrDescription)
	}
}

func TestTokenAndAudienceHelpers(t *testing.T) {
	if IsTokenExpiredErr(nil) || IsTokenExpiredErr(errors.New("x")) {
		t.Fatal("unexpected expired")
	}
	if !IsTokenExpiredErr(fmt.Errorf("wrap: %w", ErrTokenExpired)) {
		t.Fatal("expected expired")
	}

	iss := "http://keycloak.example/realms/demo"
	auth, realm, err := ClaimsSource(&jwt.StandardClaims{Issuer: iss})
	if err != nil || auth != "http://keycloak.example" || realm != "demo" {
		t.Fatalf("claims = %s %s %v", auth, realm, err)
	}
	auth, realm, err = ClaimsSource(jwt.MapClaims{"iss": iss + "/"})
	if err != nil || realm != "demo" {
		t.Fatalf("map claims = %s %s %v", auth, realm, err)
	}
	if _, _, err = ClaimsSource(jwt.MapClaims{"iss": 1}); err == nil {
		t.Fatal("expected missing issuer")
	}
	if _, _, err = ClaimsSource(&jwt.StandardClaims{}); err == nil {
		t.Fatal("expected missing issuer")
	}
	if _, _, err = ClaimsSource(jwt.MapClaims{"iss": "http://example"}); err == nil {
		t.Fatal("expected unsplittable issuer")
	}

	raw := unsignedToken(iss)
	auth, realm, err = TokenSource(raw)
	if err != nil || auth != "http://keycloak.example" || realm != "demo" {
		t.Fatalf("token source = %s %s %v", auth, realm, err)
	}
	if _, _, err = TokenSource("not-a-token"); err == nil {
		t.Fatal("expected token error")
	}

	if !verifyAudience(nil, "app", false) || verifyAudience(nil, "app", true) {
		t.Fatal("empty audience")
	}
	if verifyAudience([]string{""}, "app", true) || !verifyAudience([]string{""}, "app", false) {
		t.Fatal("blank audience")
	}
	if !verifyAudience([]string{"other", "app"}, "app", true) || verifyAudience([]string{"other"}, "app", true) {
		t.Fatal("audience match")
	}

	if copyStrs(nil) != nil {
		t.Fatal("nil copy")
	}
	copied := copyStrs([]string{"a"})
	copied[0] = "b"
	if copyStrs([]string{"a"})[0] != "a" {
		t.Fatal("copy alias")
	}

	if _, err = permissionModifyPath(&PermissionCreateUpdateRequest{Type: PermissionTypeResource}); err != nil {
		t.Fatal(err)
	}
	if _, err = permissionModifyPath(&PermissionCreateUpdateRequest{Type: PermissionTypeRole}); err != nil {
		t.Fatal(err)
	}
	if _, err = permissionModifyPath(&PermissionCreateUpdateRequest{}); err == nil {
		t.Fatal("expected permission type error")
	}
	for _, kind := range []string{PolicyTypeJavascript, PolicyTypeRole, PolicyTypeTime} {
		if _, err = policyModifyPath(&PolicyCreateUpdateRequest{Type: kind}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = policyModifyPath(&PolicyCreateUpdateRequest{}); err == nil {
		t.Fatal("expected policy type error")
	}
}

func TestBearerTokenRequest(t *testing.T) {
	if _, ok := RequestBearerToken(nil); ok {
		t.Fatal("nil request")
	}
	req, err := http.NewRequest(http.MethodGet, "http://example", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := RequestBearerToken(req); ok {
		t.Fatal("missing header")
	}
	req.Header.Set(HTTPpHeaderAuthorization, "Basic abc")
	if _, ok := RequestBearerToken(req); ok {
		t.Fatal("basic header")
	}
	req.Header.Set(HTTPpHeaderAuthorization, "Bearer tok")
	got, ok := RequestBearerToken(req)
	if !ok || got != "tok" {
		t.Fatalf("token = %q %v", got, ok)
	}
	provider, err := NewBearerTokenProviderFromRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	mutators, err := provider.RequestMutators(nil, nil)
	if err != nil || len(mutators) != 1 {
		t.Fatal(err)
	}
	apiReq := NewAPIRequest(http.MethodGet, "http://example")
	if err = mutators[0](apiReq); err != nil {
		t.Fatal(err)
	}
	if apiReq.Headers().Get(HTTPpHeaderAuthorization) != "Bearer tok" {
		t.Fatalf("header = %s", apiReq.Headers().Get(HTTPpHeaderAuthorization))
	}
	req.Header.Del(HTTPpHeaderAuthorization)
	if _, err = NewBearerTokenProviderFromRequest(req); err == nil {
		t.Fatal("expected missing bearer")
	}
}

func TestClientSecretConfig(t *testing.T) {
	if _, err := NewClientSecretAuthenticationProvider(ClientSecretProviderConfig{}); err == nil {
		t.Fatal("expected url error")
	}
	if _, err := NewClientSecretAuthenticationProvider(ClientSecretProviderConfig{AuthServerURL: "http://h"}); err == nil {
		t.Fatal("expected realm error")
	}
	if _, err := NewClientSecretAuthenticationProvider(ClientSecretProviderConfig{AuthServerURL: "http://h", Realm: "r"}); err == nil {
		t.Fatal("expected client error")
	}
	if _, err := NewClientSecretAuthenticationProvider(ClientSecretProviderConfig{AuthServerURL: "http://h", Realm: "r", Resource: "app"}); err == nil {
		t.Fatal("expected secret error")
	}
	provider, err := NewClientSecretAuthenticationProvider(ClientSecretProviderConfig{
		AuthServerURL: "http://h",
		Realm:         "r",
		Resource:      "app",
		Secret:        "secret",
		ExpiryMargin:  time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !provider.Expired() {
		t.Fatal("new provider should be expired")
	}
	realm, err := provider.Realm()
	if err != nil || realm != "r" || provider.ClientID() != "app" {
		t.Fatalf("provider = %s %s %v", realm, provider.ClientID(), err)
	}
	_ = provider.LastRefreshed()
	_ = provider.Expiry()

	doc := NewClientSecretConfigWithInstallDocument(&InstallDocument{
		Realm:         "realm",
		AuthServerURL: "http://h",
		Resource:      "app",
		Credentials:   map[string]string{"secret": "s"},
	})
	if doc.Secret != "s" || doc.Realm != "realm" {
		t.Fatalf("install = %#v", doc)
	}
}

func TestConfigAndCache(t *testing.T) {
	parsed, err := url.Parse("https://example.com/auth")
	if err != nil {
		t.Fatal(err)
	}
	serverURL, err := NewAuthServerURLProviderWithURL(parsed).AuthServerURL()
	if err != nil || serverURL != "https://example.com/auth" {
		t.Fatalf("url = %s %v", serverURL, err)
	}

	httpClient := &http.Client{}
	cache := NewNoopCache()
	cfg := CompileAPIClientConfig(&APIClientConfig{HTTPClient: httpClient, CacheBackend: cache, Debug: &DebugConfig{}}, func(c *APIClientConfig) {
		c.AuthServerURLProvider = NewAuthServerURLProvider("http://configured")
	})
	if cfg.HTTPClient != httpClient || cfg.CacheBackend != cache || cfg.Debug == nil {
		t.Fatal("config fields were not kept")
	}
	if got, err := cfg.AuthServerURLProvider.AuthServerURL(); err != nil || got != "http://configured" {
		t.Fatalf("configured url = %s %v", got, err)
	}
	cfg = CompileAPIClientConfig(nil)
	if got, err := cfg.AuthServerURLProvider.AuthServerURL(); err != nil || got != "http://127.0.0.1/auth" {
		t.Fatalf("default url = %s %v", got, err)
	}
	if cfg.HTTPClient == nil || cfg.CacheBackend == nil {
		t.Fatal("default config is incomplete")
	}

	cache.StoreUntil("k", "v", time.Now().Add(time.Hour))
	if _, ok := cache.Load("k"); ok || cache.Flush() != 0 {
		t.Fatal("noop cache stored a value")
	}
	cache.Delete("k")

	persistent := NewPersistentCache()
	persistent.StoreUntil("k", "v", time.Now())
	persistent.StoreUntil("k2", "v2", time.Now())
	if value, ok := persistent.Load("k"); !ok || value != "v" {
		t.Fatalf("load = %#v %v", value, ok)
	}
	persistent.Delete("k2")
	if persistent.Flush() != 1 {
		t.Fatal("flush count")
	}
	if _, ok := persistent.Load("k"); ok {
		t.Fatal("flushed key remains")
	}

	if buildPKCacheKey("http://h", "realm", "kid") == "" {
		t.Fatal("empty pk key")
	}
	auth, realm := parseRealmEnvCacheKey(buildRealmEnvCacheKey("http://h", "realm"))
	if auth != "http://h" || realm != "realm" {
		t.Fatalf("realm key = %s %s", auth, realm)
	}
	if auth, realm = parseRealmEnvCacheKey(1); auth != "" || realm != "" {
		t.Fatal("non-string key")
	}
	if auth, realm = parseRealmEnvCacheKey("nope"); auth != "" || realm != "" {
		t.Fatal("bad key")
	}
	parsePKCacheKey(buildPKCacheKey("http://h", "realm", "kid"))
	parsePKCacheKey(1)
	if !globalCacheEquivalencyTest(nil, "a", "a") || globalCacheEquivalencyTest(nil, "a", "b") {
		t.Fatal("cache compare")
	}
}

func TestConstructorsPanicOnNil(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	NewAuthServerURLProviderWithURL(nil)
}

func TestNilRealmProviderPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	SetRealmEnvironmentProvider(nil)
}

func TestRealmEnvironmentAccessors(t *testing.T) {
	oidc := &OpenIDConfiguration{
		Issuer: "oidc-iss", AuthorizationEndpoint: "oidc-auth", TokenEndpoint: "oidc-token",
		IntrospectionEndpoint: "oidc-intro", EndSessionEndpoint: "oidc-end", JSONWebKeysEndpoint: "oidc-jwks",
		RegistrationEndpoint: "oidc-reg", UserInfoEndpoint: "oidc-user", CheckSessionIframe: "oidc-iframe",
		GrantTypesSupported: []string{"oidc-grant"}, ResponseTypesSupported: []string{"oidc-response"},
		ResponseModesSupported: []string{"oidc-mode"}, TokenEndpointAuthMethodsSupported: []string{"oidc-auth-method"},
		TokenEndpointAuthSigningAlgValuesSupported: []string{"oidc-alg"}, ScopesSupported: []string{"oidc-scope"},
		SubjectTypesSupported: []string{"public"}, IDTokenSigningAlgValuesSupported: []string{"RS256"},
		IDTokenEncryptionAlgValuesSupported: []string{"RSA-OAEP"}, IDTokenEncryptionEncValuesSupported: []string{"A256GCM"},
		UserinfoSigningAlgValuesSupported: []string{"RS256"}, RequestObjectSigningAlgValuesSupported: []string{"RS256"},
		ClaimsSupported: []string{"sub"}, ClaimTypesSupported: []string{"normal"},
		CodeChallengeMethodsSupported: []string{"S256"}, ClaimsParameterSupported: true,
		RequestParameterSupported: true, RequestURIParameterSupported: true, TLSClientCertificateBoundAccessToken: true,
	}
	uma := &UMA2Configuration{
		Issuer: "uma-iss", AuthorizationEndpoint: "uma-auth", TokenEndpoint: "uma-token",
		IntrospectionEndpoint: "uma-intro", EndSessionEndpoint: "uma-end", JwksURI: "uma-jwks",
		RegistrationEndpoint: "uma-reg", PermissionEndpoint: "uma-perm", PolicyEndpoint: "uma-policy",
		ResourceRegistrationEndpoint: "uma-res", GrantTypesSupported: []string{"uma-grant"},
		ResponseTypesSupported: []string{"uma-response"}, ResponseModesSupported: []string{"uma-mode"},
		TokenEndpointAuthMethodsSupported:          []string{"uma-auth-method"},
		TokenEndpointAuthSigningAlgValuesSupported: []string{"uma-alg"}, ScopesSupported: []string{"uma-scope"},
	}
	withUMA := &RealmEnvironment{oidc: oidc, uma2c: uma}
	oidcOnly := &RealmEnvironment{oidc: oidc}

	if !withUMA.SupportsUMA2() || oidcOnly.SupportsUMA2() {
		t.Fatal("uma support")
	}
	if withUMA.IssuerAddress() != "uma-iss" || oidcOnly.IssuerAddress() != "oidc-iss" {
		t.Fatal("issuer")
	}
	if withUMA.AuthorizationEndpoint() != "uma-auth" || oidcOnly.AuthorizationEndpoint() != "oidc-auth" {
		t.Fatal("authorization")
	}
	if withUMA.TokenEndpoint() != "uma-token" || oidcOnly.TokenEndpoint() != "oidc-token" {
		t.Fatal("token")
	}
	if withUMA.IntrospectionEndpoint() != "uma-intro" || oidcOnly.IntrospectionEndpoint() != "oidc-intro" {
		t.Fatal("introspection")
	}
	if withUMA.EndSessionEndpoint() != "uma-end" || oidcOnly.EndSessionEndpoint() != "oidc-end" {
		t.Fatal("end session")
	}
	if withUMA.JSONWebKeysEndpoint() != "uma-jwks" || oidcOnly.JSONWebKeysEndpoint() != "oidc-jwks" {
		t.Fatal("jwks")
	}
	if withUMA.RegistrationEndpoint() != "uma-reg" || oidcOnly.RegistrationEndpoint() != "oidc-reg" {
		t.Fatal("registration")
	}
	assertCopied(t, withUMA.GrantTypesSupported(), "uma-grant")
	assertCopied(t, oidcOnly.GrantTypesSupported(), "oidc-grant")
	assertCopied(t, withUMA.ResponseTypesSupported(), "uma-response")
	assertCopied(t, oidcOnly.ResponseTypesSupported(), "oidc-response")
	assertCopied(t, withUMA.ResponseModesSupported(), "uma-mode")
	assertCopied(t, oidcOnly.ResponseModesSupported(), "oidc-mode")
	assertCopied(t, withUMA.TokenEndpointAuthMethodsSupported(), "uma-auth-method")
	assertCopied(t, oidcOnly.TokenEndpointAuthMethodsSupported(), "oidc-auth-method")
	assertCopied(t, withUMA.TokenEndpointAuthSigningAlgValuesSupported(), "uma-alg")
	assertCopied(t, oidcOnly.TokenEndpointAuthSigningAlgValuesSupported(), "oidc-alg")
	assertCopied(t, withUMA.ScopesSupported(), "uma-scope")
	assertCopied(t, oidcOnly.ScopesSupported(), "oidc-scope")

	if oidcOnly.UserInfoEndpoint() != "oidc-user" || oidcOnly.CheckSessionIframe() != "oidc-iframe" {
		t.Fatal("oidc endpoints")
	}
	assertCopied(t, oidcOnly.SubjectTypesSupported(), "public")
	assertCopied(t, oidcOnly.IDTokenSigningAlgValuesSupported(), "RS256")
	assertCopied(t, oidcOnly.IDTokenEncryptionAlgValuesSupported(), "RSA-OAEP")
	assertCopied(t, oidcOnly.IDTokenEncryptionEncValuesSupported(), "A256GCM")
	assertCopied(t, oidcOnly.UserInfoSigningAlgValuesSupported(), "RS256")
	assertCopied(t, oidcOnly.RequestObjectSigningAlgValuesSupported(), "RS256")
	assertCopied(t, oidcOnly.ClaimsSupported(), "sub")
	assertCopied(t, oidcOnly.ClaimTypesSupported(), "normal")
	assertCopied(t, oidcOnly.CodeChallengeMethodsSupported(), "S256")
	if !oidcOnly.ClaimsParameterSupported() || !oidcOnly.RequestParameterSupported() || !oidcOnly.RequestURIParameterSupported() || !oidcOnly.TLSClientCertificateBoundAccessTokens() {
		t.Fatal("oidc flags")
	}

	if got, ok := withUMA.ResourceRegistrationEndpoint(); !ok || got != "uma-res" {
		t.Fatalf("resource registration = %s %v", got, ok)
	}
	if _, ok := oidcOnly.ResourceRegistrationEndpoint(); ok {
		t.Fatal("oidc resource registration")
	}
	if got, ok := withUMA.PermissionEndpoint(); !ok || got != "uma-perm" {
		t.Fatalf("permission = %s %v", got, ok)
	}
	if _, ok := oidcOnly.PermissionEndpoint(); ok {
		t.Fatal("oidc permission")
	}
	if got, ok := withUMA.PolicyEndpoint(); !ok || got == "" {
		t.Fatalf("policy = %s %v", got, ok)
	}
	if _, ok := oidcOnly.PolicyEndpoint(); ok {
		t.Fatal("oidc policy")
	}
}

func TestTokenParserRejectsBadTokens(t *testing.T) {
	parser := NewX509TokenParser(time.Minute)
	client := &APIClient{authServerURL: "http://example"}
	if _, err := parser.Parse(context.Background(), client, nil); err == nil {
		t.Fatal("nil token")
	}
	token := &jwt.Token{Method: jwt.SigningMethodHS256, Header: map[string]interface{}{}}
	if _, err := parser.Parse(context.Background(), client, token); err == nil {
		t.Fatal("unsupported alg")
	}
	token.Method = jwt.SigningMethodRS256
	if _, err := parser.Parse(context.Background(), client, token); err == nil {
		t.Fatal("missing kid")
	}
	token.Header["kid"] = 1
	if _, err := parser.Parse(context.Background(), client, token); err == nil {
		t.Fatal("non-string kid")
	}
	token.Header["kid"] = "k1"
	token.Raw = "not-a-token"
	if _, err := parser.Parse(context.Background(), client, token); err == nil {
		t.Fatal("bad raw token")
	}
	if algs := parser.SupportedAlgorithms(); len(algs) == 0 {
		t.Fatal("no algorithms")
	}
	if got, ok := GetTokenParser("RS256"); !ok || got == nil {
		t.Fatal("missing RS256 parser")
	}
	if _, ok := GetTokenParser("NO-SUCH-ALG"); ok {
		t.Fatal("unexpected parser")
	}
	RegisterTokenParsers(testTokenParser{})
	if _, ok := GetTokenParser("TESTALG"); !ok {
		t.Fatal("registered parser missing")
	}
}

type testTokenParser struct{}

func (testTokenParser) Parse(ctx context.Context, client *APIClient, token *jwt.Token) (interface{}, error) {
	return nil, errors.New("unused")
}

func (testTokenParser) SupportedAlgorithms() []string { return []string{"TESTALG"} }

func recordedResponse(status int, body string) *http.Response {
	rec := httptest.NewRecorder()
	rec.WriteHeader(status)
	_, _ = rec.WriteString(body)
	return rec.Result()
}

func unsignedToken(iss string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + iss + `"}`))
	return header + "." + payload + "."
}

func assertCopied(t *testing.T, got []string, want string) {
	t.Helper()
	if len(got) != 1 || got[0] != want {
		t.Fatalf("got %#v, want %s", got, want)
	}
	got[0] = "changed"
}
