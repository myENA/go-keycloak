package keycloak

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go/v4"
)

func TestClientAndTokenCoverage(t *testing.T) {
	rsaKey, rsaCert, rsaPub := testRSA(t)
	_, ecCert := testECDSA(t)
	var oidcHits atomic.Int32
	var certHits atomic.Int32

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := readBody(r)
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path
		switch {
		case strings.Contains(p, "/realms/missing/"):
			http.NotFound(w, r)
		case strings.Contains(p, "/realms/old/") && strings.Contains(p, "uma2-configuration"):
			http.NotFound(w, r)
		case strings.Contains(p, "openid-configuration"):
			if strings.Contains(p, "/realms/realm/") {
				oidcHits.Add(1)
			}
			realm := "realm"
			if strings.Contains(p, "/realms/old/") {
				realm = "old"
			}
			_, _ = w.Write([]byte(realmDoc(srv.URL, realm)))
		case strings.Contains(p, "uma2-configuration"):
			_, _ = w.Write([]byte(realmDoc(srv.URL, "realm")))
		case strings.HasSuffix(p, "/certs"):
			certHits.Add(1)
			fmt.Fprintf(w, `{"keys":[{"kid":"k1","x5c":[%q]},{"kid":"k2"},{"kid":"k3","x5c":[%q]}]}`, rsaCert, ecCert)
		case strings.Contains(p, "/entitlement/"):
			fmt.Fprintf(w, `{"rpt":%q}`, signToken(t, rsaKey, srv.URL+"/realms/old", "k1"))
		case p == "/token":
			switch {
			case strings.Contains(body, "client_secret=bad"):
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			case strings.Contains(body, "audience=bad"):
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"bad"}`))
			case strings.Contains(body, "audience=deny"):
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"deny"}`))
			case strings.Contains(body, "response_mode=permissions"):
				_, _ = w.Write([]byte(`[{"rsid":"res","rsname":"docs","scopes":["read"]}]`))
			case strings.Contains(body, "response_mode=decision"):
				_, _ = w.Write([]byte(`{"result":true}`))
			default:
				fmt.Fprintf(w, `{"access_token":%q,"expires_in":60,"refresh_expires_in":120,"token_type":"Bearer"}`, signToken(t, rsaKey, srv.URL+"/realms/realm", "k1"))
			}
		case p == "/introspect":
			_, _ = w.Write([]byte(`{"active":true,"aud":"app"}`))
		default:
			fmt.Fprintf(w, `{"realm":"realm","public_key":%q}`, rsaPub)
		}
	}))
	t.Cleanup(srv.Close)

	cfg := DefaultAPIClientConfig()
	cfg.AuthServerURLProvider = NewAuthServerURLProvider(srv.URL)
	cfg.HTTPClient = srv.Client()
	cfg.CacheBackend = NewPersistentCache()
	client, err := NewAPIClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if client.AuthServerURL() != srv.URL || client.CacheBackend() == nil {
		t.Fatal("client was not configured")
	}
	ctx := context.Background()

	if _, err = client.RealmIssuerConfiguration(ctx, "realm"); err != nil {
		t.Fatal(err)
	}
	if _, err = client.OpenIDConfiguration(ctx, "realm"); err != nil {
		t.Fatal(err)
	}
	if _, err = client.UMA2Configuration(ctx, "realm"); err != nil {
		t.Fatal(err)
	}
	env, err := client.RealmEnvironment(ctx, "realm")
	if err != nil || !env.SupportsUMA2() || env.TokenEndpoint() != srv.URL+"/token" {
		t.Fatalf("uma = %v, err = %v", env != nil && env.SupportsUMA2(), err)
	}
	hits := oidcHits.Load()
	if _, err = client.RealmEnvironment(ctx, "realm"); err != nil || oidcHits.Load() != hits {
		t.Fatalf("oidc hits = %d, want %d, err = %v", oidcHits.Load(), hits, err)
	}
	if _, err = client.RealmEnvironment(ctx, "missing"); err == nil {
		t.Fatal("expected missing realm error")
	}
	jwks, err := client.JSONWebKeys(ctx, "realm")
	if err != nil || jwks.KeychainByID("k1") == nil || jwks.KeychainByID("missing") != nil {
		t.Fatalf("jwks = %#v %v", jwks, err)
	}

	token, err := client.Login(ctx, NewOpenIDConnectTokenRequest(GrantTypeClientCredentials), "realm")
	if err != nil || token.AccessToken == "" {
		t.Fatalf("login = %#v %v", token, err)
	}
	if _, err = client.Login(ctx, NewOpenIDConnectTokenRequest(GrantTypeClientCredentials), "missing"); err == nil {
		t.Fatal("expected login error")
	}

	service := client.TokenService()
	if _, err = service.OpenIDConnectToken(ctx, "realm", nil, NewOpenIDConnectTokenRequest(GrantTypeClientCredentials)); err != nil {
		t.Fatal(err)
	}
	perms, err := service.PermissionEvaluation(ctx, "realm", nil, NewOpenIDConnectTokenRequest(GrantTypeUMA2Ticket))
	if err != nil || len(perms) != 1 || perms[0].ResourceID != "res" {
		t.Fatalf("permissions = %#v %v", perms, err)
	}
	decision, err := service.PermissionDecision(ctx, "realm", nil, NewOpenIDConnectTokenRequest(GrantTypeUMA2Ticket))
	if err != nil || decision == nil || !decision.Result {
		t.Fatalf("decision = %#v %v", decision, err)
	}
	denied, err := service.PermissionDecision(ctx, "realm", nil, &OpenIDConnectTokenRequest{GrantType: GrantTypeUMA2Ticket, Audience: "deny"})
	if err == nil || denied == nil || denied.Result {
		t.Fatalf("denied = %#v %v", denied, err)
	}
	if got, err := service.PermissionDecision(ctx, "realm", nil, &OpenIDConnectTokenRequest{GrantType: GrantTypeUMA2Ticket, Audience: "bad"}); err == nil || got != nil {
		t.Fatalf("bad decision = %#v %v", got, err)
	}
	parsed, err := service.RequestingPartyToken(ctx, "realm", nil, NewOpenIDConnectTokenRequest(GrantTypeUMA2Ticket), nil, nil)
	if err != nil || !parsed.Valid {
		t.Fatalf("rpt = %#v %v", parsed, err)
	}
	if _, err = service.IntrospectRequestingPartyToken(ctx, "realm", NewBearerTokenProvider("tok"), "raw-rpt"); err != nil {
		t.Fatal(err)
	}
	if _, err = service.ClientEntitlement(ctx, "realm", nil, "app", nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = service.ClientEntitlement(ctx, "old", nil, "app", nil, nil); err != nil {
		t.Fatal(err)
	}
	mode := "custom"
	if _, err = client.openIDConnectToken(ctx, "realm", nil, &OpenIDConnectTokenRequest{GrantType: GrantTypeClientCredentials, ResponseMode: &mode}); err != nil {
		t.Fatal(err)
	}

	if _, err = client.ParseToken(ctx, token.AccessToken, nil); err != nil {
		t.Fatal(err)
	}
	hits = certHits.Load()
	if _, err = client.ParseToken(ctx, token.AccessToken, nil); err != nil {
		t.Fatal(err)
	}
	if certHits.Load() != hits {
		t.Fatalf("cached key was fetched again: %d -> %d", hits, certHits.Load())
	}
	httpReq, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	httpReq.Header.Set(HTTPpHeaderAuthorization, "Bearer "+token.AccessToken)
	if _, err = client.ParseRequestToken(ctx, httpReq, nil); err != nil {
		t.Fatal(err)
	}
	httpReq.Header.Del(HTTPpHeaderAuthorization)
	if _, err = client.ParseRequestToken(ctx, httpReq, nil); err == nil {
		t.Fatal("expected missing bearer")
	}

	parser := NewX509TokenParser(time.Minute)
	base := tokenFrom(t, token.AccessToken)
	base.Header["kid"] = "k2"
	if key, err := parser.Parse(ctx, client, base); err != nil || key == nil {
		t.Fatal(err)
	}
	ecToken := tokenFrom(t, token.AccessToken)
	ecToken.Header["kid"] = "k3"
	ecToken.Method = jwt.SigningMethodES256
	if key, err := parser.Parse(ctx, client, ecToken); err != nil {
		t.Fatal(err)
	} else if _, ok := key.(*ecdsa.PublicKey); !ok {
		t.Fatalf("key = %T", key)
	}
	mismatch := tokenFrom(t, token.AccessToken)
	mismatch.Method = jwt.SigningMethodES256
	if _, err = parser.Parse(ctx, client, mismatch); err == nil {
		t.Fatal("expected key type mismatch")
	}
	missing := tokenFrom(t, unsignedToken(srv.URL+"/realms/missing"))
	missing.Method = jwt.SigningMethodRS256
	missing.Header["kid"] = "k9"
	if _, err = parser.Parse(ctx, client, missing); err == nil {
		t.Fatal("expected missing realm error")
	}

	secret, err := NewClientSecretAuthenticationProvider(ClientSecretProviderConfig{
		AuthServerURL: srv.URL, Realm: "realm", Resource: "app", Secret: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = secret.RequestMutators(ctx, client); err != nil {
		t.Fatal(err)
	}
	if secret.Expired() {
		t.Fatal("token should be current")
	}
	if _, err = secret.Current(ctx, client); err != nil {
		t.Fatal(err)
	}
	secret.tokenExpiry = time.Now().Add(-time.Second)
	secret.tokenRefreshExpiry = time.Now().Add(time.Minute)
	if _, err = secret.Current(ctx, client); err != nil {
		t.Fatal(err)
	}
	badSecret, err := NewClientSecretAuthenticationProvider(ClientSecretProviderConfig{
		AuthServerURL: srv.URL, Realm: "realm", Resource: "app", Secret: "bad",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = badSecret.Current(ctx, client); err == nil {
		t.Fatal("expected secret error")
	}

	resp, err := client.Do(ctx, NewAPIRequest(http.MethodGet, srv.URL+"/certs"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if _, err = client.Do(ctx, NewAPIRequest(http.MethodGet, srv.URL+"/certs"), func(*APIRequest) error {
		return errors.New("mutator")
	}); err == nil {
		t.Fatal("expected mutator error")
	}
	resp, err = client.Call(ctx, NewBearerTokenProvider("tok"), http.MethodGet, srv.URL+"/introspect", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if _, err = client.Call(ctx, failingAuth{}, http.MethodGet, srv.URL+"/introspect", nil); err == nil {
		t.Fatal("expected auth error")
	}
	resp, err = client.callRealms(ctx, "realm", nil, http.MethodGet, "issuer", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	admin, err := NewAdminAPIClient(cfg, "realm", NewBearerTokenProvider("tok"))
	if err != nil || admin.AuthProvider() == nil {
		t.Fatal(err)
	}
	if _, err = NewAdminAPIClientWithProvider(secret, "realm"); err != nil {
		t.Fatal(err)
	}
	if _, err = NewAdminAPIClientWithInstallDocument(&InstallDocument{
		Realm: "realm", AuthServerURL: srv.URL, Resource: "app", Credentials: map[string]string{"secret": "secret"},
	}, "realm"); err != nil {
		t.Fatal(err)
	}
	if _, err = NewAdminAPIClientWithInstallDocument(&InstallDocument{Realm: "realm", AuthServerURL: srv.URL, Resource: "app"}, "realm"); err == nil {
		t.Fatal("expected missing secret")
	}
	trimmed, err := NewAPIClient(&APIClientConfig{AuthServerURLProvider: NewAuthServerURLProvider(srv.URL + "/")})
	if err != nil {
		t.Fatal(err)
	}
	if trimmed.AuthServerURL() != srv.URL {
		t.Fatalf("trimmed = %q", trimmed.AuthServerURL())
	}
	if _, err = NewAPIClient(&APIClientConfig{AuthServerURLProvider: badURL{}}); err == nil {
		t.Fatal("expected url error")
	}
	if _, err = NewAPIClient(nil); err != nil {
		t.Fatal(err)
	}
}

type failingAuth struct{}

func (failingAuth) RequestMutators(context.Context, *APIClient) ([]APIRequestMutator, error) {
	return nil, errors.New("no auth")
}

type badURL struct{}

func (badURL) AuthServerURL() (string, error) { return "", errors.New("no url") }

func realmDoc(base, realm string) string {
	return fmt.Sprintf(`{"issuer":"%s/realms/%s","authorization_endpoint":"%s/auth","token_endpoint":"%s/token","introspection_endpoint":"%s/introspect","userinfo_endpoint":"%s/userinfo","end_session_endpoint":"%s/logout","jwks_uri":"%s/certs","permission_endpoint":"%s/perm","policy_endpoint":"%s/policy","registration_endpoint":"%s/reg","resource_registration_endpoint":"%s/resreg","grant_types_supported":["client_credentials"],"response_types_supported":["code"],"subject_types_supported":["public"],"response_modes_supported":["query"],"token_endpoint_auth_methods_supported":["client_secret_basic"],"token_endpoint_auth_signing_alg_values_supported":["RS256"],"scopes_supported":["openid"]}`,
		base, realm, base, base, base, base, base, base, base, base, base, base)
}

func signToken(t *testing.T, key *rsa.PrivateKey, iss, kid string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": iss,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func tokenFrom(t *testing.T, raw string) *jwt.Token {
	t.Helper()
	token, _, err := new(jwt.Parser).ParseUnverified(raw, &jwt.StandardClaims{})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func testRSA(t *testing.T) (*rsa.PrivateKey, string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := testCert(t, &key.PublicKey, key)
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return key, base64.StdEncoding.EncodeToString(der), base64.StdEncoding.EncodeToString(pub)
}

func testECDSA(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key, base64.StdEncoding.EncodeToString(testCert(t, &key.PublicKey, key))
}

func testCert(t *testing.T, pub interface{}, priv interface{}) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
