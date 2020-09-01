package keycloak_test

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/myENA/go-keycloak/v2"
)

const (
	EnvIssuerAddr       = "ISSUER_ADDR"
	EnvKeycloakRealm    = "KEYCLOAK_REALM"
	EnvKeycloakClientID = "KEYCLOAK_CLIENT_ID"
	EnvBearerToken      = "BEARER_TOKEN"
)

func usableClientID(t *testing.T) string {
	t.Helper()
	cid := os.Getenv(EnvKeycloakClientID)
	if cid == "" {
		t.Log("No usable Client ID found")
		t.FailNow()
	}
	t.Logf("Using %q for Keycloak Client ID", cid)
	return cid
}

type staticTP string

func (tp *staticTP) BearerToken(ctx context.Context, _ *keycloak2.RealmAPIClient) (string, error) {
	return keycloak.TokenContext(ctx, string(*tp)), nil
}

func newClient(t *testing.T, mutators ...keycloak.ConfigMutator) *keycloak.APIClient {
	t.Helper()
	var (
		ip  keycloak.IssuerProvider
		rp  keycloak.RealmConfigurationProvider
		tp  keycloak.TokenProvider
		err error

		issAddr = os.Getenv(EnvIssuerAddr)
		kcRealm = os.Getenv(EnvKeycloakRealm)
		bt      = os.Getenv(EnvBearerToken)
	)

	if issAddr != "" {
		ip = keycloak.NewStaticIssuerProvider(issAddr)
	}

	if kcRealm != "" {
		rp = keycloak.NewSimpleRealmConfigProvider(kcRealm)
		t.Logf("Using SimpleRealmConfigurationProvider with realm %q", kcRealm)
	}

	if bt != "" {
		stp := new(staticTP)
		*stp = staticTP(bt)
		tp = stp
		t.Logf("Using test-only StaticTokenProvider with token: %s", bt)
	}

	conf := keycloak.DefaultAPIClientConfig()
	conf.IssuerProvider = ip
	conf.RealmProvider = rp
	conf.TokenProvider = tp

	cl, err := keycloak.NewAPIClient(conf, mutators...)
	if err != nil {
		t.Logf("Error creating client: %s", err)
		t.FailNow()
	}
	return cl
}

func TestRealmIssuerConfig(t *testing.T) {
	t.Parallel()
	cl := newClient(t)
	ks := cl.AuthService()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	config, err := ks.RealmIssuerConfiguration(ctx)
	if err != nil {
		t.Logf("Error fetching Realm Issuer Configuration: %s", err)
		t.Fail()
	} else {
		t.Logf("config=%v", config)
	}
}

func TestWellKnownConfigs(t *testing.T) {
	t.Run("oidc", func(t *testing.T) {
		t.Parallel()
		cl := newClient(t)
		ks := cl.AuthService()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		oidc, err := ks.OpenIDConfiguration(ctx)
		if err != nil {
			t.Logf("Error fetching OIDC: %s", err)
			t.Fail()
		} else {
			t.Logf("oidc=%v", oidc)
		}
	})
	t.Run("uma2", func(t *testing.T) {
		t.Parallel()
		cl := newClient(t)
		ks := cl.AuthService()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		uma2, err := ks.UMA2Configuration(ctx)
		if err != nil {
			if keycloak.IsAPIError(err) && err.(*keycloak.APIError).ResponseCode != http.StatusNotFound {
				t.Logf("Error fetching UMA2 config: %s", err)
				t.Fail()
			}
			t.Log("It appears your Keycloak instance does not support uma2")
		} else {
			t.Logf("uma2=%v", uma2)
		}
	})
}

func TestRPT(t *testing.T) {
	t.Parallel()
	cl := newClient(t)
	cid := usableClientID(t)
	ks := cl.AuthService()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ctx, err := cl.RequireToken(ctx)
	if err != nil {
		t.Logf("Error requiring token: %v", err)
		t.FailNow()
		return
	}

	_, ok := keycloak.ContextToken(ctx)
	if !ok {
		t.Log("Token missing from context")
		t.FailNow()
		return
	}

	req := keycloak.NewOpenIDConnectTokenRequest(keycloak.GrantTypeUMA2Ticket)
	req.Audience = cid
	_, err = ks.OpenIDConnectToken(ctx, req)
	if err != nil {
		t.Logf("Error fetching RPT: %s", err)
		t.Fail()
	}
}
