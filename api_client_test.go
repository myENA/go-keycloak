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

type staticTP struct {
	token string
	realm string
}

func (tp staticTP) TargetRealm() string {
	return tp.realm
}

func (tp staticTP) BearerToken() (string, error) {
	return tp.token, nil
}

func newStaticTP(token, realm string) staticTP {
	return staticTP{token, realm}
}

func newClient(t *testing.T, mutators ...keycloak.ConfigMutator) *keycloak.TokenAPIClient {
	t.Helper()
	var (
		ip  keycloak.IssuerProvider
		tp  keycloak.FixedRealmTokenProvider
		err error

		issAddr     = os.Getenv(EnvIssuerAddr)
		kcRealm     = os.Getenv(EnvKeycloakRealm)
		bearerToken = os.Getenv(EnvBearerToken)
	)

	if issAddr != "" {
		ip = keycloak.NewStaticIssuerProvider(issAddr)
	}

	if bearerToken != "" {
		tp = newStaticTP(bearerToken, kcRealm)
		t.Logf("Using test-only StaticTokenProvider with token: %s", bearerToken)
	}

	if mutators == nil {
		mutators = make([]keycloak.ConfigMutator, 0)
	}
	mutators = append(
		mutators,
		func(config *keycloak.APIClientConfig) {
			config.IssuerProvider = ip
		},
	)

	cl, err := keycloak.NewAPIClient(nil, mutators...)
	if err != nil {
		t.Logf("Error creating api client: %s", err)
		t.FailNow()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tcl, err := cl.TokenAPIClientFromProvider(ctx, tp)
	if err != nil {
		t.Logf("Error creating token api client: %v", err)
		t.FailNow()
		return nil
	}

	return tcl
}

func TestRealmIssuerConfig(t *testing.T) {
	t.Parallel()
	cl := newClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	config, err := cl.RealmIssuerConfiguration(ctx)
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
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		oidc, err := cl.OpenIDConfiguration(ctx)
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
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		uma2, err := cl.UMA2Configuration(ctx)
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
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req := keycloak.NewOpenIDConnectTokenRequest(keycloak.GrantTypeUMA2Ticket)
	req.Audience = cid
	_, err := cl.OpenIDConnectToken(ctx, req)
	if err != nil {
		t.Logf("Error fetching RPT: %s", err)
		t.Fail()
	}
}
