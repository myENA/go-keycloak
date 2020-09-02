package keycloak_test

import (
	"context"
	"encoding/json"
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

func newClient(t *testing.T, mutators ...keycloak.ConfigMutator) *keycloak.APIClient {
	t.Helper()
	var (
		ip  keycloak.IssuerProvider
		err error

		issAddr = os.Getenv(EnvIssuerAddr)
	)

	if issAddr != "" {
		ip = keycloak.NewStaticIssuerProvider(issAddr)
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

	return cl
}

func newRealmClient(t *testing.T, mutators ...keycloak.ConfigMutator) *keycloak.RealmAPIClient {
	var (
		cl  *keycloak.APIClient
		err error

		kcRealm = os.Getenv(EnvKeycloakRealm)
	)

	if cl = newClient(t, mutators...); cl == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	rc, err := cl.RealmAPIClient(ctx, kcRealm)
	if err != nil {
		t.Logf("Error constructing realm client: %v", err)
		t.FailNow()
		return nil
	}

	return rc
}

func newTokenClient(t *testing.T, mutators ...keycloak.ConfigMutator) *keycloak.TokenAPIClient {
	var (
		rc  *keycloak.RealmAPIClient
		tc  *keycloak.TokenAPIClient
		err error

		bearerToken = os.Getenv(EnvBearerToken)
	)

	if bearerToken == "" {
		t.Logf("missing %q env var", EnvBearerToken)
		t.FailNow()
		return nil
	}

	if rc = newRealmClient(t, mutators...); rc == nil {
		return nil
	}

	if tc, err = rc.TokenAPIClient(newStaticTP(bearerToken, rc.RealmName())); err != nil {
		t.Logf("Error constructing token client: %v", err)
		t.FailNow()
		return nil
	}

	return tc
}

func TestRealmIssuerConfig(t *testing.T) {
	t.Parallel()
	cl := newRealmClient(t)
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
		cl := newRealmClient(t)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		oidc, err := cl.OpenIDConfiguration(ctx)
		if err != nil {
			t.Logf("Error fetching OIDC: %s", err)
			t.Fail()
		} else {
			b, _ := json.Marshal(oidc)
			t.Logf("oidc=%s", b)
		}
	})
	t.Run("uma2", func(t *testing.T) {
		t.Parallel()
		cl := newRealmClient(t)
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
			b, _ := json.Marshal(uma2)
			t.Logf("uma2=%s", b)
		}
	})
}

func TestRPT(t *testing.T) {
	t.Parallel()
	cl := newTokenClient(t)
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
