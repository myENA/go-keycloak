package keycloak_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/myENA/go-keycloak/v2"
	"github.com/rs/zerolog"
)

const (
	EnvTestConfigFile = "TEST_CONFIG_FILE"
)

type testConfig struct {
	Issuer          string                    `json:"issuer"`
	Realm           string                    `json:"realm"`
	ClientID        string                    `json:"client_id"`
	BearerToken     string                    `json:"bearer_token"`
	InstallDocument *keycloak.InstallDocument `json:"install_document"`
	Logging         struct {
		Enabled bool          `json:"enabled"`
		Level   zerolog.Level `json:"level"`
		Out     string        `json:"out"`
	} `json:"logging"`
}

func getConfig(t *testing.T) *testConfig {
	t.Helper()

	var (
		b   []byte
		f   *os.File
		err error

		fp = os.Getenv(EnvTestConfigFile)

		conf = new(testConfig)
	)

	if fp == "" {
		t.Logf("env %q not defined, looking in default location...", EnvTestConfigFile)
		if cwd, err := os.Getwd(); err != nil {
			t.Logf("unable to get working directory: %v", err)
			t.FailNow()
			return nil
		} else {
			fp = fmt.Sprintf("%s/testdata.json", cwd)
		}
	}

	t.Logf("Using config file %q", fp)

	if f, err = os.OpenFile(fp, os.O_RDONLY, 0); err != nil {
		t.Logf("Error reading config file %q: %v", fp, err)
		t.FailNow()
		return nil
	}

	defer func() { _ = f.Close() }()

	b, _ = ioutil.ReadAll(f)
	if err = json.Unmarshal(b, conf); err != nil {
		t.Logf("Error unmarshalling %q into %T: %v", fp, conf, err)
		t.FailNow()
		return nil
	}

	if conf.Issuer == "" {
		t.Log("Issuer key empty in config")
		t.FailNow()
		return nil
	}

	if conf.Logging.Out == "" {
		conf.Logging.Out = "stdout"
	}

	return conf
}

func buildClientConfigMutators(conf *testConfig, mutators ...keycloak.ConfigMutator) []keycloak.ConfigMutator {
	if mutators == nil {
		mutators = make([]keycloak.ConfigMutator, 0)
	}
	mutators = append(mutators, func(config *keycloak.APIClientConfig) {
		config.AuthServerURLProvider = keycloak.NewAuthServerURLProvider(conf.Issuer)
	})

	return mutators
}

func newClient(t *testing.T, conf *testConfig, mutators ...keycloak.ConfigMutator) *keycloak.APIClient {
	t.Helper()
	var err error

	mutators = buildClientConfigMutators(conf, mutators...)

	cl, err := keycloak.NewAPIClient(nil, mutators...)
	if err != nil {
		t.Logf("Error creating api client: %s", err)
		t.FailNow()
		return nil
	}

	return cl
}

func newBearerTokenClient(t *testing.T, conf *testConfig, mutators ...keycloak.ConfigMutator) *keycloak.TokenAPIClient {
	var (
		cl  *keycloak.APIClient
		tc  *keycloak.TokenAPIClient
		err error

		tcc = new(keycloak.TokenAPIClientConfig)
	)

	if cl = newClient(t, conf, mutators...); cl == nil {
		return nil
	}

	if conf.Realm == "" {
		t.Log("realm key is empty in config")
		t.FailNow()
		return nil
	}

	if conf.BearerToken == "" {
		t.Log("bearer_token key is empty in config")
		t.FailNow()
		return nil
	}

	tcc.RealmProvider = keycloak.NewRealmProvider(conf.Realm, 0)
	tcc.BearerTokenProvider = keycloak.NewBearerTokenProvider(conf.BearerToken)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if tc, err = cl.TokenAPIClient(ctx, tcc); err != nil {
		t.Logf("Error constructing token client: %v", err)
		t.FailNow()
		return nil
	}

	return tc
}

func newConfidentialClientTokenClient(t *testing.T, conf *testConfig, mutators ...keycloak.ConfigMutator) *keycloak.TokenAPIClient {
	var (
		tc  *keycloak.TokenAPIClient
		ctp keycloak.CombinedEnvironmentProvider
		err error

		tpc = new(keycloak.ConfidentialClientTokenProviderConfig)
	)

	tpc.InstallDocument = conf.InstallDocument
	mutators = buildClientConfigMutators(conf, mutators...)

	if conf.InstallDocument == nil {
		t.Logf("install_document key is empty in config")
		t.FailNow()
		return nil
	}

	if ctp, err = keycloak.NewConfidentialClientTokenProvider(tpc); err != nil {
		t.Logf("Error creating new confidential client token provider: %v", err)
		t.FailNow()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if tc, err = keycloak.NewTokenAPIClientWithProvider(ctx, keycloak.CompileAPIClientConfig(nil, mutators...), ctp); err != nil {
		t.Logf("error constructiong token api client: %v", err)
		t.FailNow()
		return nil
	}

	return tc
}

func TestRealmIssuerConfig(t *testing.T) {
	t.Parallel()
	conf := getConfig(t)
	cl := newBearerTokenClient(t, conf)
	if cl == nil || t.Failed() {
		return
	}
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
		conf := getConfig(t)
		cl := newBearerTokenClient(t, conf)
		if cl == nil || t.Failed() {
			return
		}
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
		conf := getConfig(t)
		cl := newBearerTokenClient(t, conf)
		if cl == nil || t.Failed() {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		uma2, err := cl.UMA2Configuration(ctx)
		if err != nil {
			if keycloak.IsAPIError(err) && err.(*keycloak.APIError).ResponseCode != http.StatusNotFound {
				t.Logf("Error fetching UMA2 config: %s", err)
				t.Fail()
			} else {
				t.Skip("It appears your Keycloak instance does not support uma2")
			}
		} else {
			b, _ := json.Marshal(uma2)
			t.Logf("uma2=%s", b)
		}
	})
}

func TestRPT(t *testing.T) {
	t.Parallel()
	conf := getConfig(t)

	if conf.ClientID == "" {
		t.Log("client_id key is empty in test config")
		t.FailNow()
		return
	}

	cl := newBearerTokenClient(t, conf)
	if cl == nil || t.Failed() {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	claims := new(keycloak.StandardClaims)
	tok, err := cl.RequestingPartyToken(ctx, conf.ClientID, claims)
	if err != nil {
		t.Logf("Error fetching RPT: %v", err)
		t.FailNow()
		return
	}

	if !tok.Valid {
		t.Logf("RPT token failed validation: %v", err)
		t.FailNow()
		return
	}
}

func TestConfidentialClientTokenProvider(t *testing.T) {
	t.Parallel()
	conf := getConfig(t)

	if conf.InstallDocument == nil {
		if !t.Failed() {
			t.Skip("No install document configured, cannot test confidential client token provider")
		}
		return
	}

	tc := newConfidentialClientTokenClient(t, conf)
	if tc == nil {
		return
	}

	t.Run("get-token", func(t *testing.T) {
		if _, err := tc.TokenProvider().Current(); err != nil {
			t.Logf("Failed to fetch bearer token from provider: %v", err)
			t.FailNow()
		}
	})

	t.Run("refresh-token", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := tc.TokenProvider().(keycloak.RenewableBearerTokenProvider).Renew(ctx, tc, false); err != nil {

		}
	})
}
