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
)

const (
	EnvTestConfigFile = "TEST_CONFIG_FILE"
)

type testConfig struct {
	Name         string `json:"name"`
	ClientConfig struct {
		Cred *struct {
			BearerToken     string                    `json:"bearer_token"`
			InstallDocument *keycloak.InstallDocument `json:"install_document"`
		} `json:"cred"`
		NoCred *struct {
			AuthServerURL string `json:"auth_server_url"`
			RealmName     string `json:"realm_name"`
		} `json:"no_cred"`
	} `json:"client_config"`
	ClientID               string `json:"client_id"`
	Strategy               string `json:"strategy"`
	Audience               string `json:"audience"`
	ExpectedDecisionResult bool   `json:"expected_decision_result"`
	Permissions            []struct {
		Resource string `json:"resource"`
		Scope    string `json:"scope"`
	}
}

func getTestConfigs(t *testing.T) []*testConfig {
	t.Helper()

	var (
		b   []byte
		f   *os.File
		err error

		fp = os.Getenv(EnvTestConfigFile)

		configs = make([]*testConfig, 0)
	)

	if fp == "" {
		t.Logf("env %q not defined, looking in default location...", EnvTestConfigFile)
		if cwd, err := os.Getwd(); err != nil {
			t.Logf("unable to get working directory: %v", err)
			t.FailNow()
			return nil
		} else {
			fp = fmt.Sprintf("%s/test_configs.json", cwd)
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
	if err = json.Unmarshal(b, &configs); err != nil {
		t.Logf("Error unmarshalling %q into %T: %v", fp, configs, err)
		t.FailNow()
		return nil
	}

	return configs
}

func newClient(t *testing.T, testConfig *testConfig, mutators ...keycloak.ConfigMutator) *keycloak.APIClient {
	t.Helper()
	var (
		cl  *keycloak.APIClient
		err error
	)

	if testConfig.Name == "" {
		t.Log("Config entry missing \"name\" field")
		t.FailNow()
		return nil
	}

	if mutators == nil {
		mutators = make([]keycloak.ConfigMutator, 0)
	}

	if testConfig.ClientConfig.Cred == nil && testConfig.ClientConfig.NoCred == nil {
		t.Logf("Test %q has nil cred and no_cred entries (one required)", testConfig.Name)
		t.FailNow()
		return nil
	}

	if testConfig.ClientConfig.Cred != nil && testConfig.ClientConfig.NoCred != nil {
		t.Logf("Test %q has non-nil cred and no_cred entries (only 1 allowed)", testConfig.Name)
		t.FailNow()
		return nil
	}

	if testConfig.ClientConfig.Cred != nil {
		if testConfig.ClientConfig.Cred.BearerToken != "" {
			cl, err = keycloak.NewAPIClientWithBearerToken(testConfig.ClientConfig.Cred.BearerToken)
		} else if testConfig.ClientConfig.Cred.InstallDocument != nil {
			cl, err = keycloak.NewAPIClientWithInstallDocument(testConfig.ClientConfig.Cred.InstallDocument)
		} else {
			t.Logf("Test %q does not have usable cred defined", testConfig.Name)
			t.FailNow()
			return nil
		}
	} else {
		if testConfig.ClientConfig.NoCred.AuthServerURL == "" {
			t.Logf("Test %q no_cred has empty auth_server_url field", testConfig.Name)
			t.FailNow()
			return nil
		}
		if testConfig.ClientConfig.NoCred.RealmName == "" {
			t.Logf("Test %q no_cred has empty realm_name field", testConfig.Name)
			t.FailNow()
			return nil
		}
		clientConfig := keycloak.DefaultAPIClientConfig()
		clientConfig.AuthServerURLProvider = keycloak.NewAuthServerURLProvider(testConfig.ClientConfig.NoCred.AuthServerURL)
		clientConfig.RealmProvider = keycloak.NewStaticRealmProvider(testConfig.ClientConfig.NoCred.RealmName)
		cl, err = keycloak.NewAPIClient(clientConfig, mutators...)
	}

	if err != nil {
		t.Logf("Error building client for test %q: %v", testConfig.Name, err)
		t.FailNow()
		return nil
	}

	return cl
}

func wrapTestFunc(testConfig *testConfig, testFunc func(*testing.T, *testConfig)) func(*testing.T) {
	return func(t *testing.T) {
		testFunc(t, testConfig)
	}
}

func TestAPIClient(t *testing.T) {
	conf := getTestConfigs(t)
	if t.Failed() {
		return
	}

testLoop:
	for i, tc := range conf {
		var testFunc func(*testing.T, *testConfig)
		switch tc.Name {
		case "issuer-config":
			testFunc = testGetIssuerConfig
		case "well-known-configs":
			testFunc = testWellKnownConfigs
		case "client-entitlement-confidential", "client-entitlement-bearer":
			testFunc = testClientEntitlement
		default:
			t.Logf("No test case to handle entry %d %q", i, tc.Name)
			t.Fail()
			continue testLoop
		}

		t.Run(tc.Name, wrapTestFunc(tc, testFunc))
	}
}

func testGetIssuerConfig(t *testing.T, conf *testConfig) {
	t.Parallel()
	cl := newClient(t, conf)
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

func testWellKnownConfigs(t *testing.T, conf *testConfig) {
	t.Run("oidc", func(t *testing.T) {
		t.Parallel()
		cl := newClient(t, conf)
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
		cl := newClient(t, conf)
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

func testClientEntitlement(t *testing.T, conf *testConfig) {
	t.Parallel()
	if conf.ClientID == "" {
		t.Log("client_id key is empty in test config")
		t.FailNow()
		return
	}

	cl := newClient(t, conf)
	if cl == nil || t.Failed() {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	claims := new(keycloak.StandardClaims)
	tok, err := cl.TokenService().ClientEntitlement(ctx, conf.ClientID, claims)
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
