package keycloak

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/go-querystring/query"
)

type baseService struct {
	c *APIClient
}

func newBaseService(c *APIClient) *baseService {
	kc := new(baseService)
	kc.c = c
	return kc
}

type AuthService struct {
	*baseService
}

func NewAuthService(client *APIClient) *AuthService {
	as := new(AuthService)
	as.baseService = newBaseService(client)
	return as
}

// RealmIssuerConfiguration returns metadata about the  instance being connected to, such as the public key for
// token signing
func (k *baseService) RealmIssuerConfiguration(ctx context.Context) (*RealmIssuerConfiguration, error) {
	var (
		requestPath string
		resp        *http.Response
		ic          *RealmIssuerConfiguration
		err         error
	)
	if ctx, err = k.c.requireRealm(ctx); err != nil {
		return nil, err
	}
	if requestPath, err = k.realmsPath(ctx); err != nil {
		return nil, err
	}
	if resp, err = k.c.CallRequireOK(ctx, http.MethodGet, requestPath, nil); err != nil {
		return nil, err
	}
	ic = new(RealmIssuerConfiguration)
	if err = handleResponse(resp, ic); err != nil {
		return nil, err
	}
	return ic, nil
}

// OpenIDConfiguration returns OpenID Configuration metadata about a realm in the  instance being connected
// to.  This endpoint exists across both 3.4 and newer versions of .
func (k *baseService) OpenIDConfiguration(ctx context.Context) (*OpenIDConfiguration, error) {
	var (
		requestPath string
		resp        *http.Response
		oidc        *OpenIDConfiguration
		err         error
	)
	if ctx, err = k.c.requireRealm(ctx); err != nil {
		return nil, err
	}
	if requestPath, err = k.realmsPath(ctx, kcPathOIDC); err != nil {
		return nil, err
	}
	if resp, err = k.c.CallRequireOK(ctx, http.MethodGet, requestPath, nil); err != nil {
		return nil, err
	}
	oidc = new(OpenIDConfiguration)
	if err = handleResponse(resp, oidc); err != nil {
		return nil, err
	}
	return oidc, nil
}

// UMA2Configuration returns UMA2 configuration metadata about a realm in the  instance being connected to.
// This endpoint only exists in versions of  newer than 4
func (k *baseService) UMA2Configuration(ctx context.Context) (*UMA2Configuration, error) {
	var (
		requestPath string
		resp        *http.Response
		uma2c       *UMA2Configuration
		err         error
	)
	if ctx, err = k.c.requireRealm(ctx); err != nil {
		return nil, err
	}
	if requestPath, err = k.realmsPath(ctx, kcPathUMA2C); err != nil {
		return nil, err
	}
	if resp, err = k.c.CallRequireOK(ctx, http.MethodGet, requestPath, nil); err != nil {
		return nil, err
	}
	uma2c = new(UMA2Configuration)
	if err = handleResponse(resp, uma2c); err != nil {
		return nil, err
	}
	return uma2c, err
}

// OpenIDConnectToken is the starting point for all authorization requests
func (k *baseService) OpenIDConnectToken(ctx context.Context, req OpenIDConnectTokenRequest) (*OpenIDConnectToken, error) {
	var (
		requestPath string
		body        url.Values
		resp        *http.Response
		token       *OpenIDConnectToken
		err         error
	)
	if ctx, err = k.c.requireRealm(ctx); err != nil {
		return nil, err
	}
	if requestPath, err = k.realmsPath(ctx, confidentialClientTokenBits...); err != nil {
		return nil, err
	}
	if body, err = query.Values(req); err != nil {
		return nil, fmt.Errorf("error encoding request: %w", err)
	}
	resp, err = k.c.CallRequireOK(
		ctx,
		http.MethodPost,
		requestPath,
		strings.NewReader(body.Encode()),
		HeaderMutator(httpHeaderContentType, httpHeaderValueFormURLEncoded, true))
	if err != nil {
		return nil, err
	}
	token = new(OpenIDConnectToken)
	if err = handleResponse(resp, token); err != nil {
		return nil, err
	}
	return token, nil
}

// ParseToken will attempt to parse and validate a raw token into a modeled type.  If this method does not return
// an error, you can safely assume the provided raw token is safe for use.
func (k *baseService) ParseToken(ctx context.Context, rawToken string, claimsType jwt.Claims) (*jwt.Token, error) {
	var (
		jwtToken *jwt.Token
		err      error
	)
	if ctx, err = k.c.requireRealm(ctx); err != nil {
		return nil, err
	}
	ctx = IssuerAddressContext(ctx, k.c.IssuerAddress())
	if jwtToken, err = jwt.ParseWithClaims(rawToken, claimsType, k.keyFunc(ctx)); err != nil {
		return nil, fmt.Errorf("error parsing raw token into %T: %w", claimsType, err)
	}
	return jwtToken, nil
}

// ClientEntitlement will attempt to call the pre-uma2 entitlement endpoint to return a Requesting Party Token
// containing details about what aspects of the provided clientID the token for this request has access to, if any.
// DEPRECATED: use the newer introspection workflow for  instances newer than 3.4
func (k *baseService) ClientEntitlement(ctx context.Context, clientID string) (*RequestingPartyToken, error) {
	var (
		resp   *http.Response
		parsed *jwt.Token
		err    error

		rptResp = new(struct {
			RPT string `json:"rpt"`
		})
	)

	// construct context fully, including token, realm, and issuer address
	if ctx, err = k.c.requireAllContextValues(ctx); err != nil {
		return nil, err
	}
	ctx = IssuerAddressContext(ctx, k.c.IssuerAddress())

	// compile request path manually based on above context
	requestPath, err := k.realmsPath(ctx, path.Join(kcPathPrefixEntitlement, clientID))
	if err != nil {
		return nil, err
	}

	// execute request.
	if resp, err = k.c.CallRequireOK(ctx, http.MethodGet, requestPath, nil); err != nil {
		return nil, err
	}

	if err = handleResponse(resp, rptResp); err != nil {
		return nil, err
	}

	if parsed, err = k.ParseToken(ctx, rptResp.RPT, new(RequestingPartyToken)); err != nil {
		return nil, err
	}

	return parsed.Claims.(*RequestingPartyToken), nil
}

// TODO: add this as method on TokenParser?
func (k *baseService) keyFunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		return k.c.pp.Parse(ctx, k.c, token)
	}
}

// apiPath builds a request path under the /auth... path
func (k baseService) apiPath(bits ...string) string {
	if len(bits) == 0 {
		return k.c.pathPrefix
	}
	return fmt.Sprintf(apiPathFormat, k.c.pathPrefix, path.Join(bits...))
}

// realmsPath builds a request path under the /realms/{realm}/... path
func (k *baseService) realmsPath(ctx context.Context, bits ...string) (string, error) {
	if realm, ok := contextStringValue(ctx, ContextKeyRealm); ok {
		return fmt.Sprintf(kcURLPathRealmsFormat, k.c.pathPrefix, realm, path.Join(bits...)), nil
	}
	return "", errors.New("context does not contain realm value")
}

func (k *baseService) callRealms(ctx context.Context, method, requestPath string, body interface{}, mutators ...RequestMutator) (*http.Response, error) {
	var err error
	if ctx, err = k.c.requireAllContextValues(ctx); err != nil {
		return nil, err
	}
	requestPath, err = k.realmsPath(ctx, requestPath)
	if err != nil {
		return nil, err
	}
	return k.c.Call(ctx, method, requestPath, body, mutators...)
}

func (k *baseService) callRealmsRequireOK(ctx context.Context, method, requestPath string, body interface{}, mutators ...RequestMutator) (*http.Response, error) {
	var err error
	if ctx, err = k.c.requireAllContextValues(ctx); err != nil {
		return nil, err
	}
	requestPath, err = k.realmsPath(ctx, requestPath)
	if err != nil {
		return nil, err
	}
	return k.c.CallRequireOK(ctx, method, requestPath, body, mutators...)
}
