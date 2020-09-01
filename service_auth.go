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

// OpenIDConnectToken is the starting point for all authorization requests
func (b *baseService) OpenIDConnectToken(ctx context.Context, req *OpenIDConnectTokenRequest) (*OpenIDConnectToken, error) {
	var (
		requestPath string
		body        url.Values
		resp        *http.Response
		token       *OpenIDConnectToken
		err         error
	)
	if ctx, err = b.c.RequireRealm(ctx); err != nil {
		return nil, err
	}
	if requestPath, err = b.realmsPath(ctx, oidcTokenBits...); err != nil {
		return nil, err
	}
	if body, err = query.Values(req); err != nil {
		return nil, fmt.Errorf("error encoding request: %w", err)
	}
	fmt.Println(body.Encode())
	resp, err = b.c.Call(
		ctx,
		http.MethodPost,
		requestPath,
		strings.NewReader(body.Encode()),
		HeaderMutator(httpHeaderContentType, httpHeaderValueFormURLEncoded, true))
	token = new(OpenIDConnectToken)
	if err = handleResponse(resp, http.StatusOK, token, err); err != nil {
		return nil, err
	}
	return token, nil
}

func (b *baseService) IntrospectRequestingPartyToken(ctx context.Context, rawRPT string) (*TokenIntrospectionResults, error) {
	var (
		requestPath string
		body        url.Values
		resp        *http.Response
		results     *TokenIntrospectionResults
		err         error
	)
	if ctx, err = b.c.RequireRealm(ctx); err != nil {
		return nil, err
	}
	if requestPath, err = b.realmsPath(ctx, oidcTokenIntrospectBits...); err != nil {
		return nil, err
	}
	body = make(url.Values)
	body.Add(paramTokenTypeHint, TokenTypeHintRequestingPartyToken)
	body.Add(paramTypeToken, rawRPT)
	resp, err = b.c.Call(
		ctx,
		http.MethodPost,
		requestPath,
		strings.NewReader(body.Encode()),
		HeaderMutator(httpHeaderContentType, httpHeaderValueFormURLEncoded, true))
	results = new(TokenIntrospectionResults)
	if err = handleResponse(resp, http.StatusOK, results, err); err != nil {
		return nil, err
	}
	return results, nil
}

// ClientEntitlement will attempt to call the pre-uma2 entitlement endpoint to return a Requesting Party Token
// containing details about what aspects of the provided clientID the token for this request has access to, if any.
// DEPRECATED: use the newer introspection workflow for  instances newer than 3.4
func (b *baseService) ClientEntitlement(ctx context.Context, clientID string, claimsType jwt.Claims) (*jwt.Token, error) {
	var (
		resp *http.Response
		err  error

		rptResp = new(struct {
			RPT string `json:"rpt"`
		})
	)

	// construct context fully, including token, realm, and issuer address
	if ctx, err = b.c.RequireAllContextValues(ctx); err != nil {
		return nil, err
	}
	ctx = IssuerAddressContext(ctx, b.c.IssuerAddress())

	// compile request path manually based on above context
	requestPath, err := b.realmsPath(ctx, path.Join(kcPathPrefixEntitlement, clientID))
	if err != nil {
		return nil, err
	}

	// execute request.
	resp, err = b.c.Call(ctx, http.MethodGet, requestPath, nil)
	if err = handleResponse(resp, http.StatusOK, rptResp, err); err != nil {
		return nil, err
	}

	return b.ParseToken(ctx, rptResp.RPT, claimsType)
}

func (b *baseService) callRealms(ctx context.Context, method, requestPath string, body interface{}, mutators ...RequestMutator) (*http.Response, error) {
	var err error
	if ctx, err = b.c.RequireAllContextValues(ctx); err != nil {
		return nil, err
	}
	requestPath, err = b.realmsPath(ctx, requestPath)
	if err != nil {
		return nil, err
	}
	return b.c.Call(ctx, method, requestPath, body, mutators...)
}
