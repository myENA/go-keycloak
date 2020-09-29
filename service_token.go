package keycloak

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/google/go-querystring/query"
)

type TokenService struct {
	c *APIClient
}

func (c *APIClient) TokenService() *TokenService {
	ps := new(TokenService)
	ps.c = c
	return ps
}

// ClientEntitlement will attempt to call the pre-uma2 entitlement endpoint to return a Requesting Party Token
// containing details about what aspects of the provided clientID the token for this request has access to, if any.
// DEPRECATED: use the newer token workflow for instances newer than 3.4
func (ts *TokenService) ClientEntitlement(ctx context.Context, realmName string, ap AuthProvider, clientID string, claimsType jwt.Claims, mutators ...APIRequestMutator) (*jwt.Token, error) {
	var (
		resp *http.Response
		env  *RealmEnvironment
		err  error
	)
	if env, err = ts.c.RealmEnvironment(ctx, realmName); err != nil {
		return nil, err
	}
	// if the keycloak instance supports uma2, use that.
	if env.SupportsUMA2() {
		req := NewOpenIDConnectTokenRequest(GrantTypeUMA2Ticket)
		req.Audience = clientID
		return ts.RequestingPartyToken(ctx, realmName, ap, req, claimsType, mutators...)
	}

	// otherwise, execute legacy entitlement api
	rptResp := new(struct {
		RPT string `json:"rpt"`
	})
	resp, err = ts.c.Call(
		ctx,
		ap,
		http.MethodGet,
		ts.c.realmsURL(kcPathPartAuthz, kcPathPartEntitlement, clientID),
		nil,
		HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
	)
	if err = handleResponse(resp, http.StatusOK, rptResp, err); err != nil {
		return nil, err
	}
	return ts.c.ParseToken(ctx, rptResp.RPT, claimsType)
}

// PermissionEvaluation will return an array of permissions granted by the server
func (ts *TokenService) PermissionEvaluation(ctx context.Context, realmName string, ap AuthProvider, req *OpenIDConnectTokenRequest, mutators ...APIRequestMutator) (EvaluatedPermissions, error) {
	var (
		body  url.Values
		resp  *http.Response
		env   *RealmEnvironment
		perms EvaluatedPermissions
		err   error

		mode = UMA2ResponseModePermissions
	)
	if env, err = ts.c.RealmEnvironment(ctx, realmName); err != nil {
		return nil, err
	}
	req.ResponseMode = &mode
	if body, err = query.Values(req); err != nil {
		return nil, fmt.Errorf("error encoding request: %w", err)
	}
	resp, err = ts.c.Call(
		ctx,
		ap,
		http.MethodPost,
		env.TokenEndpoint(),
		strings.NewReader(body.Encode()),
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
			HeaderMutator(httpHeaderContentType, httpHeaderValueFormURLEncoded, true),
		)...,
	)
	perms = make(EvaluatedPermissions, 0)
	if err = handleResponse(resp, http.StatusOK, &perms, err); err != nil {
		return nil, err
	}
	return perms, nil
}

// PermissionDecision can be used to determine whether a bearer token is allowed the permission requested
func (ts *TokenService) PermissionDecision(ctx context.Context, realmName string, ap AuthProvider, req *OpenIDConnectTokenRequest, mutators ...APIRequestMutator) (*PermissionDecisionResponse, error) {
	var (
		res  interface{}
		resT *PermissionDecisionResponse
		ok   bool
		err  error

		mode = UMA2ResponseModeDecision
	)
	req.ResponseMode = &mode
	if res, err = ts.c.openIDConnectToken(ctx, realmName, ap, req, mutators...); err != nil {
		if IsAPIError(err) && err.(*APIError).ResponseCode != http.StatusForbidden {
			return nil, err
		}
		return &PermissionDecisionResponse{Result: false}, err
	}
	if resT, ok = res.(*PermissionDecisionResponse); !ok {
		return nil, fmt.Errorf("expected response to be %T, saw %T", resT, res)
	}
	return resT, nil
}

func (ts *TokenService) OpenIDConnectToken(ctx context.Context, realmName string, ap AuthProvider, req *OpenIDConnectTokenRequest, mutators ...APIRequestMutator) (*OpenIDConnectToken, error) {
	var (
		res   interface{}
		token *OpenIDConnectToken
		ok    bool
		err   error
	)
	req.ResponseMode = nil
	if res, err = ts.c.openIDConnectToken(ctx, realmName, ap, req, mutators...); err != nil {
		return nil, err
	}
	if token, ok = res.(*OpenIDConnectToken); !ok {
		return nil, fmt.Errorf("expected response to be %T, saw %T", token, res)
	}
	return token, nil
}

// RequestingPartyToken will attempt to automatically decode and validate a RPT returned from an OIDC token request
func (ts *TokenService) RequestingPartyToken(ctx context.Context, realmName string, ap AuthProvider, req *OpenIDConnectTokenRequest, claimsType jwt.Claims, mutators ...APIRequestMutator) (*jwt.Token, error) {
	req.ResponseMode = nil
	resp, err := ts.OpenIDConnectToken(ctx, realmName, ap, req, mutators...)
	if err != nil {
		return nil, err
	}
	return ts.c.ParseToken(ctx, resp.AccessToken, claimsType)
}

func (ts *TokenService) IntrospectRequestingPartyToken(ctx context.Context, realmName string, ap AuthProvider, rawRPT string, mutators ...APIRequestMutator) (*TokenIntrospectionResults, error) {
	var (
		body    url.Values
		resp    *http.Response
		results *TokenIntrospectionResults
		env     *RealmEnvironment
		err     error
	)
	if env, err = ts.c.RealmEnvironment(ctx, realmName); err != nil {
		return nil, err
	}
	body = make(url.Values)
	body.Add(paramTokenTypeHint, TokenTypeHintRequestingPartyToken)
	body.Add(paramTypeToken, rawRPT)
	resp, err = ts.c.Call(
		ctx,
		ap,
		http.MethodPost,
		env.IntrospectionEndpoint(),
		strings.NewReader(body.Encode()),
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
			HeaderMutator(httpHeaderContentType, httpHeaderValueFormURLEncoded, true),
		)...,
	)
	results = new(TokenIntrospectionResults)
	if err = handleResponse(resp, http.StatusOK, results, err); err != nil {
		return nil, err
	}
	return results, nil
}
