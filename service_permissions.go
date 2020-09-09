package keycloak

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/go-querystring/query"
)

type PermissionsService struct {
	tc *TokenAPIClient
}

func (tc *TokenAPIClient) PermissionsService() *PermissionsService {
	ps := new(PermissionsService)
	ps.tc = tc
	return ps
}

// Evaluate will return an array of permissions granted by the server
func (ps *PermissionsService) Evaluate(ctx context.Context, req *OpenIDConnectTokenRequest) (EvaluatedPermissions, error) {
	var (
		body  url.Values
		resp  *http.Response
		perms EvaluatedPermissions
		err   error

		mode = UMA2ResponseModePermissions
	)
	req.ResponseMode = &mode
	if body, err = query.Values(req); err != nil {
		return nil, fmt.Errorf("error encoding request: %w", err)
	}
	resp, err = ps.tc.Call(
		ctx,
		http.MethodPost,
		ps.tc.realmEnv.TokenEndpoint(),
		strings.NewReader(body.Encode()),
		HeaderMutator(httpHeaderContentType, httpHeaderValueFormURLEncoded, true))
	perms = make(EvaluatedPermissions, 0)
	if err = handleResponse(resp, http.StatusOK, &perms, err); err != nil {
		return nil, err
	}
	return perms, nil
}

// Decide can be used to determine whether a bearer token is allowed the permission requested
func (ps *PermissionsService) Decide(ctx context.Context, req *OpenIDConnectTokenRequest) (bool, error) {
	type respT struct {
		Result bool `json:"result"`
	}
	var (
		body url.Values
		resp *http.Response
		err  error

		decision = new(respT)
		mode     = UMA2ResponseModeDecision
	)
	req.ResponseMode = &mode
	if body, err = query.Values(req); err != nil {
		return false, fmt.Errorf("error encoding request: %w", err)
	}
	resp, err = ps.tc.callRealms(
		ctx,
		http.MethodPost,
		ps.tc.realmEnv.TokenEndpoint(),
		strings.NewReader(body.Encode()),
		HeaderMutator(httpHeaderContentType, httpHeaderValueFormURLEncoded, true))
	if err = handleResponse(resp, http.StatusOK, decision, err); err != nil {
		return false, err
	}
	return decision.Result, nil
}

// RequestingPartyToken will attempt to automatically decode and validate a RPT returned from an OIDC token request
func (ps *PermissionsService) RequestingPartyToken(ctx context.Context, req *OpenIDConnectTokenRequest, claimsType jwt.Claims, mutators ...RequestMutator) (*jwt.Token, error) {
	req.ResponseMode = nil
	resp, err := ps.tc.OpenIDConnectToken(ctx, req, mutators...)
	if err != nil {
		return nil, err
	}
	return ps.tc.ParseToken(ctx, resp.AccessToken, claimsType)
}
