package keycloak

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/google/go-querystring/query"
)

type PermissionsService struct {
	as *AuthService
}

func NewPermissionsService(as *AuthService) *PermissionsService {
	ps := new(PermissionsService)
	ps.as = as
	return ps
}

func (as *AuthService) Permissions() *PermissionsService {
	return NewPermissionsService(as)
}

// Evaluate will return an array of permissions granted by the server
func (b *PermissionsService) Evaluate(ctx context.Context, req *OpenIDConnectTokenRequest) (EvaluatedPermissions, error) {
	var (
		body  url.Values
		resp  *http.Response
		perms EvaluatedPermissions
		err   error
	)
	if body, err = query.Values(req); err != nil {
		return nil, fmt.Errorf("error encoding request: %w", err)
	}
	body.Set(paramResponseMode, ResponseModePermissions)
	resp, err = b.as.callRealms(
		ctx,
		http.MethodPost,
		path.Join(oidcTokenBits...),
		strings.NewReader(body.Encode()),
		HeaderMutator(httpHeaderContentType, httpHeaderValueFormURLEncoded, true))
	perms = make(EvaluatedPermissions, 0)
	if err = handleResponse(resp, http.StatusOK, &perms, err); err != nil {
		return nil, err
	}
	return perms, nil
}

// Decide can be used to determine whether a bearer token is allowed the permission requested
func (b *PermissionsService) Decide(ctx context.Context, req *OpenIDConnectTokenRequest) (bool, error) {
	type respT struct {
		Result bool `json:"result"`
	}
	var (
		body url.Values
		resp *http.Response
		err  error

		decision = new(respT)
	)
	if body, err = query.Values(req); err != nil {
		return false, fmt.Errorf("error encoding request: %w", err)
	}
	body.Set(paramResponseMode, ResponseModeDecision)
	resp, err = b.as.callRealms(
		ctx,
		http.MethodPost,
		path.Join(oidcTokenBits...),
		strings.NewReader(body.Encode()),
		HeaderMutator(httpHeaderContentType, httpHeaderValueFormURLEncoded, true))
	if err = handleResponse(resp, http.StatusOK, decision, err); err != nil {
		return false, err
	}
	return decision.Result, nil
}
