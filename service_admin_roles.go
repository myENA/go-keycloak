package keycloak

import (
	"context"
	"net/http"
	"path"
)

type AdminRolesService struct {
	tc *AdminTokenAPIClient
}

func (tc *AdminTokenAPIClient) RolesService() *AdminRolesService {
	rs := new(AdminRolesService)
	rs.tc = tc
	return rs
}

func (rs *AdminRolesService) List(ctx context.Context, mutators ...RequestMutator) (Roles, error) {
	var (
		resp  *http.Response
		roles Roles
		err   error
	)
	resp, err = rs.tc.callAdminRealms(ctx, http.MethodGet, kcPathPartRoles, nil, mutators...)
	roles = make(Roles, 0)
	if err = handleResponse(resp, http.StatusOK, &roles, err); err != nil {
		return nil, err
	}
	return roles, nil
}

func (rs *AdminRolesService) Create(ctx context.Context, role *Role, mutators ...RequestMutator) ([]string, error) {
	var (
		resp *http.Response
		err  error
	)
	resp, err = rs.tc.callAdminRealms(ctx, http.MethodPost, kcPathPartRoles, role, mutators...)
	if err = handleResponse(resp, http.StatusOK, nil, err); err != nil {
		return nil, err
	}
	return parseResponseLocations(resp)
}

func (rs *AdminRolesService) Get(ctx context.Context, roleName string, mutators ...RequestMutator) (*Role, error) {
	var (
		resp *http.Response
		role *Role
		err  error
	)
	resp, err = rs.tc.callAdminRealms(ctx, http.MethodGet, path.Join(kcPathPartRoles, roleName), nil, mutators...)
	role = new(Role)
	if err = handleResponse(resp, http.StatusOK, role, err); err != nil {
		return nil, err
	}
	return role, nil
}

func (rs *AdminRolesService) Update(ctx context.Context, roleName string, role *Role, mutators ...RequestMutator) error {
	resp, err := rs.tc.callAdminRealms(ctx, http.MethodPut, path.Join(kcPathPartRoles, roleName), role, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}

func (rs *AdminRolesService) Delete(ctx context.Context, roleName string, mutators ...RequestMutator) error {
	resp, err := rs.tc.callAdminRealms(ctx, http.MethodDelete, path.Join(kcPathPartRoles, roleName), nil, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}

type AdminRoleCompositesService struct {
	kas      *TokenAPIClient
	roleName string
}

func (tc *TokenAPIClient) RoleCompositesService(roleName string) *AdminRoleCompositesService {
	rcs := new(AdminRoleCompositesService)
	rcs.kas = tc
	rcs.roleName = roleName
	return rcs
}

func (rs *AdminRolesService) CompositesService(roleName string) *AdminRoleCompositesService {
	return rs.tc.RoleCompositesService(roleName)
}

func (rcs *AdminRoleCompositesService) List(ctx context.Context, mutators ...RequestMutator) (Roles, error) {
	var (
		resp  *http.Response
		roles Roles
		err   error
	)
	resp, err = rcs.kas.callAdminRealms(ctx, http.MethodGet, path.Join(kcPathPartRoles, rcs.roleName, kcPathPartComposites), nil, mutators...)
	roles = make(Roles, 0)
	if err = handleResponse(resp, http.StatusOK, &roles, err); err != nil {
		return nil, err
	}
	return roles, nil
}

func (rcs *AdminRoleCompositesService) Add(ctx context.Context, roles Roles, mutators ...RequestMutator) error {
	resp, err := rcs.kas.callAdminRealms(ctx, http.MethodPost, path.Join(kcPathPartRoles, rcs.roleName, kcPathPartComposites), roles, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}

func (rcs *AdminRoleCompositesService) Remove(ctx context.Context, roles Roles, mutators ...RequestMutator) error {
	resp, err := rcs.kas.callAdminRealms(ctx, http.MethodDelete, path.Join(kcPathPartRoles, rcs.roleName, kcPathPartComposites), roles, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}

func (rcs *AdminRoleCompositesService) ClientRoles(ctx context.Context, clientName string, mutators ...RequestMutator) (Roles, error) {
	var (
		resp  *http.Response
		roles Roles
		err   error
	)
	resp, err = rcs.kas.callAdminRealms(ctx, http.MethodGet, path.Join(kcPathPartRoles, rcs.roleName, kcPathPartComposites, kcPathPartClients, clientName), nil, mutators...)
	roles = make(Roles, 0)
	if err = handleResponse(resp, http.StatusOK, &roles, err); err != nil {
		return nil, err
	}
	return roles, nil
}

func (rcs *AdminRoleCompositesService) RealmRoles(ctx context.Context, mutators ...RequestMutator) (Roles, error) {
	var (
		resp  *http.Response
		roles Roles
		err   error
	)
	resp, err = rcs.kas.callAdminRealms(ctx, http.MethodGet, path.Join(kcPathPartRoles, rcs.roleName, kcPathPartComposites, kcPathPartRealm), nil, mutators...)
	roles = make(Roles, 0)
	if err = handleResponse(resp, http.StatusOK, &roles, err); err != nil {
		return nil, err
	}
	return roles, nil
}
