package keycloak

import (
	"context"
	"net/http"
	"path"
)

type AdminRolesService struct {
	kas *AdminService
}

func NewAdminRolesService(kas *AdminService) *AdminRolesService {
	rs := new(AdminRolesService)
	rs.kas = kas
	return rs
}

func (k *AdminService) RolesService() *AdminRolesService {
	return NewAdminRolesService(k)
}

func (rs *AdminRolesService) List(ctx context.Context) (Roles, error) {
	var (
		resp  *http.Response
		roles Roles
		err   error
	)
	resp, err = rs.kas.callAdminRealmsRequireOK(ctx, http.MethodGet, kcPathPartRoles, nil)
	if err != nil {
		return nil, err
	}
	roles = make(Roles, 0)
	if err = handleResponse(resp, &roles); err != nil {
		return nil, err
	}
	return roles, nil
}

func (rs *AdminRolesService) Create(ctx context.Context, role *Role) ([]string, error) {
	var (
		resp *http.Response
		err  error
	)
	resp, err = rs.kas.callAdminRealmsRequireOK(ctx, http.MethodPost, kcPathPartRoles, role, nil)
	if err != nil {
		return nil, err
	}
	return parseResponseLocations(resp)
}

func (rs *AdminRolesService) Get(ctx context.Context, roleName string) (*Role, error) {
	var (
		resp *http.Response
		role *Role
		err  error
	)
	resp, err = rs.kas.callAdminRealmsRequireOK(ctx, http.MethodGet, path.Join(kcPathPartRoles, roleName), nil)
	if err != nil {
		return nil, err
	}
	role = new(Role)
	if err = handleResponse(resp, role); err != nil {
		return nil, err
	}
	return role, nil
}

func (rs *AdminRolesService) Update(ctx context.Context, roleName string, role *Role) error {
	_, err := rs.kas.callAdminRealmsRequireOK(ctx, http.MethodPut, path.Join(kcPathPartRoles, roleName), role)
	return err
}

func (rs *AdminRolesService) Delete(ctx context.Context, roleName string) error {
	_, err := rs.kas.callAdminRealmsRequireOK(ctx, http.MethodDelete, path.Join(kcPathPartRoles, roleName), nil)
	return err
}

type AdminRoleCompositesService struct {
	kas      *AdminService
	roleName string
}

func NewAdminRoleCompositesService(kas *AdminService, roleName string) *AdminRoleCompositesService {
	rcs := new(AdminRoleCompositesService)
	rcs.kas = kas
	rcs.roleName = roleName
	return rcs
}

func (k *AdminService) RoleCompositesService(roleName string) *AdminRoleCompositesService {
	return NewAdminRoleCompositesService(k, roleName)
}

func (rs *AdminRolesService) CompositesService(roleName string) *AdminRoleCompositesService {
	return rs.kas.RoleCompositesService(roleName)
}

func (rcs *AdminRoleCompositesService) List(ctx context.Context) (Roles, error) {
	var (
		resp  *http.Response
		roles Roles
		err   error
	)
	resp, err = rcs.kas.callAdminRealmsRequireOK(ctx, http.MethodGet, path.Join(kcPathPartRoles, rcs.roleName, kcPathPartComposites), nil)
	if err != nil {
		return nil, err
	}
	roles = make(Roles, 0)
	if err = handleResponse(resp, &roles); err != nil {
		return nil, err
	}
	return roles, nil
}

func (rcs *AdminRoleCompositesService) Add(ctx context.Context, roles Roles) error {
	_, err := rcs.kas.callAdminRealmsRequireOK(ctx, http.MethodPost, path.Join(kcPathPartRoles, rcs.roleName, kcPathPartComposites), roles)
	return err
}

func (rcs *AdminRoleCompositesService) Remove(ctx context.Context, roles Roles) error {
	_, err := rcs.kas.callAdminRealmsRequireOK(ctx, http.MethodDelete, path.Join(kcPathPartRoles, rcs.roleName, kcPathPartComposites), roles)
	return err
}

func (rcs *AdminRoleCompositesService) ClientRoles(ctx context.Context, clientName string) (Roles, error) {
	var (
		resp  *http.Response
		roles Roles
		err   error
	)
	resp, err = rcs.kas.callAdminRealmsRequireOK(ctx, http.MethodGet, path.Join(kcPathPartRoles, rcs.roleName, kcPathPartComposites, kcPathPartClients, clientName), nil)
	if err != nil {
		return nil, err
	}
	roles = make(Roles, 0)
	if err = handleResponse(resp, &roles); err != nil {
		return nil, err
	}
	return roles, nil
}

func (rcs *AdminRoleCompositesService) RealmRoles(ctx context.Context) (Roles, error) {
	var (
		resp  *http.Response
		roles Roles
		err   error
	)
	resp, err = rcs.kas.callAdminRealmsRequireOK(ctx, http.MethodGet, path.Join(kcPathPartRoles, rcs.roleName, kcPathPartComposites, kcPathPartRealm), nil)
	if err != nil {
		return nil, err
	}
	roles = make(Roles, 0)
	if err = handleResponse(resp, &roles); err != nil {
		return nil, err
	}
	return roles, nil
}
