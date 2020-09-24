package keycloak

import (
	"context"
	"fmt"
	"net/http"
	"path"
)

type AdminRoleService struct {
	c *AdminAPIClient
}

func (c *AdminAPIClient) RoleService() *AdminRoleService {
	rs := new(AdminRoleService)
	rs.c = c
	return rs
}

func (rs *AdminRoleService) RealmRoles(ctx context.Context, first, max int, mutators ...APIRequestMutator) (Roles, error) {
	var (
		resp *http.Response
		err  error

		roles = make(Roles, 0)
	)
	resp, err = rs.c.callAdminRealms(
		ctx,
		http.MethodGet,
		kcPathPartRoles,
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
			QueryMutator("first", first, true),
			NonZeroQueryMutator("max", max, 20, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusOK, &roles, err); err != nil {
		return nil, err
	}
	return roles, nil
}

func (rs *AdminRoleService) ClientRoles(ctx context.Context, clientID string, first, max int, mutators ...APIRequestMutator) (Roles, error) {
	var (
		resp *http.Response
		err  error

		roles = make(Roles, 0)
	)
	resp, err = rs.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, clientID, kcPathPartRoles),
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
			QueryMutator("first", first, true),
			NonZeroQueryMutator("max", max, 20, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusOK, &roles, err); err != nil {
		return nil, err
	}
	return roles, nil
}

func (rs *AdminRoleService) RealmRoleCreate(ctx context.Context, body *RoleCreateRequest, mutators ...APIRequestMutator) ([]string, error) {
	var (
		resp *http.Response
		err  error
	)
	resp, err = rs.c.callAdminRealms(
		ctx,
		http.MethodPost,
		kcPathPartRoles,
		body,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
			HeaderMutator(httpHeaderContentType, httpHeaderValueJSON, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusCreated, nil, err); err != nil {
		return nil, err
	}
	return parseResponseLocations(resp)
}

func (rs *AdminRoleService) RealmRoleCreateAndGet(ctx context.Context, body *RoleCreateRequest, mutators ...APIRequestMutator) (*Role, error) {
	var (
		ids []string
		err error
	)
	if ids, err = rs.RealmRoleCreate(ctx, body, mutators...); err != nil {
		return nil, err
	}
	if len(ids) != 1 {
		return nil, fmt.Errorf("expected 1 id in response, found %v", ids)
	}
	return rs.Get(ctx, ids[0], mutators...)
}

func (rs *AdminRoleService) ClientRoleCreate(ctx context.Context, clientID string, body *RoleCreateRequest, mutators ...APIRequestMutator) ([]string, error) {
	var (
		resp *http.Response
		err  error
	)
	resp, err = rs.c.callAdminRealms(
		ctx,
		http.MethodPost,
		path.Join(kcPathPartClients, clientID, kcPathPartRoles),
		body,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
			HeaderMutator(httpHeaderContentType, httpHeaderValueJSON, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusCreated, nil, err); err != nil {
		return nil, err
	}
	return parseResponseLocations(resp)
}

func (rs *AdminRoleService) ClientRoleCreateAndGet(ctx context.Context, clientID string, body *RoleCreateRequest, mutators ...APIRequestMutator) (*Role, error) {
	var (
		ids []string
		err error
	)
	if ids, err = rs.ClientRoleCreate(ctx, clientID, body, mutators...); err != nil {
		return nil, err
	}
	if len(ids) != 1 {
		return nil, fmt.Errorf("expected 1 id in response, found %v", ids)
	}
	return rs.Get(ctx, ids[0], mutators...)
}

func (rs *AdminRoleService) RealmRoleUsers(ctx context.Context, roleName string, first, max int, mutators ...APIRequestMutator) (Users, error) {
	var (
		resp *http.Response
		err  error

		users = make(Users, 0)
	)
	resp, err = rs.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartRoles, roleName, kcPathPartUsers),
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
			QueryMutator("first", first, true),
			NonZeroQueryMutator("max", max, 20, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusOK, &users, err); err != nil {
		return nil, err
	}
	return users, nil
}

func (rs *AdminRoleService) ClientRoleUsers(ctx context.Context, clientID, roleName string, first, max int, mutators ...APIRequestMutator) (Users, error) {
	var (
		resp *http.Response
		err  error

		users = make(Users, 0)
	)
	resp, err = rs.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, clientID, kcPathPartRoles, roleName, kcPathPartUsers),
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
			QueryMutator("first", first, true),
			NonZeroQueryMutator("max", max, 20, true),
		)...)
	if err = handleResponse(resp, http.StatusOK, &users, err); err != nil {
		return nil, err
	}
	return users, nil
}

func (rs *AdminRoleService) Get(ctx context.Context, roleID string, mutators ...APIRequestMutator) (*Role, error) {
	var (
		resp *http.Response
		err  error

		role = new(Role)
	)
	resp, err = rs.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartRolesByID, roleID),
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusOK, role, err); err != nil {
		return nil, err
	}
	return role, nil
}

// Update requires that ID be populated in body parameter
func (rs *AdminRoleService) Update(ctx context.Context, body *Role, mutators ...APIRequestMutator) error {
	resp, err := rs.c.callAdminRealms(
		ctx,
		http.MethodPut,
		path.Join(kcPathPartRolesByID, body.ID),
		body,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderContentType, httpHeaderValueJSON, true),
		)...,
	)
	return handleResponse(resp, http.StatusNoContent, nil, err)
}

func (rs *AdminRoleService) UpdateAndGet(ctx context.Context, body *Role, mutators ...APIRequestMutator) (*Role, error) {
	if err := rs.Update(ctx, body, mutators...); err != nil {
		return nil, err
	}
	return rs.Get(ctx, body.ID, mutators...)
}

func (rs *AdminRoleService) Delete(ctx context.Context, roleID string, mutators ...APIRequestMutator) error {
	resp, err := rs.c.callAdminRealms(ctx, http.MethodDelete, path.Join(kcPathPartRolesByID, roleID), nil, mutators...)
	return handleResponse(resp, http.StatusNoContent, nil, err)
}
