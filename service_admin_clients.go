package keycloak

import (
	"context"
	"net/http"
	"path"
)

type AdminClientsService struct {
	c *AdminAPIClient
}

func NewAdminClientsService(c *AdminAPIClient) *AdminClientsService {
	cs := new(AdminClientsService)
	cs.c = c
	return cs
}

// List returns a new admin clients service instance
func (c *AdminAPIClient) ClientsService() *AdminClientsService {
	return NewAdminClientsService(c)
}

// List attempts to return a list of all  clients available in the Realm this client was created with
func (cs *AdminClientsService) List(ctx context.Context, clientID string, viewableOnly bool, mutators ...APIRequestMutator) (Clients, error) {
	var (
		resp    *http.Response
		clients Clients
		err     error
	)
	resp, err = cs.c.callAdminRealms(
		ctx,
		http.MethodGet,
		kcPathPartClients,
		nil,
		appendRequestMutators(
			mutators,
			NonZeroQueryMutator("clientId", clientID, nil, true),
			NonZeroQueryMutator("viewableOnly", viewableOnly, nil, true),
		)...)
	clients = make(Clients, 0)
	if err = handleResponse(resp, http.StatusOK, &clients, err); err != nil {
		return nil, err
	}
	return clients, nil
}

// Get attempts to return details about a specific  Get in the Realm this client was created with
func (cs *AdminClientsService) Get(ctx context.Context, clientID string, mutators ...APIRequestMutator) (*Client, error) {
	var (
		resp   *http.Response
		client *Client
		err    error
	)
	resp, err = cs.c.callAdminRealms(ctx, http.MethodGet, path.Join(kcPathPartClients, clientID), nil, mutators...)
	client = new(Client)
	if err = handleResponse(resp, http.StatusOK, client, err); err != nil {
		return nil, err
	}
	return client, nil
}

// Create attempts to create a new client within
func (cs *AdminClientsService) Create(ctx context.Context, client *ClientCreate, mutators ...APIRequestMutator) ([]string, error) {
	var (
		resp *http.Response
		err  error
	)
	resp, err = cs.c.callAdminRealms(ctx, http.MethodPost, kcPathPartClients, client, mutators...)
	if err = handleResponse(resp, http.StatusOK, nil, err); err != nil {
		return nil, err
	}
	return parseResponseLocations(resp)
}

// Update attempts to update a  client in the Realm this client was created with
func (cs *AdminClientsService) Update(ctx context.Context, clientID string, client *Client, mutators ...APIRequestMutator) error {
	resp, err := cs.c.callAdminRealms(ctx, http.MethodPut, path.Join(kcPathPartClients, clientID), client, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}

// Delete attempts to delete a  client from the Realm this client was created with
func (cs *AdminClientsService) Delete(ctx context.Context, clientID string, mutators ...APIRequestMutator) error {
	resp, err := cs.c.callAdminRealms(ctx, http.MethodDelete, path.Join(kcPathPartClients, clientID), nil, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}

// AdminClientRolesService contains all the methods needed to manage roles associated with a given client
type AdminClientRolesService struct {
	c        *AdminAPIClient
	clientID string
}

func (c *AdminAPIClient) AdminClientRolesService(clientID string) *AdminClientRolesService {
	rs := new(AdminClientRolesService)
	rs.c = c
	rs.clientID = clientID
	return rs
}

// RolesService returns a new AdminClientRolesService use to manage roles associated with the provided client id
func (cs *AdminClientsService) RolesService(clientID string) *AdminClientRolesService {
	return cs.c.AdminClientRolesService(clientID)
}

// List attempts to return all the roles defined with the provided client id
func (rs *AdminClientRolesService) List(ctx context.Context, mutators ...APIRequestMutator) (Roles, error) {
	var (
		resp  *http.Response
		roles Roles
		err   error
	)
	resp, err = rs.c.callAdminRealms(ctx, http.MethodGet, path.Join(kcPathPartClients, rs.clientID, kcPathPartRoles), nil, mutators...)
	roles = make(Roles, 0)
	if err = handleResponse(resp, http.StatusOK, &roles, err); err != nil {
		return nil, err
	}
	return roles, nil
}

// Get attempts to locate a single role on a client by the role's name
func (rs *AdminClientRolesService) Get(ctx context.Context, roleName string, mutators ...APIRequestMutator) (*Role, error) {
	var (
		resp *http.Response
		role *Role
		err  error
	)
	resp, err = rs.c.callAdminRealms(ctx, http.MethodGet, path.Join(kcPathPartClients, rs.clientID, kcPathPartRoles, roleName), nil, mutators...)
	role = new(Role)
	if err = handleResponse(resp, http.StatusOK, role, err); err != nil {
		return nil, err
	}
	return role, nil
}

// Create attempts to create a new role for the provided client
func (rs *AdminClientRolesService) Create(ctx context.Context, role *Role, mutators ...APIRequestMutator) ([]string, error) {
	var (
		resp *http.Response
		err  error
	)
	resp, err = rs.c.callAdminRealms(ctx, http.MethodPost, path.Join(kcPathPartClients, rs.clientID, kcPathPartRoles), role, mutators...)
	if err = handleResponse(resp, http.StatusOK, nil, err); err != nil {
		return nil, err
	}
	return parseResponseLocations(resp)
}

// Update attempts to update the provided role within
func (rs *AdminClientRolesService) Update(ctx context.Context, roleName string, role *Role, mutators ...APIRequestMutator) error {
	resp, err := rs.c.callAdminRealms(ctx, http.MethodPut, path.Join(kcPathPartClients, rs.clientID, kcPathPartRoles, roleName), role, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}

// Delete attempts to delete the specified role
func (rs *AdminClientRolesService) Delete(ctx context.Context, roleName string, mutators ...APIRequestMutator) error {
	resp, err := rs.c.callAdminRealms(ctx, http.MethodPut, path.Join(kcPathPartClients, rs.clientID, kcPathPartRoles, roleName), nil, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}

// Users attempts to return a list of all the users who have the specified role within the keycloak realm
func (rs *AdminClientRolesService) Users(ctx context.Context, roleName string, first, max int, mutators ...APIRequestMutator) (Users, error) {
	var (
		resp  *http.Response
		users Users
		err   error
	)
	resp, err = rs.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, rs.clientID, kcPathPartRoles, roleName, kcPathPartUsers),
		nil,
		appendRequestMutators(
			mutators,
			NonZeroQueryMutator("first", first, nil, true),
			NonZeroQueryMutator("max", max, nil, true),
		)...)
	users = make(Users, 0)
	if err = handleResponse(resp, http.StatusOK, &users, err); err != nil {
		return nil, err
	}
	return users, nil
}

type AdminClientRoleCompositesService struct {
	tc       *AdminAPIClient
	clientID string
	roleName string
}

func (c *AdminAPIClient) AdminClientRoleCompositesService(clientID, roleName string) *AdminClientRoleCompositesService {
	crs := new(AdminClientRoleCompositesService)
	crs.tc = c
	crs.clientID = clientID
	crs.roleName = roleName
	return crs
}

func (rs *AdminClientRolesService) CompositesService(roleName string) *AdminClientRoleCompositesService {
	return rs.c.AdminClientRoleCompositesService(rs.clientID, roleName)
}

// List attempts to return all composite roles that the specified role is a member of
func (crs *AdminClientRoleCompositesService) List(ctx context.Context, mutators ...APIRequestMutator) (Roles, error) {
	var (
		resp  *http.Response
		roles Roles
		err   error
	)
	resp, err = crs.tc.callAdminRealms(ctx, http.MethodGet, path.Join(kcPathPartClients, crs.clientID, kcPathPartRoles, crs.roleName, kcPathPartComposites), nil, mutators...)
	roles = make(Roles, 0)
	if err = handleResponse(resp, http.StatusOK, &roles, err); err != nil {
		return nil, err
	}
	return roles, nil
}

// Add attempts to add the specified role to the provided composite roles
func (crs *AdminClientRoleCompositesService) Add(ctx context.Context, roles Roles, mutators ...APIRequestMutator) error {
	resp, err := crs.tc.callAdminRealms(ctx, http.MethodPost, path.Join(kcPathPartClients, crs.clientID, kcPathPartRoles, crs.roleName, kcPathPartComposites), roles, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}

// Remove attempts to remove the provided role from the specified composite roles
func (crs *AdminClientRoleCompositesService) Remove(ctx context.Context, roles Roles, mutators ...APIRequestMutator) error {
	resp, err := crs.tc.callAdminRealms(ctx, http.MethodDelete, path.Join(kcPathPartClients, crs.clientID, kcPathPartRoles, crs.roleName, kcPathPartComposites), roles, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}

type AdminClientAuthzService struct {
	c        *AdminAPIClient
	clientID string
}

func NewAdminClientAuthzService(c *AdminAPIClient, clientID string) *AdminClientAuthzService {
	cs := new(AdminClientAuthzService)
	cs.c = c
	cs.clientID = clientID
	return cs
}

func (c *AdminAPIClient) ClientAuthzService(clientID string) *AdminClientAuthzService {
	return NewAdminClientAuthzService(c, clientID)
}

func (cas *AdminClientAuthzService) Overview(ctx context.Context, mutators ...APIRequestMutator) (*ResourceServerOverview, error) {
	var (
		resp *http.Response
		rs   *ResourceServerOverview
		err  error
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer),
		nil,
		mutators...,
	)
	rs = new(ResourceServerOverview)
	if err = handleResponse(resp, http.StatusOK, rs, err); err != nil {
		return nil, err
	}
	return rs, nil
}

func (cas *AdminClientAuthzService) Resources(ctx context.Context, deep bool, first, max int, mutators ...APIRequestMutator) (Resources, error) {
	var (
		resp *http.Response
		res  Resources
		err  error
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartResource),
		nil,
		appendRequestMutators(
			mutators,
			QueryMutator("deep", deep, true),
			NonZeroQueryMutator("first", first, 0, true),
			NonZeroQueryMutator("max", max, 20, true),
		)...,
	)
	res = make(Resources, 0)
	if err = handleResponse(resp, http.StatusOK, &res, err); err != nil {
		return nil, err
	}
	return res, nil
}

func (cas *AdminClientAuthzService) ResourceSearch(ctx context.Context, name string, mutators ...APIRequestMutator) (*Resource, error) {
	var (
		resp     *http.Response
		resource *Resource
		err      error
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartResource, kcPathPartSearch),
		nil,
		appendRequestMutators(
			mutators,
			QueryMutator("name", name, true),
		)...,
	)
	resource = new(Resource)
	if err = handleResponse(resp, http.StatusOK, resource, err); err != nil {
		return nil, err
	}
	return resource, nil
}

func (cas *AdminClientAuthzService) ResourceCreate(ctx context.Context, body *ResourceCreate, mutators ...APIRequestMutator) (*AdminCreateResponse, error) {
	var (
		resp *http.Response
		res  *AdminCreateResponse
		err  error
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodPost,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartResource),
		body,
		mutators...,
	)
	res = new(AdminCreateResponse)
	if err = handleResponse(resp, http.StatusCreated, res, err); err != nil {
		return nil, err
	}
	return res, nil
}

func (cas *AdminClientAuthzService) Scopes(ctx context.Context, deep bool, first, max int, name string, mutators ...APIRequestMutator) (Scopes, error) {
	var (
		resp   *http.Response
		scopes Scopes
		err    error
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartScope),
		nil,
		appendRequestMutators(
			mutators,
			QueryMutator("deep", deep, true),
			NonZeroQueryMutator("first", first, 0, true),
			NonZeroQueryMutator("max", max, 20, true),
			NonZeroQueryMutator("name", name, nil, true),
		)...,
	)
	scopes = make(Scopes, 0)
	if err = handleResponse(resp, http.StatusOK, &scopes, err); err != nil {
		return nil, err
	}
	return scopes, nil
}

func (cas *AdminClientAuthzService) ScopeSearch(ctx context.Context, name string, mutators ...APIRequestMutator) (*Scope, error) {
	var (
		resp  *http.Response
		scope *Scope
		err   error
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartScope, kcPathPartSearch),
		nil,
		appendRequestMutators(
			mutators,
			QueryMutator("name", name, true),
		)...,
	)
	scope = new(Scope)
	if err = handleResponse(resp, http.StatusOK, scope, err); err != nil {
		return nil, err
	}
	return scope, nil
}

func (cas *AdminClientAuthzService) ScopeCreate(ctx context.Context, body *MinimalScopeCreate, mutators ...APIRequestMutator) (*Scope, error) {
	var (
		resp  *http.Response
		scope *Scope
		err   error
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodPost,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartScope),
		body,
		mutators...,
	)
	scope = new(Scope)
	if err = handleResponse(resp, http.StatusCreated, scope, err); err != nil {
		return nil, err
	}
	return scope, nil
}

func (cas *AdminClientAuthzService) Policies(ctx context.Context, permission bool, first, max int, mutators ...APIRequestMutator) (Policies, error) {
	var (
		resp     *http.Response
		policies Policies
		err      error
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartPolicy),
		nil,
		appendRequestMutators(
			mutators,
			QueryMutator("permission", permission, true),
			NonZeroQueryMutator("first", first, 0, true),
			NonZeroQueryMutator("max", max, 20, true),
		)...,
	)
	policies = make(Policies, 0)
	if err = handleResponse(resp, http.StatusOK, &policies, err); err != nil {
		return nil, err
	}
	return policies, nil
}

func (cas *AdminClientAuthzService) PolicyProviders(ctx context.Context, mutators ...APIRequestMutator) (PolicyProviders, error) {
	var (
		resp     *http.Response
		policies PolicyProviders
		err      error
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartPolicy, kcPathPartProviders),
		nil,
		mutators...,
	)
	policies = make(PolicyProviders, 0)
	if err = handleResponse(resp, http.StatusOK, &policies, err); err != nil {
		return nil, err
	}
	return policies, nil
}

func (cas *AdminClientAuthzService) PolicyRoles(ctx context.Context, policyID string, mutators ...APIRequestMutator) (*Policy, error) {
	var (
		resp   *http.Response
		policy *Policy
		err    error
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartPolicy, kcPathPartRole, policyID),
		nil,
		mutators...,
	)
	policy = new(Policy)
	if err = handleResponse(resp, http.StatusOK, policy, err); err != nil {
		return nil, err
	}
	return policy, nil
}

func (cas *AdminClientAuthzService) PolicyDependents(ctx context.Context, policyID string, mutators ...APIRequestMutator) (Policies, error) {
	var (
		resp     *http.Response
		policies Policies
		err      error
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartPolicy, policyID, kcPathPartDependentPolicies),
		nil,
		mutators...,
	)
	policies = make(Policies, 0)
	if err = handleResponse(resp, http.StatusOK, &policies, err); err != nil {
		return nil, err
	}
	return policies, nil
}

func (cas *AdminClientAuthzService) PolicySearch(ctx context.Context, name string, mutators ...APIRequestMutator) (*Policy, error) {
	var (
		resp   *http.Response
		policy *Policy
		err    error
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartPolicy),
		nil,
		appendRequestMutators(
			mutators,
			QueryMutator("name", name, true),
		)...,
	)
	policy = new(Policy)
	if err = handleResponse(resp, http.StatusOK, policy, err); err != nil {
		return nil, err
	}
	return policy, nil
}

func (cas *AdminClientAuthzService) PolicyCreateRole(ctx context.Context, body *PolicyCreate, mutators ...APIRequestMutator) (*Policy, error) {
	var (
		resp   *http.Response
		policy *Policy
		err    error
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodPost,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartPolicy),
		body,
		mutators...,
	)
	policy = new(Policy)
	if err = handleResponse(resp, http.StatusCreated, policy, err); err != nil {
		return nil, err
	}
	return policy, nil
}

func (cas *AdminClientAuthzService) Permissions(ctx context.Context, first, max int, mutators ...APIRequestMutator) (Permissions, error) {
	var (
		resp  *http.Response
		perms Permissions
		err   error
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartPermission),
		nil,
		appendRequestMutators(
			mutators,
			NonZeroQueryMutator("first", first, 0, true),
			NonZeroQueryMutator("max", max, 20, true),
		)...,
	)
	perms = make(Permissions, 0)
	if err = handleResponse(resp, http.StatusOK, &perms, err); err != nil {
		return nil, err
	}
	return perms, nil
}

func (cas *AdminClientAuthzService) PermissionPolicies(ctx context.Context, permissionID string, mutators ...APIRequestMutator) (Policies, error) {
	var (
		resp     *http.Response
		policies Policies
		err      error
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartPolicy, permissionID, kcPathPartAssociatedPolicies),
		nil,
		mutators...,
	)
	policies = make(Policies, 0)
	if err = handleResponse(resp, http.StatusOK, &policies, err); err != nil {
		return nil, err
	}
	return policies, nil
}

func (cas *AdminClientAuthzService) ResourceScopes(ctx context.Context, resource string, mutators ...APIRequestMutator) (Scopes, error) {
	var (
		resp   *http.Response
		scopes Scopes
		err    error
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartResource, resource, kcPathPartScopes),
		nil,
		mutators...,
	)
	scopes = make(Scopes, 0)
	if err = handleResponse(resp, http.StatusOK, &scopes, err); err != nil {
		return nil, err
	}
	return scopes, nil
}

func (cas *AdminClientAuthzService) ResourceScope(ctx context.Context, resource, scopeID string, mutators ...APIRequestMutator) (*Scope, error) {
	var (
		resp  *http.Response
		scope *Scope
		err   error
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartResource, resource, kcPathPartScope, scopeID),
		nil,
		mutators...,
	)
	scope = new(Scope)
	if err = handleResponse(resp, http.StatusOK, scope, err); err != nil {
		return nil, err
	}
	return scope, nil
}

func (cas *AdminClientAuthzService) ResourcePermissions(ctx context.Context, resource string, mutators ...APIRequestMutator) (Permissions, error) {
	var (
		resp  *http.Response
		perms Permissions
		err   error
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartResource, resource, kcPathPartPermissions),
		nil,
		mutators...,
	)
	perms = make(Permissions, 0)
	if err = handleResponse(resp, http.StatusOK, &perms, err); err != nil {
		return nil, err
	}
	return perms, nil
}
