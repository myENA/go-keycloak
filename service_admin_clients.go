package keycloak

import (
	"context"
	"fmt"
	"net/http"
	"path"
)

type AdminClientsService struct {
	c *AdminAPIClient
}

// RealmRoles returns a new admin clients service instance
func (c *AdminAPIClient) ClientsService() *AdminClientsService {
	cs := new(AdminClientsService)
	cs.c = c
	return cs
}

// List attempts to return a list of all  clients available in the Realm this client was created with
func (cs *AdminClientsService) List(ctx context.Context, clientID string, viewableOnly bool, first, max int, mutators ...APIRequestMutator) (Clients, error) {
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
		requestMutators(
			mutators,
			NonZeroQueryMutator("clientId", clientID, nil, true),
			NonZeroQueryMutator("viewableOnly", viewableOnly, nil, true),
			QueryMutator("first", first, true),
			NonZeroQueryMutator("max", max, 20, true),
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
func (cs *AdminClientsService) Create(ctx context.Context, body *ClientCreate, mutators ...APIRequestMutator) ([]string, error) {
	var (
		resp *http.Response
		err  error
	)
	resp, err = cs.c.callAdminRealms(ctx, http.MethodPost, kcPathPartClients, body, mutators...)
	if err = handleResponse(resp, http.StatusOK, nil, err); err != nil {
		return nil, err
	}
	return parseResponseLocations(resp)
}

func (cs *AdminClientsService) CreateAndGet(ctx context.Context, body *ClientCreate, mutators ...APIRequestMutator) (*Client, error) {
	var (
		ids []string
		err error
	)
	if ids, err = cs.Create(ctx, body, mutators...); err != nil {
		return nil, err
	}
	if len(ids) != 1 {
		return nil, fmt.Errorf("expected 1 id, found: %v", ids)
	}
	return cs.Get(ctx, ids[0], mutators...)
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

type AdminClientAuthzService struct {
	c        *AdminAPIClient
	clientID string
}

func (c *AdminAPIClient) ClientAuthzService(clientID string) *AdminClientAuthzService {
	cs := new(AdminClientAuthzService)
	cs.c = c
	cs.clientID = clientID
	return cs
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
		requestMutators(
			mutators,
			QueryMutator("deep", deep, true),
			QueryMutator("first", first, true),
			NonZeroQueryMutator("max", max, 20, true),
		)...,
	)
	res = make(Resources, 0)
	if err = handleResponse(resp, http.StatusOK, &res, err); err != nil {
		return nil, err
	}
	return res, nil
}

func (cas *AdminClientAuthzService) Resource(ctx context.Context, resourceName string, mutators ...APIRequestMutator) (*Resource, error) {
	var (
		resp *http.Response
		res  *Resource
		err  error
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartResource),
		nil,
		mutators...,
	)
	res = new(Resource)
	if err = handleResponse(resp, http.StatusOK, res, err); err != nil {
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
		requestMutators(
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

func (cas *AdminClientAuthzService) ResourceCreate(ctx context.Context, body *ResourceCreateUpdateRequest, mutators ...APIRequestMutator) (*AdminCreateResponse, error) {
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

func (cas *AdminClientAuthzService) ResourceUpdate(ctx context.Context, body *ResourceCreateUpdateRequest, mutators ...APIRequestMutator) error {
	resp, err := cas.c.callAdminRealms(
		ctx,
		http.MethodPut,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartResource, body.ID),
		body,
		mutators...,
	)
	return handleResponse(resp, http.StatusNoContent, nil, err)
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
		requestMutators(
			mutators,
			QueryMutator("deep", deep, true),
			QueryMutator("first", first, true),
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
		requestMutators(
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

func (cas *AdminClientAuthzService) ScopeCreate(ctx context.Context, body *ScopeCreateUpdateRequest, mutators ...APIRequestMutator) (*Scope, error) {
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

func (cas *AdminClientAuthzService) ScopeUpdate(ctx context.Context, body *ScopeCreateUpdateRequest, mutators ...APIRequestMutator) error {
	resp, err := cas.c.callAdminRealms(
		ctx,
		http.MethodPut,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartScope, body.ID),
		body,
		mutators...,
	)
	return handleResponse(resp, http.StatusNoContent, nil, err)
}

func (cas *AdminClientAuthzService) ScopeDelete(ctx context.Context, scopeID string, mutators ...APIRequestMutator) error {
	resp, err := cas.c.callAdminRealms(
		ctx,
		http.MethodDelete,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartScope, scopeID),
		nil,
		mutators...,
	)
	return handleResponse(resp, http.StatusNoContent, nil, err)
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
		requestMutators(
			mutators,
			QueryMutator("permission", permission, true),
			QueryMutator("first", first, true),
			NonZeroQueryMutator("max", max, 20, true),
		)...,
	)
	policies = make(Policies, 0)
	if err = handleResponse(resp, http.StatusOK, &policies, err); err != nil {
		return nil, err
	}
	return policies, nil
}

func (cas *AdminClientAuthzService) Policy(ctx context.Context, policyID string, mutators ...APIRequestMutator) (*Policy, error) {
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
		requestMutators(
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

func (cas *AdminClientAuthzService) PolicyCreate(ctx context.Context, body *PolicyCreateUpdateRequest, mutators ...APIRequestMutator) (*Policy, error) {
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

func (cas *AdminClientAuthzService) PolicyUpdate(ctx context.Context, body *PolicyCreateUpdateRequest, mutators ...APIRequestMutator) error {
	resp, err := cas.c.callAdminRealms(
		ctx,
		http.MethodPut,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartPolicy, body.ID),
		body,
		mutators...,
	)
	return handleResponse(resp, http.StatusCreated, nil, err)
}

func (cas *AdminClientAuthzService) PolicyDelete(ctx context.Context, policyID string, mutators ...APIRequestMutator) error {
	resp, err := cas.c.callAdminRealms(
		ctx,
		http.MethodDelete,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartPolicy, policyID),
		nil,
		mutators...,
	)
	return handleResponse(resp, http.StatusCreated, nil, err)
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
		requestMutators(
			mutators,
			QueryMutator("first", first, true),
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
