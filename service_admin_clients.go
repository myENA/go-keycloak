package keycloak

import (
	"context"
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
		resp *http.Response
		err  error

		clients = make(Clients, 0)
	)
	resp, err = cs.c.callAdminRealms(
		ctx,
		http.MethodGet,
		kcPathPartClients,
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
			NonZeroQueryMutator("clientId", clientID, nil, true),
			NonZeroQueryMutator("viewableOnly", viewableOnly, nil, true),
			QueryMutator("first", first, true),
			NonZeroQueryMutator("max", max, 20, true),
		)...)
	if err = handleResponse(resp, http.StatusOK, &clients, err); err != nil {
		return nil, err
	}
	return clients, nil
}

// Get attempts to return details about a specific  Get in the Realm this client was created with
func (cs *AdminClientsService) Get(ctx context.Context, clientID string, mutators ...APIRequestMutator) (*Client, error) {
	var (
		resp *http.Response
		err  error

		client = new(Client)
	)
	resp, err = cs.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, clientID),
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusOK, client, err); err != nil {
		return nil, err
	}
	return client, nil
}

// Create attempts to create a new client within
func (cs *AdminClientsService) Create(ctx context.Context, body *ClientCreateRequest, mutators ...APIRequestMutator) (*Client, error) {
	var (
		resp *http.Response
		err  error

		client = new(Client)
	)
	resp, err = cs.c.callAdminRealms(
		ctx,
		http.MethodPost,
		kcPathPartClients,
		body,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusCreated, nil, err); err != nil {
		return nil, err
	}
	return client, nil
}

func (cs *AdminClientsService) CreateAndGet(ctx context.Context, body *ClientCreateRequest, mutators ...APIRequestMutator) (*Client, error) {
	var (
		client *Client
		err    error
	)
	if client, err = cs.Create(ctx, body, mutators...); err != nil {
		return nil, err
	}
	return cs.Get(ctx, client.ID, mutators...)
}

func (cs *AdminClientsService) Update(ctx context.Context, client *Client, mutators ...APIRequestMutator) error {
	resp, err := cs.c.callAdminRealms(
		ctx,
		http.MethodPut,
		path.Join(kcPathPartClients, client.ID),
		client,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderContentType, httpHeaderValueJSON, true),
		)...,
	)
	return handleResponse(resp, http.StatusNoContent, nil, err)
}

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
		err  error

		rs = new(ResourceServerOverview)
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer),
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusOK, rs, err); err != nil {
		return nil, err
	}
	return rs, nil
}

func (cas *AdminClientAuthzService) Resources(ctx context.Context, deep bool, first, max int, mutators ...APIRequestMutator) (Resources, error) {
	var (
		resp *http.Response
		err  error

		res = make(Resources, 0)
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartResource),
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
			QueryMutator("deep", deep, true),
			QueryMutator("first", first, true),
			NonZeroQueryMutator("max", max, 20, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusOK, &res, err); err != nil {
		return nil, err
	}
	return res, nil
}

func (cas *AdminClientAuthzService) Resource(ctx context.Context, resourceID string, mutators ...APIRequestMutator) (*Resource, error) {
	var (
		resp *http.Response
		err  error

		res = new(Resource)
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartResource, resourceID),
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
		)...)
	if err = handleResponse(resp, http.StatusOK, res, err); err != nil {
		return nil, err
	}
	return res, nil
}

func (cas *AdminClientAuthzService) ResourceSearch(ctx context.Context, name string, mutators ...APIRequestMutator) (*Resource, error) {
	var (
		resp *http.Response
		err  error

		resource = new(Resource)
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartResource, kcPathPartSearch),
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
			QueryMutator("name", name, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusOK, resource, err); err != nil {
		return nil, err
	}
	return resource, nil
}

func (cas *AdminClientAuthzService) ResourceCreate(ctx context.Context, body *ResourceCreateUpdateRequest, mutators ...APIRequestMutator) (*AdminCreateResponse, error) {
	var (
		resp *http.Response
		err  error

		res = new(AdminCreateResponse)
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodPost,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartResource),
		body,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
			HeaderMutator(httpHeaderContentType, httpHeaderValueJSON, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusCreated, res, err); err != nil {
		return nil, err
	}
	return res, nil
}

func (cas *AdminClientAuthzService) ResourceCreateAndGet(ctx context.Context, body *ResourceCreateUpdateRequest, mutators ...APIRequestMutator) (*Resource, error) {
	var (
		resp *AdminCreateResponse
		err  error
	)
	if resp, err = cas.ResourceCreate(ctx, body, mutators...); err != nil {
		return nil, err
	}
	return cas.Resource(ctx, resp.ID, mutators...)
}

func (cas *AdminClientAuthzService) ResourceUpdate(ctx context.Context, body *ResourceCreateUpdateRequest, mutators ...APIRequestMutator) error {
	resp, err := cas.c.callAdminRealms(
		ctx,
		http.MethodPut,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartResource, body.ID),
		body,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderContentType, httpHeaderValueJSON, true),
		)...,
	)
	return handleResponse(resp, http.StatusNoContent, nil, err)
}

func (cas *AdminClientAuthzService) ResourceDelete(ctx context.Context, resourceID string, mutators ...APIRequestMutator) error {
	resp, err := cas.c.callAdminRealms(
		ctx,
		http.MethodDelete,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartResource, resourceID),
		nil,
		mutators...,
	)
	return handleResponse(resp, http.StatusNoContent, nil, err)
}

func (cas *AdminClientAuthzService) Scopes(ctx context.Context, deep bool, first, max int, name string, mutators ...APIRequestMutator) (Scopes, error) {
	var (
		resp *http.Response
		err  error

		scopes = make(Scopes, 0)
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartScope),
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
			QueryMutator("deep", deep, true),
			QueryMutator("first", first, true),
			NonZeroQueryMutator("max", max, 20, true),
			NonZeroQueryMutator("name", name, nil, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusOK, &scopes, err); err != nil {
		return nil, err
	}
	return scopes, nil
}

func (cas *AdminClientAuthzService) ScopeSearch(ctx context.Context, name string, mutators ...APIRequestMutator) (*Scope, error) {
	var (
		resp *http.Response
		err  error

		scope = new(Scope)
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartScope, kcPathPartSearch),
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
			QueryMutator("name", name, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusOK, scope, err); err != nil {
		return nil, err
	}
	return scope, nil
}

func (cas *AdminClientAuthzService) ScopeCreate(ctx context.Context, body *ScopeCreateUpdateRequest, mutators ...APIRequestMutator) (*Scope, error) {
	var (
		resp *http.Response
		err  error

		scope = new(Scope)
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodPost,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartScope),
		body,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
			HeaderMutator(httpHeaderContentType, httpHeaderValueJSON, true),
		)...,
	)
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
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderContentType, httpHeaderValueJSON, true),
		)...,
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
		resp *http.Response
		err  error

		policies = make(Policies, 0)
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartPolicy),
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
			QueryMutator("permission", permission, true),
			QueryMutator("first", first, true),
			NonZeroQueryMutator("max", max, 20, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusOK, &policies, err); err != nil {
		return nil, err
	}
	return policies, nil
}

func (cas *AdminClientAuthzService) Policy(ctx context.Context, policyID string, mutators ...APIRequestMutator) (*Policy, error) {
	var (
		resp *http.Response
		err  error

		policy = new(Policy)
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartPolicy, kcPathPartRole, policyID),
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusOK, policy, err); err != nil {
		return nil, err
	}
	return policy, nil
}

func (cas *AdminClientAuthzService) PolicyProviders(ctx context.Context, mutators ...APIRequestMutator) (PolicyProviders, error) {
	var (
		resp *http.Response
		err  error

		policies = make(PolicyProviders, 0)
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartPolicy, kcPathPartProviders),
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusOK, &policies, err); err != nil {
		return nil, err
	}
	return policies, nil
}

func (cas *AdminClientAuthzService) PolicyDependents(ctx context.Context, policyID string, mutators ...APIRequestMutator) (Policies, error) {
	var (
		resp *http.Response
		err  error

		policies = make(Policies, 0)
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartPolicy, policyID, kcPathPartDependentPolicies),
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusOK, &policies, err); err != nil {
		return nil, err
	}
	return policies, nil
}

func (cas *AdminClientAuthzService) PolicySearch(ctx context.Context, name string, mutators ...APIRequestMutator) (*Policy, error) {
	var (
		resp *http.Response
		err  error

		policy = new(Policy)
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartPolicy),
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
			QueryMutator("name", name, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusOK, policy, err); err != nil {
		return nil, err
	}
	return policy, nil
}

func (cas *AdminClientAuthzService) PolicyCreate(ctx context.Context, body *PolicyCreateUpdateRequest, mutators ...APIRequestMutator) (*Policy, error) {
	var (
		resp *http.Response
		err  error

		policy = new(Policy)
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodPost,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartPolicy),
		body,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
			HeaderMutator(httpHeaderContentType, httpHeaderValueJSON, true),
		)...,
	)
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
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
			HeaderMutator(httpHeaderContentType, httpHeaderValueJSON, true),
		)...,
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
		resp *http.Response
		err  error

		perms = make(Permissions, 0)
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartPermission),
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
			QueryMutator("first", first, true),
			NonZeroQueryMutator("max", max, 20, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusOK, &perms, err); err != nil {
		return nil, err
	}
	return perms, nil
}

func (cas *AdminClientAuthzService) Permission(ctx context.Context, permissionID string, mutators ...APIRequestMutator) (*Permission, error) {
	var (
		resp *http.Response
		err  error

		perm = new(Permission)
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartPermission, kcPathPartScope, permissionID),
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusOK, perm, err); err != nil {
		return nil, err
	}
	return perm, err
}

func (cas *AdminClientAuthzService) PermissionCreate(ctx context.Context, body *PermissionCreateUpdateRequest, mutators ...APIRequestMutator) (*Permission, error) {
	var (
		finalSlug string
		resp      *http.Response
		perm      *Permission
		err       error
	)
	if finalSlug, err = permissionModifyPath(body); err != nil {
		return nil, err
	}
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodPost,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartPermission, finalSlug),
		body,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
			HeaderMutator(httpHeaderContentType, httpHeaderValueJSON, true),
		)...)
	perm = new(Permission)
	if err = handleResponse(resp, http.StatusCreated, perm, err); err != nil {
		return nil, err
	}
	return perm, nil
}

func (cas *AdminClientAuthzService) PermissionUpdate(ctx context.Context, body *PermissionCreateUpdateRequest, mutators ...APIRequestMutator) error {
	var (
		finalSlug string
		resp      *http.Response
		err       error
	)
	if finalSlug, err = permissionModifyPath(body); err != nil {
		return err
	}
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodPut,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartPermission, finalSlug, body.ID),
		body,
		mutators...,
	)
	return handleResponse(resp, http.StatusCreated, nil, err)
}

func (cas *AdminClientAuthzService) PermissionDelete(ctx context.Context, permissionID string, mutators ...APIRequestMutator) error {
	resp, err := cas.c.callAdminRealms(
		ctx,
		http.MethodDelete,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartPermission, permissionID),
		nil,
		mutators...,
	)
	return handleResponse(resp, http.StatusNoContent, nil, err)
}

func (cas *AdminClientAuthzService) PermissionAssociatedPolicies(ctx context.Context, permissionID string, mutators ...APIRequestMutator) (Policies, error) {
	var (
		resp *http.Response
		err  error

		policies = make(Policies, 0)
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartPolicy, permissionID, kcPathPartAssociatedPolicies),
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusOK, &policies, err); err != nil {
		return nil, err
	}
	return policies, nil
}

func (cas *AdminClientAuthzService) ResourceScopes(ctx context.Context, resource string, mutators ...APIRequestMutator) (Scopes, error) {
	var (
		resp *http.Response
		err  error

		scopes = make(Scopes, 0)
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartResource, resource, kcPathPartScopes),
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusOK, &scopes, err); err != nil {
		return nil, err
	}
	return scopes, nil
}

func (cas *AdminClientAuthzService) ResourceScope(ctx context.Context, resource, scopeID string, mutators ...APIRequestMutator) (*Scope, error) {
	var (
		resp *http.Response
		err  error

		scope = new(Scope)
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartResource, resource, kcPathPartScope, scopeID),
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusOK, scope, err); err != nil {
		return nil, err
	}
	return scope, nil
}

func (cas *AdminClientAuthzService) ResourcePermissions(ctx context.Context, resource string, mutators ...APIRequestMutator) (Permissions, error) {
	var (
		resp *http.Response
		err  error

		perms = make(Permissions, 0)
	)
	resp, err = cas.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, cas.clientID, kcPathPartAuthz, kcPathPartResourceServer, kcPathPartResource, resource, kcPathPartPermissions),
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusOK, &perms, err); err != nil {
		return nil, err
	}
	return perms, nil
}
