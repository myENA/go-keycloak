package keycloak

import (
	"context"
	"net/http"
	"path"
)

type AdminClientsService struct {
	as *AdminService
}

func NewAdminClientsService(as *AdminService) *AdminClientsService {
	cs := new(AdminClientsService)
	cs.as = as
	return cs
}

// List returns a new admin clients service instance
func (s *AdminService) ClientsService() *AdminClientsService {
	return NewAdminClientsService(s)
}

// List attempts to return a list of all  clients available in the Realm this client was created with
func (cs *AdminClientsService) List(ctx context.Context, clientID string, viewableOnly bool, mutators ...RequestMutator) (Clients, error) {
	var (
		resp    *http.Response
		clients Clients
		err     error
	)
	resp, err = cs.as.callAdminRealms(
		ctx,
		http.MethodGet,
		kcPathPartClients,
		nil,
		addMutators(
			mutators,
			ValuedQueryMutator("clientId", clientID, true),
			ValuedQueryMutator("viewableOnly", viewableOnly, true),
		)...)
	clients = make(Clients, 0)
	if err = handleResponse(resp, http.StatusOK, &clients, err); err != nil {
		return nil, err
	}
	return clients, nil
}

// Get attempts to return details about a specific  Get in the Realm this client was created with
func (cs *AdminClientsService) Get(ctx context.Context, clientID string, mutators ...RequestMutator) (*Client, error) {
	var (
		resp   *http.Response
		client *Client
		err    error
	)
	resp, err = cs.as.callAdminRealms(ctx, http.MethodGet, path.Join(kcPathPartClients, clientID), nil, mutators...)
	client = new(Client)
	if err = handleResponse(resp, http.StatusOK, client, err); err != nil {
		return nil, err
	}
	return client, nil
}

// Create attempts to create a new client within
func (cs *AdminClientsService) Create(ctx context.Context, client *ClientCreate, mutators ...RequestMutator) ([]string, error) {
	var (
		resp *http.Response
		err  error
	)
	resp, err = cs.as.callAdminRealms(ctx, http.MethodPost, kcPathPartClients, client, mutators...)
	if err = handleResponse(resp, http.StatusOK, nil, err); err != nil {
		return nil, err
	}
	return parseResponseLocations(resp)
}

// Update attempts to update a  client in the Realm this client was created with
func (cs *AdminClientsService) Update(ctx context.Context, clientID string, client *Client, mutators ...RequestMutator) error {
	resp, err := cs.as.callAdminRealms(ctx, http.MethodPut, path.Join(kcPathPartClients, clientID), client, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}

// Delete attempts to delete a  client from the Realm this client was created with
func (cs *AdminClientsService) Delete(ctx context.Context, clientID string, mutators ...RequestMutator) error {
	resp, err := cs.as.callAdminRealms(ctx, http.MethodDelete, path.Join(kcPathPartClients, clientID), nil, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}

// AdminClientRolesService contains all the methods needed to manage roles associated with a given client
type AdminClientRolesService struct {
	kas      *AdminService
	clientID string
}

func (s *AdminService) ClientRolesService(clientID string) *AdminClientRolesService {
	rs := new(AdminClientRolesService)
	rs.kas = s
	rs.clientID = clientID
	return rs
}

// RolesService returns a new AdminClientRolesService use to manage roles associated with the provided client id
func (cs *AdminClientsService) RolesService(clientID string) *AdminClientRolesService {
	return cs.as.ClientRolesService(clientID)
}

// List attempts to return all the roles defined with the provided client id
func (rs *AdminClientRolesService) List(ctx context.Context, mutators ...RequestMutator) (Roles, error) {
	var (
		resp  *http.Response
		roles Roles
		err   error
	)
	resp, err = rs.kas.callAdminRealms(ctx, http.MethodGet, path.Join(kcPathPartClients, rs.clientID, kcPathPartRoles), nil, mutators...)
	roles = make(Roles, 0)
	if err = handleResponse(resp, http.StatusOK, &roles, err); err != nil {
		return nil, err
	}
	return roles, nil
}

// Get attempts to locate a single role on a client by the role's name
func (rs *AdminClientRolesService) Get(ctx context.Context, roleName string, mutators ...RequestMutator) (*Role, error) {
	var (
		resp *http.Response
		role *Role
		err  error
	)
	resp, err = rs.kas.callAdminRealms(ctx, http.MethodGet, path.Join(kcPathPartClients, rs.clientID, kcPathPartRoles, roleName), nil, mutators...)
	role = new(Role)
	if err = handleResponse(resp, http.StatusOK, role, err); err != nil {
		return nil, err
	}
	return role, nil
}

// Create attempts to create a new role for the provided client
func (rs *AdminClientRolesService) Create(ctx context.Context, role *Role, mutators ...RequestMutator) ([]string, error) {
	var (
		resp *http.Response
		err  error
	)
	resp, err = rs.kas.callAdminRealms(ctx, http.MethodPost, path.Join(kcPathPartClients, rs.clientID, kcPathPartRoles), role, mutators...)
	if err = handleResponse(resp, http.StatusOK, nil, err); err != nil {
		return nil, err
	}
	return parseResponseLocations(resp)
}

// Update attempts to update the provided role within
func (rs *AdminClientRolesService) Update(ctx context.Context, roleName string, role *Role, mutators ...RequestMutator) error {
	resp, err := rs.kas.callAdminRealms(ctx, http.MethodPut, path.Join(kcPathPartClients, rs.clientID, kcPathPartRoles, roleName), role, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}

// Delete attempts to delete the specified role
func (rs *AdminClientRolesService) Delete(ctx context.Context, roleName string, mutators ...RequestMutator) error {
	resp, err := rs.kas.callAdminRealms(ctx, http.MethodPut, path.Join(kcPathPartClients, rs.clientID, kcPathPartRoles, roleName), nil, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}

// Users attempts to return a list of all the users who have the specified role within the keycloak realm
func (rs *AdminClientRolesService) Users(ctx context.Context, roleName string, first, max int, mutators ...RequestMutator) (Users, error) {
	var (
		resp  *http.Response
		users Users
		err   error
	)
	resp, err = rs.kas.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, rs.clientID, kcPathPartRoles, roleName, kcPathPartUsers),
		nil,
		addMutators(
			mutators,
			ValuedQueryMutator("first", first, true),
			ValuedQueryMutator("max", max, true),
		)...)
	users = make(Users, 0)
	if err = handleResponse(resp, http.StatusOK, &users, err); err != nil {
		return nil, err
	}
	return users, nil
}

type AdminClientRoleCompositesService struct {
	kas      *AdminService
	clientID string
	roleName string
}

func (s *AdminService) ClientRoleCompositesService(clientID, roleName string) *AdminClientRoleCompositesService {
	crs := new(AdminClientRoleCompositesService)
	crs.kas = s
	crs.clientID = clientID
	crs.roleName = roleName
	return crs
}

func (rs *AdminClientRolesService) CompositesService(roleName string) *AdminClientRoleCompositesService {
	return rs.kas.ClientRoleCompositesService(rs.clientID, roleName)
}

// List attempts to return all composite roles that the specified role is a member of
func (crs *AdminClientRoleCompositesService) List(ctx context.Context, mutators ...RequestMutator) (Roles, error) {
	var (
		resp  *http.Response
		roles Roles
		err   error
	)
	resp, err = crs.kas.callAdminRealms(ctx, http.MethodGet, path.Join(kcPathPartClients, crs.clientID, kcPathPartRoles, crs.roleName, kcPathPartComposites), nil, mutators...)
	roles = make(Roles, 0)
	if err = handleResponse(resp, http.StatusOK, &roles, err); err != nil {
		return nil, err
	}
	return roles, nil
}

// Add attempts to add the specified role to the provided composite roles
func (crs *AdminClientRoleCompositesService) Add(ctx context.Context, roles Roles, mutators ...RequestMutator) error {
	resp, err := crs.kas.callAdminRealms(ctx, http.MethodPost, path.Join(kcPathPartClients, crs.clientID, kcPathPartRoles, crs.roleName, kcPathPartComposites), roles, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}

// Remove attempts to remove the provided role from the specified composite roles
func (crs *AdminClientRoleCompositesService) Remove(ctx context.Context, roles Roles, mutators ...RequestMutator) error {
	resp, err := crs.kas.callAdminRealms(ctx, http.MethodDelete, path.Join(kcPathPartClients, crs.clientID, kcPathPartRoles, crs.roleName, kcPathPartComposites), roles, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}
