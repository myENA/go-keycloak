package keycloak

import (
	"context"
	"net/http"
	"path"
	"strconv"
)

type AdminClientsService struct {
	kas *AdminService
}

func NewAdminClientsService(kas *AdminService) *AdminClientsService {
	cs := new(AdminClientsService)
	cs.kas = kas
	return cs
}

// List returns a new admin clients service instance
func (k *AdminService) ClientsService() *AdminClientsService {
	return NewAdminClientsService(k)
}

// List attempts to return a list of all  clients available in the Realm this client was created with
func (cs *AdminClientsService) List(ctx context.Context, clientID string, viewableOnly bool) (Clients, error) {
	var (
		resp    *http.Response
		clients Clients
		err     error
	)
	resp, err = cs.kas.callAdminRealmsRequireOK(
		ctx,
		http.MethodGet,
		kcPathPartClients,
		nil,
		ValuedQueryMutator("clientId", clientID, true),
		ValuedQueryMutator("viewableOnly", strconv.FormatBool(viewableOnly), true))
	if err != nil {
		return nil, err
	}
	clients = make(Clients, 0)
	if err = handleResponse(resp, &clients); err != nil {
		return nil, err
	}
	return clients, nil
}

// Get attempts to return details about a specific  Get in the Realm this client was created with
func (cs *AdminClientsService) Get(ctx context.Context, clientID string) (*Client, error) {
	var (
		resp   *http.Response
		client *Client
		err    error
	)
	resp, err = cs.kas.callAdminRealmsRequireOK(ctx, http.MethodGet, path.Join(kcPathPartClients, clientID), nil)
	if err != nil {
		return nil, err
	}
	client = new(Client)
	if err = handleResponse(resp, client); err != nil {
		return nil, err
	}
	return client, nil
}

// Create attempts to create a new client within
func (cs *AdminClientsService) Create(ctx context.Context, client *ClientCreate) ([]string, error) {
	var (
		resp *http.Response
		err  error
	)
	resp, err = cs.kas.callAdminRealmsRequireOK(ctx, http.MethodPost, kcPathPartClients, client, nil)
	if err != nil {
		return nil, err
	}
	return parseResponseLocations(resp)
}

// Update attempts to update a  client in the Realm this client was created with
func (cs *AdminClientsService) Update(ctx context.Context, clientID string, client *Client) error {
	_, err := cs.kas.callAdminRealmsRequireOK(ctx, http.MethodPut, path.Join(kcPathPartClients, clientID), client)
	return err
}

// Delete attempts to delete a  client from the Realm this client was created with
func (cs *AdminClientsService) Delete(ctx context.Context, clientID string) error {
	_, err := cs.kas.callAdminRealmsRequireOK(ctx, http.MethodDelete, path.Join(kcPathPartClients, clientID), nil)
	return err
}

// AdminClientRolesService contains all the methods needed to manage roles associated with a given client
type AdminClientRolesService struct {
	kas      *AdminService
	clientID string
}

// NewAdminClientRolesService returns a new AdminClientRolesService use to manage roles associated with the provided client id
func NewAdminClientRolesService(kas *AdminService, clientID string) *AdminClientRolesService {
	rs := new(AdminClientRolesService)
	rs.kas = kas
	rs.clientID = clientID
	return rs
}

func (k *AdminService) ClientRolesService(clientID string) *AdminClientRolesService {
	return NewAdminClientRolesService(k, clientID)
}

// RolesService returns a new AdminClientRolesService use to manage roles associated with the provided client id
func (cs *AdminClientsService) RolesService(clientID string) *AdminClientRolesService {
	return cs.kas.ClientRolesService(clientID)
}

// List attempts to return all the roles defined with the provided client id
func (rs *AdminClientRolesService) List(ctx context.Context) (Roles, error) {
	var (
		resp  *http.Response
		roles Roles
		err   error
	)
	resp, err = rs.kas.callAdminRealmsRequireOK(ctx, http.MethodGet, path.Join(kcPathPartClients, rs.clientID, kcPathPartRoles), nil)
	if err != nil {
		return nil, err
	}
	roles = make(Roles, 0)
	if err = handleResponse(resp, &roles); err != nil {
		return nil, err
	}
	return roles, nil
}

// Get attempts to locate a single role on a client by the role's name
func (rs *AdminClientRolesService) Get(ctx context.Context, roleName string) (*Role, error) {
	var (
		resp *http.Response
		role *Role
		err  error
	)
	resp, err = rs.kas.callAdminRealmsRequireOK(ctx, http.MethodGet, path.Join(kcPathPartClients, rs.clientID, kcPathPartRoles, roleName), nil)
	if err != nil {
		return nil, err
	}
	role = new(Role)
	if err = handleResponse(resp, role); err != nil {
		return nil, err
	}
	return role, nil
}

// Create attempts to create a new role for the provided client
func (rs *AdminClientRolesService) Create(ctx context.Context, role *Role) ([]string, error) {
	var (
		resp *http.Response
		err  error
	)
	resp, err = rs.kas.callAdminRealmsRequireOK(ctx, http.MethodPost, path.Join(kcPathPartClients, rs.clientID, kcPathPartRoles), role)
	if err != nil {
		return nil, err
	}
	return parseResponseLocations(resp)
}

// Update attempts to update the provided role within
func (rs *AdminClientRolesService) Update(ctx context.Context, roleName string, role *Role) error {
	_, err := rs.kas.callAdminRealmsRequireOK(ctx, http.MethodPut, path.Join(kcPathPartClients, rs.clientID, kcPathPartRoles, roleName), role)
	return err
}

// Delete attempts to delete the specified role
func (rs *AdminClientRolesService) Delete(ctx context.Context, roleName string) error {
	_, err := rs.kas.callAdminRealmsRequireOK(ctx, http.MethodPut, path.Join(kcPathPartClients, rs.clientID, kcPathPartRoles, roleName), nil)
	return err
}

// Users attempts to return a list of all the users who have the specified role within the keycloak realm
func (rs *AdminClientRolesService) Users(ctx context.Context, roleName string, first, max int) (Users, error) {
	var (
		resp  *http.Response
		users Users
		err   error
	)
	resp, err = rs.kas.callAdminRealmsRequireOK(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartClients, rs.clientID, kcPathPartRoles, roleName, kcPathPartUsers),
		nil,
		ValuedQueryMutator("first", first, true),
		ValuedQueryMutator("max", max, true),
	)
	if err != nil {
		return nil, err
	}
	users = make(Users, 0)
	if err = handleResponse(resp, &users); err != nil {
		return nil, err
	}
	return users, nil
}

type AdminClientRoleCompositesService struct {
	kas      *AdminService
	clientID string
	roleName string
}

func NewAdminClientRoleCompositesService(kas *AdminService, clientID, roleName string) *AdminClientRoleCompositesService {
	crs := new(AdminClientRoleCompositesService)
	crs.kas = kas
	crs.clientID = clientID
	crs.roleName = roleName
	return crs
}

func (k *AdminService) ClientRoleCompositesService(clientID, roleName string) *AdminClientRoleCompositesService {
	return NewAdminClientRoleCompositesService(k, clientID, roleName)
}

func (rs *AdminClientRolesService) CompositesService(roleName string) *AdminClientRoleCompositesService {
	return rs.kas.ClientRoleCompositesService(rs.clientID, roleName)
}

// List attempts to return all composite roles that the specified role is a member of
func (crs *AdminClientRoleCompositesService) List(ctx context.Context) (Roles, error) {
	var (
		resp  *http.Response
		roles Roles
		err   error
	)
	resp, err = crs.kas.callAdminRealmsRequireOK(ctx, http.MethodGet, path.Join(kcPathPartClients, crs.clientID, kcPathPartRoles, crs.roleName, kcPathPartComposites), nil)
	if err != nil {
		return nil, err
	}
	roles = make(Roles, 0)
	if err = handleResponse(resp, &roles); err != nil {
		return nil, err
	}
	return roles, nil
}

// Add attempts to add the specified role to the provided composite roles
func (crs *AdminClientRoleCompositesService) Add(ctx context.Context, roles Roles) error {
	_, err := crs.kas.callAdminRealmsRequireOK(ctx, http.MethodPost, path.Join(kcPathPartClients, crs.clientID, kcPathPartRoles, crs.roleName, kcPathPartComposites), roles)
	return err
}

// Remove attempts to remove the provided role from the specified composite roles
func (crs *AdminClientRoleCompositesService) Remove(ctx context.Context, roles Roles) error {
	_, err := crs.kas.callAdminRealmsRequireOK(ctx, http.MethodDelete, path.Join(kcPathPartClients, crs.clientID, kcPathPartRoles, crs.roleName, kcPathPartComposites), roles)
	return err
}
