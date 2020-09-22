package keycloak

import (
	"context"
	"net/http"
	"path"
)

type AdminUsersService struct {
	c *AdminAPIClient
}

func (c *AdminAPIClient) UsersService() *AdminUsersService {
	us := new(AdminUsersService)
	us.c = c
	return us
}

// List attempts to retrieve a list of users from
func (us *AdminUsersService) List(ctx context.Context, email, firstName, lastName, username, search string, first, max int, mutators ...APIRequestMutator) (Users, error) {
	var (
		resp  *http.Response
		users Users
		err   error
	)
	resp, err = us.c.callAdminRealms(
		ctx,
		http.MethodGet,
		kcPathPartUsers,
		nil,
		requestMutators(
			mutators,
			NonZeroQueryMutator("email", email, nil, true),
			NonZeroQueryMutator("firstName", firstName, nil, true),
			NonZeroQueryMutator("lastName", lastName, nil, true),
			NonZeroQueryMutator("username", username, nil, true),
			NonZeroQueryMutator("search", search, nil, true),
			QueryMutator("first", first, true),
			NonZeroQueryMutator("max", max, 20, true),
		)...)
	users = make(Users, 0)
	if err = handleResponse(resp, http.StatusOK, &users, err); err != nil {
		return nil, err
	}
	return users, nil
}

// Count attempts to get a count of all users currently in a keycloak realm
func (us *AdminUsersService) Count(ctx context.Context, mutators ...APIRequestMutator) (int, error) {
	var (
		resp  *http.Response
		count int
		err   error
	)
	resp, err = us.c.callAdminRealms(ctx, http.MethodGet, path.Join(kcPathPartUsers, kcPathPartCount), nil, mutators...)
	// ok to not check handle response separately as zero-val for int is same whether or not there is an error
	return count, handleResponse(resp, http.StatusOK, &count, err)
}

// Get attempts to query  for a specific user based on their InstallDocument
func (us *AdminUsersService) Get(ctx context.Context, userID string, mutators ...APIRequestMutator) (*User, error) {
	var (
		resp *http.Response
		user *User
		err  error
	)
	resp, err = us.c.callAdminRealms(ctx, http.MethodGet, path.Join(kcPathPartUsers, userID), nil, mutators...)
	user = new(User)
	if err = handleResponse(resp, http.StatusOK, user, err); err != nil {
		return nil, err
	}
	return user, nil
}

// Create attempts to add a user to a keycloak realm
func (us *AdminUsersService) Create(ctx context.Context, user *UserCreate, mutators ...APIRequestMutator) ([]string, error) {
	var (
		resp *http.Response
		err  error
	)
	resp, err = us.c.callAdminRealms(ctx, http.MethodPost, kcPathPartUsers, user, mutators...)
	if err = handleResponse(resp, http.StatusOK, nil, err); err != nil {
		return nil, err
	}
	return parseResponseLocations(resp)
}

// Update attempts to push an updated user definition
func (us *AdminUsersService) Update(ctx context.Context, userID string, user *User, mutators ...APIRequestMutator) error {
	resp, err := us.c.callAdminRealms(ctx, http.MethodPut, path.Join(kcPathPartUsers, userID), user, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}

// Delete attempts to delete a user from the keycloak realm
func (us *AdminUsersService) Delete(ctx context.Context, userID string, mutators ...APIRequestMutator) error {
	resp, err := us.c.callAdminRealms(ctx, http.MethodDelete, path.Join(kcPathPartUsers, userID), nil, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}

type AdminUserGroupsService struct {
	c      *AdminAPIClient
	userID string
}

func (c *AdminAPIClient) UserGroupsService(userID string) *AdminUserGroupsService {
	gs := new(AdminUserGroupsService)
	gs.c = c
	gs.userID = userID
	return gs
}

func (us *AdminUsersService) GroupsService(userID string) *AdminUserGroupsService {
	return us.c.UserGroupsService(userID)
}

// List attempts to return the list of  groups the provided User is a member of
func (gs *AdminUserGroupsService) List(ctx context.Context, mutators ...APIRequestMutator) (Groups, error) {
	var (
		resp   *http.Response
		groups Groups
		err    error
	)
	resp, err = gs.c.callAdminRealms(ctx, http.MethodGet, path.Join(kcPathPartUsers, gs.userID, kcPathPartGroups), nil, mutators...)
	groups = make(Groups, 0)
	if err = handleResponse(resp, http.StatusOK, &groups, err); err != nil {
		return nil, err
	}
	return groups, nil
}

// Add attempts to add the service user to the specified group
func (gs *AdminUserGroupsService) Add(ctx context.Context, groupID string, mutators ...APIRequestMutator) error {
	resp, err := gs.c.callAdminRealms(ctx, http.MethodPut, path.Join(kcPathPartUsers, gs.userID, kcPathPartGroups, groupID), nil, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}

// Remove attempts to remove the service user from the specified group
func (gs *AdminUserGroupsService) Remove(ctx context.Context, groupID string, mutators ...APIRequestMutator) error {
	resp, err := gs.c.callAdminRealms(ctx, http.MethodDelete, path.Join(kcPathPartUsers, gs.userID, kcPathPartGroups, groupID), nil, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}

type AdminUserRoleMappingsService struct {
	c      *AdminAPIClient
	userID string
}

func (c *AdminAPIClient) UserRoleMappingsService(userID string) *AdminUserRoleMappingsService {
	rms := new(AdminUserRoleMappingsService)
	rms.c = c
	rms.userID = userID
	return rms
}

func (us *AdminUsersService) RoleMappingService(userID string) *AdminUserRoleMappingsService {
	return us.c.UserRoleMappingsService(userID)
}

func (rms *AdminUserRoleMappingsService) Get(ctx context.Context, mutators ...APIRequestMutator) (*RoleMapping, error) {
	var (
		resp        *http.Response
		roleMapping *RoleMapping
		err         error
	)
	resp, err = rms.c.callAdminRealms(ctx, http.MethodGet, path.Join(kcPathPartUsers, rms.userID, kcPathPartRoleMappings), nil, mutators...)
	roleMapping = new(RoleMapping)
	if err = handleResponse(resp, http.StatusOK, roleMapping, err); err != nil {
		return nil, err
	}
	return roleMapping, nil
}

type AdminUserRoleMappingRealmsService struct {
	c      *AdminAPIClient
	userID string
}

func (c *AdminAPIClient) UserRoleMappingRealmsService(userID string) *AdminUserRoleMappingRealmsService {
	rms := new(AdminUserRoleMappingRealmsService)
	rms.c = c
	rms.userID = userID
	return rms
}

func (rms *AdminUserRoleMappingsService) RealmsService() *AdminUserRoleMappingRealmsService {
	return rms.c.UserRoleMappingRealmsService(rms.userID)
}

func (rms *AdminUserRoleMappingRealmsService) List(ctx context.Context, mutators ...APIRequestMutator) (Roles, error) {
	var (
		resp  *http.Response
		roles Roles
		err   error
	)
	resp, err = rms.c.callAdminRealms(ctx, http.MethodGet, path.Join(kcPathPartUsers, rms.userID, kcPathPartRoleMappings, kcPathPartRealm), nil, mutators...)
	roles = make(Roles, 0)
	if err = handleResponse(resp, http.StatusOK, &roles, err); err != nil {
		return nil, err
	}
	return roles, nil
}

func (rms *AdminUserRoleMappingRealmsService) Available(ctx context.Context, mutators ...APIRequestMutator) (Roles, error) {
	var (
		resp  *http.Response
		roles Roles
		err   error
	)
	resp, err = rms.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartUsers, rms.userID, kcPathPartRoleMappings, kcPathPartRealm, kcPathPartAvailable),
		nil,
		mutators...)
	roles = make(Roles, 0)
	if err = handleResponse(resp, http.StatusOK, &roles, err); err != nil {
		return nil, err
	}
	return roles, nil
}
