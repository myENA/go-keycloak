package keycloak

import (
	"context"
	"net/http"
	"path"
)

type AdminUsersService struct {
	tc *AdminTokenAPIClient
}

func (tc *AdminTokenAPIClient) UsersService() *AdminUsersService {
	us := new(AdminUsersService)
	us.tc = tc
	return us
}

// List attempts to retrieve a list of users from
func (us *AdminUsersService) List(ctx context.Context, email, firstName, lastName, username, search string, first, max int, mutators ...RequestMutator) (Users, error) {
	var (
		resp  *http.Response
		users Users
		err   error
	)
	resp, err = us.tc.callAdminRealms(
		ctx,
		http.MethodGet,
		kcPathPartUsers,
		nil,
		appendRequestMutators(
			mutators,
			ValuedQueryMutator("email", email, true),
			ValuedQueryMutator("firstName", firstName, true),
			ValuedQueryMutator("lastName", lastName, true),
			ValuedQueryMutator("username", username, true),
			ValuedQueryMutator("search", search, true),
			ValuedQueryMutator("first", first, true),
			ValuedQueryMutator("max", max, true),
		)...)
	users = make(Users, 0)
	if err = handleResponse(resp, http.StatusOK, &users, err); err != nil {
		return nil, err
	}
	return users, nil
}

// Count attempts to get a count of all users currently in a keycloak realm
func (us *AdminUsersService) Count(ctx context.Context, mutators ...RequestMutator) (int, error) {
	var (
		resp  *http.Response
		count int
		err   error
	)
	resp, err = us.tc.callAdminRealms(ctx, http.MethodGet, path.Join(kcPathPartUsers, kcPathPartCount), nil, mutators...)
	// ok to not check handle response separately as zero-val for int is same whether or not there is an error
	return count, handleResponse(resp, http.StatusOK, &count, err)
}

// Get attempts to query  for a specific user based on their InstallDocument
func (us *AdminUsersService) Get(ctx context.Context, userID string, mutators ...RequestMutator) (*User, error) {
	var (
		resp *http.Response
		user *User
		err  error
	)
	resp, err = us.tc.callAdminRealms(ctx, http.MethodGet, path.Join(kcPathPartUsers, userID), nil, mutators...)
	user = new(User)
	if err = handleResponse(resp, http.StatusOK, user, err); err != nil {
		return nil, err
	}
	return user, nil
}

// Create attempts to add a user to a keycloak realm
func (us *AdminUsersService) Create(ctx context.Context, user *UserCreate, mutators ...RequestMutator) ([]string, error) {
	var (
		resp *http.Response
		err  error
	)
	resp, err = us.tc.callAdminRealms(ctx, http.MethodPost, kcPathPartUsers, user, mutators...)
	if err = handleResponse(resp, http.StatusOK, nil, err); err != nil {
		return nil, err
	}
	return parseAndReturnLocations(resp)
}

// Update attempts to push an updated user definition
func (us *AdminUsersService) Update(ctx context.Context, userID string, user *User, mutators ...RequestMutator) error {
	resp, err := us.tc.callAdminRealms(ctx, http.MethodPut, path.Join(kcPathPartUsers, userID), user, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}

// Delete attempts to delete a user from the keycloak realm
func (us *AdminUsersService) Delete(ctx context.Context, userID string, mutators ...RequestMutator) error {
	resp, err := us.tc.callAdminRealms(ctx, http.MethodDelete, path.Join(kcPathPartUsers, userID), nil, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}

type AdminUserGroupsService struct {
	kas    *AdminTokenAPIClient
	userID string
}

func (tc *AdminTokenAPIClient) UserGroupsService(userID string) *AdminUserGroupsService {
	gs := new(AdminUserGroupsService)
	gs.kas = tc
	gs.userID = userID
	return gs
}

func (us *AdminUsersService) GroupsService(userID string) *AdminUserGroupsService {
	return us.tc.UserGroupsService(userID)
}

// List attempts to return the list of  groups the provided User is a member of
func (gs *AdminUserGroupsService) List(ctx context.Context, mutators ...RequestMutator) (Groups, error) {
	var (
		resp   *http.Response
		groups Groups
		err    error
	)
	resp, err = gs.kas.callAdminRealms(ctx, http.MethodGet, path.Join(kcPathPartUsers, gs.userID, kcPathPartGroups), nil, mutators...)
	groups = make(Groups, 0)
	if err = handleResponse(resp, http.StatusOK, &groups, err); err != nil {
		return nil, err
	}
	return groups, nil
}

// Add attempts to add the service user to the specified group
func (gs *AdminUserGroupsService) Add(ctx context.Context, groupID string, mutators ...RequestMutator) error {
	resp, err := gs.kas.callAdminRealms(ctx, http.MethodPut, path.Join(kcPathPartUsers, gs.userID, kcPathPartGroups, groupID), nil, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}

// Remove attempts to remove the service user from the specified group
func (gs *AdminUserGroupsService) Remove(ctx context.Context, groupID string, mutators ...RequestMutator) error {
	resp, err := gs.kas.callAdminRealms(ctx, http.MethodDelete, path.Join(kcPathPartUsers, gs.userID, kcPathPartGroups, groupID), nil, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}

type AdminUserRoleMappingsService struct {
	kas    *AdminTokenAPIClient
	userID string
}

func (tc *AdminTokenAPIClient) UserRoleMappingsService(userID string) *AdminUserRoleMappingsService {
	rms := new(AdminUserRoleMappingsService)
	rms.kas = tc
	rms.userID = userID
	return rms
}

func (us *AdminUsersService) RoleMappingService(userID string) *AdminUserRoleMappingsService {
	return us.tc.UserRoleMappingsService(userID)
}

func (rms *AdminUserRoleMappingsService) Get(ctx context.Context, mutators ...RequestMutator) (*RoleMapping, error) {
	var (
		resp        *http.Response
		roleMapping *RoleMapping
		err         error
	)
	resp, err = rms.kas.callAdminRealms(ctx, http.MethodGet, path.Join(kcPathPartUsers, rms.userID, kcPathPartRoleMappings), nil, mutators...)
	roleMapping = new(RoleMapping)
	if err = handleResponse(resp, http.StatusOK, roleMapping, err); err != nil {
		return nil, err
	}
	return roleMapping, nil
}

type AdminUserRoleMappingRealmsService struct {
	kas    *AdminTokenAPIClient
	userID string
}

func (tc *AdminTokenAPIClient) UserRoleMappingRealmsService(userID string) *AdminUserRoleMappingRealmsService {
	rms := new(AdminUserRoleMappingRealmsService)
	rms.kas = tc
	rms.userID = userID
	return rms
}

func (rms *AdminUserRoleMappingsService) RealmsService() *AdminUserRoleMappingRealmsService {
	return rms.kas.UserRoleMappingRealmsService(rms.userID)
}

func (rms *AdminUserRoleMappingRealmsService) List(ctx context.Context, mutators ...RequestMutator) (Roles, error) {
	var (
		resp  *http.Response
		roles Roles
		err   error
	)
	resp, err = rms.kas.callAdminRealms(ctx, http.MethodGet, path.Join(kcPathPartUsers, rms.userID, kcPathPartRoleMappings, kcPathPartRealm), nil, mutators...)
	roles = make(Roles, 0)
	if err = handleResponse(resp, http.StatusOK, &roles, err); err != nil {
		return nil, err
	}
	return roles, nil
}

func (rms *AdminUserRoleMappingRealmsService) Available(ctx context.Context, mutators ...RequestMutator) (Roles, error) {
	var (
		resp  *http.Response
		roles Roles
		err   error
	)
	resp, err = rms.kas.callAdminRealms(
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
