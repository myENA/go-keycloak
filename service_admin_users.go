package keycloak

import (
	"context"
	"net/http"
	"path"
)

type AdminUsersService struct {
	kas *AdminService
}

func NewAdminUsersService(kas *AdminService) *AdminUsersService {
	us := new(AdminUsersService)
	us.kas = kas
	return us
}

func (k *AdminService) UsersService() *AdminUsersService {
	return NewAdminUsersService(k)
}

// List attempts to retrieve a list of users from
func (us *AdminUsersService) List(ctx context.Context, email, firstName, lastName, username, search string, first, max int) (Users, error) {
	var (
		resp  *http.Response
		users Users
		err   error
	)
	resp, err = us.kas.callAdminRealmsRequireOK(
		ctx,
		http.MethodGet,
		kcPathPartUsers,
		nil,
		ValuedQueryMutator("email", email, true),
		ValuedQueryMutator("firstName", firstName, true),
		ValuedQueryMutator("lastName", lastName, true),
		ValuedQueryMutator("username", username, true),
		ValuedQueryMutator("search", search, true),
		ValuedQueryMutator("first", first, true),
		ValuedQueryMutator("max", max, true))
	if err != nil {
		return nil, err
	}
	users = make(Users, 0)
	if err = handleResponse(resp, &users); err != nil {
		return nil, err
	}
	return users, nil
}

// Count attempts to get a count of all users currently in a keycloak realm
func (us *AdminUsersService) Count(ctx context.Context) (int, error) {
	var (
		resp  *http.Response
		count int
		err   error
	)
	resp, err = us.kas.callAdminRealmsRequireOK(ctx, http.MethodGet, path.Join(kcPathPartUsers, kcPathPartCount), nil)
	if err != nil {
		return 0, err
	}
	// ok to not check handle response separately as zero-val for int is same whether or not there is an error
	return count, handleResponse(resp, &count)
}

// Get attempts to query  for a specific user based on their ID
func (us *AdminUsersService) Get(ctx context.Context, userID string) (*User, error) {
	var (
		resp *http.Response
		user *User
		err  error
	)
	resp, err = us.kas.callAdminRealmsRequireOK(ctx, http.MethodGet, path.Join(kcPathPartUsers, userID), nil)
	if err != nil {
		return nil, err
	}
	user = new(User)
	if err = handleResponse(resp, user); err != nil {
		return nil, err
	}
	return user, nil
}

// Create attempts to add a user to a keycloak realm
func (us *AdminUsersService) Create(ctx context.Context, user *UserCreate) ([]string, error) {
	var (
		resp *http.Response
		err  error
	)
	resp, err = us.kas.callAdminRealmsRequireOK(ctx, http.MethodPost, kcPathPartUsers, user)
	if err != nil {
		return nil, err
	}
	return parseAndReturnLocations(resp)
}

// Update attempts to push an updated user definition
func (us *AdminUsersService) Update(ctx context.Context, userID string, user *User) error {
	_, err := us.kas.callAdminRealmsRequireOK(ctx, http.MethodPut, path.Join(kcPathPartUsers, userID), user)
	return err
}

// Delete attempts to delete a user from the keycloak realm
func (us *AdminUsersService) Delete(ctx context.Context, userID string) error {
	_, err := us.kas.callAdminRealmsRequireOK(ctx, http.MethodDelete, path.Join(kcPathPartUsers, userID), nil)
	return err
}

type AdminUserGroupsService struct {
	kas    *AdminService
	userID string
}

func NewAdminUserGroupsService(kas *AdminService, userID string) *AdminUserGroupsService {
	gs := new(AdminUserGroupsService)
	gs.kas = kas
	gs.userID = userID
	return gs
}

func (k *AdminService) UserGroupsService(userID string) *AdminUserGroupsService {
	return NewAdminUserGroupsService(k, userID)
}

func (us *AdminUsersService) GroupsService(userID string) *AdminUserGroupsService {
	return us.kas.UserGroupsService(userID)
}

// List attempts to return the list of  groups the provided User is a member of
func (gs *AdminUserGroupsService) List(ctx context.Context) (Groups, error) {
	var (
		resp   *http.Response
		groups Groups
		err    error
	)
	resp, err = gs.kas.callAdminRealmsRequireOK(ctx, http.MethodGet, path.Join(kcPathPartUsers, gs.userID, kcPathPartGroups), nil)
	if err != nil {
		return nil, err
	}
	groups = make(Groups, 0)
	if err = handleResponse(resp, &groups); err != nil {
		return nil, err
	}
	return groups, nil
}

// Add attempts to add the service user to the specified group
func (gs *AdminUserGroupsService) Add(ctx context.Context, groupID string) error {
	_, err := gs.kas.callAdminRealmsRequireOK(ctx, http.MethodPut, path.Join(kcPathPartUsers, gs.userID, kcPathPartGroups, groupID), nil)
	return err
}

// Remove attempts to remove the service user from the specified group
func (gs *AdminUserGroupsService) Remove(ctx context.Context, groupID string) error {
	_, err := gs.kas.callAdminRealmsRequireOK(ctx, http.MethodDelete, path.Join(kcPathPartUsers, gs.userID, kcPathPartGroups, groupID), nil)
	return err
}

type AdminUserRoleMappingsService struct {
	kas    *AdminService
	userID string
}

func NewAdminUserRoleMappingsService(kas *AdminService, userID string) *AdminUserRoleMappingsService {
	rms := new(AdminUserRoleMappingsService)
	rms.kas = kas
	rms.userID = userID
	return rms
}

func (k *AdminService) UserRoleMappingsService(userID string) *AdminUserRoleMappingsService {
	return NewAdminUserRoleMappingsService(k, userID)
}

func (us *AdminUsersService) RoleMappingService(userID string) *AdminUserRoleMappingsService {
	return us.kas.UserRoleMappingsService(userID)
}

func (rms *AdminUserRoleMappingsService) Get(ctx context.Context) (*RoleMapping, error) {
	var (
		resp        *http.Response
		roleMapping *RoleMapping
		err         error
	)
	resp, err = rms.kas.callAdminRealmsRequireOK(ctx, http.MethodGet, path.Join(kcPathPartUsers, rms.userID, kcPathPartRoleMappings), nil)
	if err != nil {
		return nil, err
	}
	roleMapping = new(RoleMapping)
	if err = handleResponse(resp, roleMapping); err != nil {
		return nil, err
	}
	return roleMapping, nil
}

type AdminUserRoleMappingRealmsService struct {
	kas    *AdminService
	userID string
}

func NewAdminUserRoleMappingRealmsService(kas *AdminService, userID string) *AdminUserRoleMappingRealmsService {
	rms := new(AdminUserRoleMappingRealmsService)
	rms.kas = kas
	rms.userID = userID
	return rms
}

func (k *AdminService) UserRoleMappingRealmsService(userID string) *AdminUserRoleMappingRealmsService {
	return NewAdminUserRoleMappingRealmsService(k, userID)
}

func (rms *AdminUserRoleMappingsService) RealmsService() *AdminUserRoleMappingRealmsService {
	return rms.kas.UserRoleMappingRealmsService(rms.userID)
}

func (rms *AdminUserRoleMappingRealmsService) List(ctx context.Context) (Roles, error) {
	var (
		resp  *http.Response
		roles Roles
		err   error
	)
	resp, err = rms.kas.callAdminRealmsRequireOK(ctx, http.MethodGet, path.Join(kcPathPartUsers, rms.userID, kcPathPartRoleMappings, kcPathPartRealm), nil)
	if err != nil {
		return nil, err
	}
	roles = make(Roles, 0)
	if err = handleResponse(resp, &roles); err != nil {
		return nil, err
	}
	return roles, nil
}

func (rms *AdminUserRoleMappingRealmsService) Available(ctx context.Context) (Roles, error) {
	var (
		resp  *http.Response
		roles Roles
		err   error
	)
	resp, err = rms.kas.callAdminRealmsRequireOK(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartUsers, rms.userID, kcPathPartRoleMappings, kcPathPartRealm, kcPathPartAvailable),
		nil,
	)
	if err != nil {
		return nil, err
	}
	roles = make(Roles, 0)
	if err = handleResponse(resp, &roles); err != nil {
		return nil, err
	}
	return roles, nil
}
