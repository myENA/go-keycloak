package keycloak

import (
	"context"
	"net/http"
	"path"
	"strconv"
)

type AdminGroupsService struct {
	tc *AdminTokenAPIClient
}

func (tc *AdminTokenAPIClient) GroupsService() *AdminGroupsService {
	gs := new(AdminGroupsService)
	gs.tc = tc
	return gs
}

// List attempts to return to you a list of all the  groups within the Realm this client was created
// with
func (gs *AdminGroupsService) List(ctx context.Context, search string, first, max int, mutators ...RequestMutator) (Groups, error) {
	var (
		resp   *http.Response
		groups Groups
		err    error
	)
	resp, err = gs.tc.callAdminRealms(
		ctx,
		http.MethodGet,
		kcPathPartGroups,
		nil,
		appendRequestMutators(
			mutators,
			ValuedQueryMutator("search", search, true),
			ValuedQueryMutator("first", first, true),
			ValuedQueryMutator("max", max, true),
		)...)
	if err != nil {
		return nil, err
	}
	groups = make(Groups, 0)
	if err = handleResponse(resp, http.StatusOK, &groups, err); err != nil {
		return nil, err
	}
	return groups, nil
}

// Count attempts to return a count of the total number of groups present in
func (gs *AdminGroupsService) Count(ctx context.Context, search string, top bool, mutators ...RequestMutator) (int, error) {
	var (
		resp *http.Response
		err  error

		model = new(struct {
			Count int `json:"count"`
		})
	)
	resp, err = gs.tc.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartGroups, kcPathPartCount),
		nil,
		appendRequestMutators(
			mutators,
			ValuedQueryMutator("search", search, true),
			ValuedQueryMutator("top", strconv.FormatBool(top), true),
		)...)
	if err = handleResponse(resp, http.StatusOK, model, err); err != nil {
		return 0, err
	}
	// ok to return without checking err here as int zero val is same whether there was an error or not
	return model.Count, nil
}

// Get attempts to retrieve details of a specific  group within the realm this client was created with
func (gs *AdminGroupsService) Get(ctx context.Context, groupID string, mutators ...RequestMutator) (*Group, error) {
	var (
		resp  *http.Response
		group *Group
		err   error
	)
	resp, err = gs.tc.callAdminRealms(ctx, http.MethodGet, path.Join(kcPathPartGroups, groupID), nil, mutators...)
	group = new(Group)
	if err = handleResponse(resp, http.StatusOK, group, err); err != nil {
		return nil, err
	}
	return group, nil
}

// Members attempts to return to you a list of all the  Users present in the  group
// specified within the realm this client was created with
func (gs *AdminGroupsService) Members(ctx context.Context, groupID string, mutators ...RequestMutator) (Users, error) {
	var (
		resp    *http.Response
		members Users
		err     error
	)
	resp, err = gs.tc.callAdminRealms(ctx, http.MethodGet, path.Join(kcPathPartGroups, groupID, kcPathPartMembers), nil, mutators...)
	members = make(Users, 0)
	if err = handleResponse(resp, http.StatusOK, &members, err); err != nil {
		return nil, err
	}
	return members, nil
}

// Create attempts to push a new group into , returning to you the InstallDocument of the newly created group.
func (gs *AdminGroupsService) Create(ctx context.Context, group GroupCreate, mutators ...RequestMutator) ([]string, error) {
	var (
		resp *http.Response
		err  error
	)
	resp, err = gs.tc.callAdminRealms(ctx, http.MethodPost, kcPathPartClients, group, mutators...)
	if err = handleResponse(resp, http.StatusOK, nil, err); err != nil {
		return nil, err
	}
	return parseAndReturnLocations(resp)
}

// Delete attempts to delete a group from
func (gs *AdminGroupsService) Delete(ctx context.Context, groupID string, mutators ...RequestMutator) error {
	resp, err := gs.tc.callAdminRealms(ctx, http.MethodDelete, path.Join(kcPathPartGroups, groupID), nil, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}

// Update attempts to push updated values for a specific group to
func (gs *AdminGroupsService) Update(ctx context.Context, groupID string, group Group, mutators ...RequestMutator) error {
	resp, err := gs.tc.callAdminRealms(ctx, http.MethodPut, path.Join(kcPathPartGroups, groupID), group, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}
