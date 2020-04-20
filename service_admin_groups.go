package keycloak

import (
	"context"
	"net/http"
	"path"
	"strconv"
)

type AdminGroupsService struct {
	kas *AdminService
}

func NewAdminGroupsService(kas *AdminService) *AdminGroupsService {
	gs := new(AdminGroupsService)
	gs.kas = kas
	return gs
}

func (k *AdminService) GroupsService() *AdminGroupsService {
	return NewAdminGroupsService(k)
}

// List attempts to return to you a list of all the  groups within the Realm this client was created
// with
func (gs *AdminGroupsService) List(ctx context.Context, search string, first, max int) (Groups, error) {
	var (
		resp   *http.Response
		groups Groups
		err    error
	)
	resp, err = gs.kas.callAdminRealmsRequireOK(
		ctx,
		http.MethodGet,
		kcPathPartGroups,
		nil,
		ValuedQueryMutator("search", search, true),
		ValuedQueryMutator("first", first, true),
		ValuedQueryMutator("max", max, true))
	if err != nil {
		return nil, err
	}
	groups = make(Groups, 0)
	if err = handleResponse(resp, &groups); err != nil {
		return nil, err
	}
	return groups, nil
}

// Count attempts to return a count of the total number of groups present in
func (gs *AdminGroupsService) Count(ctx context.Context, search string, top bool) (int, error) {
	var (
		resp *http.Response
		err  error

		model = new(struct {
			Count int `json:"count"`
		})
	)
	resp, err = gs.kas.callAdminRealmsRequireOK(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartGroups, kcPathPartCount),
		nil,
		ValuedQueryMutator("search", search, true),
		ValuedQueryMutator("top", strconv.FormatBool(top), true))
	if err != nil {
		return 0, err
	}
	// ok to return without checking err here as int zero val is same whether there was an error or not
	return model.Count, handleResponse(resp, model)
}

// Get attempts to retrieve details of a specific  group within the realm this client was created with
func (gs *AdminGroupsService) Get(ctx context.Context, groupID string) (*Group, error) {
	var (
		resp  *http.Response
		group *Group
		err   error
	)
	resp, err = gs.kas.callAdminRealmsRequireOK(ctx, http.MethodGet, path.Join(kcPathPartGroups, groupID), nil)
	if err != nil {
		return nil, err
	}
	group = new(Group)
	if err = handleResponse(resp, group); err != nil {
		return nil, err
	}
	return group, nil
}

// Members attempts to return to you a list of all the  Users present in the  group
// specified within the realm this client was created with
func (gs *AdminGroupsService) Members(ctx context.Context, groupID string) (Users, error) {
	var (
		resp    *http.Response
		members Users
		err     error
	)
	resp, err = gs.kas.callAdminRealmsRequireOK(ctx, http.MethodGet, path.Join(kcPathPartGroups, groupID, kcPathPartMembers), nil)
	if err != nil {
		return nil, err
	}
	members = make(Users, 0)
	if err = handleResponse(resp, &members); err != nil {
		return nil, err
	}
	return members, nil
}

// Create attempts to push a new group into , returning to you the ID of the newly created group.
func (gs *AdminGroupsService) Create(ctx context.Context, group GroupCreate) ([]string, error) {
	var (
		resp *http.Response
		err  error
	)
	resp, err = gs.kas.callAdminRealmsRequireOK(ctx, http.MethodPost, kcPathPartClients, group)
	if err != nil {
		return nil, err
	}
	return parseAndReturnLocations(resp)
}

// Delete attempts to delete a group from
func (gs *AdminGroupsService) Delete(ctx context.Context, groupID string) error {
	_, err := gs.kas.callAdminRealmsRequireOK(ctx, http.MethodDelete, path.Join(kcPathPartGroups, groupID), nil)
	return err
}

// Update attempts to push updated values for a specific group to
func (gs *AdminGroupsService) Update(ctx context.Context, groupID string, group Group) error {
	_, err := gs.kas.callAdminRealmsRequireOK(ctx, http.MethodPut, path.Join(kcPathPartGroups, groupID), group)
	return err
}
