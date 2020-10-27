package keycloak

import (
	"context"
	"net/http"
	"path"
	"strconv"
)

type AdminGroupsService struct {
	c *AdminAPIClient
}

func (c *AdminAPIClient) GroupsService() *AdminGroupsService {
	gs := new(AdminGroupsService)
	gs.c = c
	return gs
}

func (gs *AdminGroupsService) List(ctx context.Context, search string, first, max int, mutators ...APIRequestMutator) (Groups, error) {
	var (
		resp *http.Response
		err  error

		groups = make(Groups, 0)
	)
	resp, err = gs.c.callAdminRealms(
		ctx,
		http.MethodGet,
		kcPathPartGroups,
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
			NonZeroQueryMutator("search", search, nil, true),
			QueryMutator("first", first, true),
			NonZeroQueryMutator("max", max, 20, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusOK, &groups, err); err != nil {
		return nil, err
	}
	return groups, nil
}

func (gs *AdminGroupsService) Count(ctx context.Context, search string, top bool, mutators ...APIRequestMutator) (int, error) {
	var (
		resp *http.Response
		err  error

		model = new(struct {
			Count int `json:"count"`
		})
	)
	resp, err = gs.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartGroups, kcPathPartCount),
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
			NonZeroQueryMutator("search", search, nil, true),
			NonZeroQueryMutator("top", strconv.FormatBool(top), nil, true),
		)...)
	if err = handleResponse(resp, http.StatusOK, model, err); err != nil {
		return 0, err
	}
	// ok to return without checking err here as int zero val is same whether there was an error or not
	return model.Count, nil
}

func (gs *AdminGroupsService) Get(ctx context.Context, groupID string, mutators ...APIRequestMutator) (*Group, error) {
	var (
		resp *http.Response
		err  error

		group = new(Group)
	)
	resp, err = gs.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartGroups, groupID),
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusOK, group, err); err != nil {
		return nil, err
	}
	return group, nil
}

func (gs *AdminGroupsService) Members(ctx context.Context, groupID string, mutators ...APIRequestMutator) (Users, error) {
	var (
		resp *http.Response
		err  error

		members = make(Users, 0)
	)
	resp, err = gs.c.callAdminRealms(
		ctx,
		http.MethodGet,
		path.Join(kcPathPartGroups, groupID, kcPathPartMembers),
		nil,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusOK, &members, err); err != nil {
		return nil, err
	}
	return members, nil
}

func (gs *AdminGroupsService) Create(ctx context.Context, body GroupCreate, mutators ...APIRequestMutator) ([]string, error) {
	var (
		resp *http.Response
		err  error
	)
	resp, err = gs.c.callAdminRealms(
		ctx,
		http.MethodPost,
		kcPathPartGroups,
		body,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderContentType, httpHeaderValueJSON, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusCreated, nil, err); err != nil {
		return nil, err
	}
	return parseResponseLocations(resp)
}

func (gs *AdminGroupsService) Delete(ctx context.Context, groupID string, mutators ...APIRequestMutator) error {
	resp, err := gs.c.callAdminRealms(ctx, http.MethodDelete, path.Join(kcPathPartGroups, groupID), nil, mutators...)
	return handleResponse(resp, http.StatusOK, nil, err)
}

func (gs *AdminGroupsService) Update(ctx context.Context, groupID string, group Group, mutators ...APIRequestMutator) error {
	resp, err := gs.c.callAdminRealms(
		ctx,
		http.MethodPut,
		path.Join(kcPathPartGroups, groupID),
		group,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderAccept, httpHeaderValueJSON, true),
			HeaderMutator(httpHeaderContentType, httpHeaderValueJSON, true),
		)...,
	)
	return handleResponse(resp, http.StatusOK, nil, err)
}

func (gs *AdminGroupsService) CreateChild(ctx context.Context, parentGroupID string, body GroupCreate, mutators ...APIRequestMutator) ([]string, error) {
	var (
		resp *http.Response
		err  error
	)
	resp, err = gs.c.callAdminRealms(
		ctx,
		http.MethodPost,
		path.Join(kcPathPartGroups, parentGroupID, kcPathPartChildren),
		body,
		requestMutators(
			mutators,
			HeaderMutator(httpHeaderContentType, httpHeaderValueJSON, true),
		)...,
	)
	if err = handleResponse(resp, http.StatusCreated, nil, err); err != nil {
		return nil, err
	}
	return parseResponseLocations(resp)
}
