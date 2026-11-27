package keycloak

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminWritesAcceptKeycloakStatus(t *testing.T) {
	const userLocation = "http://keycloak.example/admin/realms/realm/users/user-1"

	cases := []struct {
		name       string
		status     int
		method     string
		pathSuffix string
		location   string
		ok         bool
		wantLocErr bool
		wantIDs    []string
		call       func(*AdminAPIClient) ([]string, error)
	}{
		{
			name:       "create user",
			status:     http.StatusCreated,
			method:     http.MethodPost,
			pathSuffix: "/users",
			location:   userLocation,
			ok:         true,
			wantIDs:    []string{userLocation},
			call: func(c *AdminAPIClient) ([]string, error) {
				return c.UsersService().Create(context.Background(), &UserCreate{Username: "ada"})
			},
		},
		{
			name:       "create user rejects ok",
			status:     http.StatusOK,
			method:     http.MethodPost,
			pathSuffix: "/users",
			location:   userLocation,
			call: func(c *AdminAPIClient) ([]string, error) {
				return c.UsersService().Create(context.Background(), &UserCreate{Username: "ada"})
			},
		},
		{
			name:       "create user without location",
			status:     http.StatusCreated,
			method:     http.MethodPost,
			pathSuffix: "/users",
			wantLocErr: true,
			call: func(c *AdminAPIClient) ([]string, error) {
				return c.UsersService().Create(context.Background(), &UserCreate{Username: "ada"})
			},
		},
		{
			name:       "update user",
			status:     http.StatusNoContent,
			method:     http.MethodPut,
			pathSuffix: "/users/user-1",
			ok:         true,
			call: func(c *AdminAPIClient) ([]string, error) {
				return nil, c.UsersService().Update(context.Background(), "user-1", &User{Username: "ada"})
			},
		},
		{
			name:       "update user rejects ok",
			status:     http.StatusOK,
			method:     http.MethodPut,
			pathSuffix: "/users/user-1",
			call: func(c *AdminAPIClient) ([]string, error) {
				return nil, c.UsersService().Update(context.Background(), "user-1", &User{Username: "ada"})
			},
		},
		{
			name:       "delete user",
			status:     http.StatusNoContent,
			method:     http.MethodDelete,
			pathSuffix: "/users/user-1",
			ok:         true,
			call: func(c *AdminAPIClient) ([]string, error) {
				return nil, c.UsersService().Delete(context.Background(), "user-1")
			},
		},
		{
			name:       "delete user rejects ok",
			status:     http.StatusOK,
			method:     http.MethodDelete,
			pathSuffix: "/users/user-1",
			call: func(c *AdminAPIClient) ([]string, error) {
				return nil, c.UsersService().Delete(context.Background(), "user-1")
			},
		},
		{
			name:       "add user to group",
			status:     http.StatusNoContent,
			method:     http.MethodPut,
			pathSuffix: "/users/user-1/groups/group-1",
			ok:         true,
			call: func(c *AdminAPIClient) ([]string, error) {
				return nil, c.UserGroupsService("user-1").Add(context.Background(), "group-1")
			},
		},
		{
			name:       "add user to group rejects ok",
			status:     http.StatusOK,
			method:     http.MethodPut,
			pathSuffix: "/users/user-1/groups/group-1",
			call: func(c *AdminAPIClient) ([]string, error) {
				return nil, c.UserGroupsService("user-1").Add(context.Background(), "group-1")
			},
		},
		{
			name:       "remove user from group",
			status:     http.StatusNoContent,
			method:     http.MethodDelete,
			pathSuffix: "/users/user-1/groups/group-1",
			ok:         true,
			call: func(c *AdminAPIClient) ([]string, error) {
				return nil, c.UserGroupsService("user-1").Remove(context.Background(), "group-1")
			},
		},
		{
			name:       "remove user from group rejects ok",
			status:     http.StatusOK,
			method:     http.MethodDelete,
			pathSuffix: "/users/user-1/groups/group-1",
			call: func(c *AdminAPIClient) ([]string, error) {
				return nil, c.UserGroupsService("user-1").Remove(context.Background(), "group-1")
			},
		},
		{
			name:       "update group",
			status:     http.StatusNoContent,
			method:     http.MethodPut,
			pathSuffix: "/groups/group-1",
			ok:         true,
			call: func(c *AdminAPIClient) ([]string, error) {
				return nil, c.GroupsService().Update(context.Background(), "group-1", Group{Name: "admins"})
			},
		},
		{
			name:       "update group rejects ok",
			status:     http.StatusOK,
			method:     http.MethodPut,
			pathSuffix: "/groups/group-1",
			call: func(c *AdminAPIClient) ([]string, error) {
				return nil, c.GroupsService().Update(context.Background(), "group-1", Group{Name: "admins"})
			},
		},
		{
			name:       "delete group",
			status:     http.StatusNoContent,
			method:     http.MethodDelete,
			pathSuffix: "/groups/group-1",
			ok:         true,
			call: func(c *AdminAPIClient) ([]string, error) {
				return nil, c.GroupsService().Delete(context.Background(), "group-1")
			},
		},
		{
			name:       "delete group rejects ok",
			status:     http.StatusOK,
			method:     http.MethodDelete,
			pathSuffix: "/groups/group-1",
			call: func(c *AdminAPIClient) ([]string, error) {
				return nil, c.GroupsService().Delete(context.Background(), "group-1")
			},
		},
		{
			name:       "update policy",
			status:     http.StatusNoContent,
			method:     http.MethodPut,
			pathSuffix: "/clients/client-1/authz/resource-server/policy/role/policy-1",
			ok:         true,
			call: func(c *AdminAPIClient) ([]string, error) {
				return nil, c.ClientAuthzService("client-1").PolicyUpdate(context.Background(), &PolicyCreateUpdateRequest{
					ID:   "policy-1",
					Type: PolicyTypeRole,
					Name: "readers",
				})
			},
		},
		{
			name:       "update policy rejects created",
			status:     http.StatusCreated,
			method:     http.MethodPut,
			pathSuffix: "/clients/client-1/authz/resource-server/policy/role/policy-1",
			call: func(c *AdminAPIClient) ([]string, error) {
				return nil, c.ClientAuthzService("client-1").PolicyUpdate(context.Background(), &PolicyCreateUpdateRequest{
					ID:   "policy-1",
					Type: PolicyTypeRole,
					Name: "readers",
				})
			},
		},
		{
			name:       "update permission",
			status:     http.StatusNoContent,
			method:     http.MethodPut,
			pathSuffix: "/clients/client-1/authz/resource-server/permission/resource/perm-1",
			ok:         true,
			call: func(c *AdminAPIClient) ([]string, error) {
				return nil, c.ClientAuthzService("client-1").PermissionUpdate(context.Background(), &PermissionCreateUpdateRequest{
					ID:   "perm-1",
					Type: PermissionTypeResource,
					Name: "read-docs",
				})
			},
		},
		{
			name:       "update permission rejects created",
			status:     http.StatusCreated,
			method:     http.MethodPut,
			pathSuffix: "/clients/client-1/authz/resource-server/permission/resource/perm-1",
			call: func(c *AdminAPIClient) ([]string, error) {
				return nil, c.ClientAuthzService("client-1").PermissionUpdate(context.Background(), &PermissionCreateUpdateRequest{
					ID:   "perm-1",
					Type: PermissionTypeResource,
					Name: "read-docs",
				})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotMethod, gotPath string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotMethod = r.Method
				gotPath = r.URL.Path
				_, _ = io.Copy(io.Discard, r.Body)
				_ = r.Body.Close()
				if tc.location != "" {
					w.Header().Set(httpHeaderLocationKey, tc.location)
				}
				w.WriteHeader(tc.status)
			}))
			t.Cleanup(srv.Close)

			client := adminClientForServer(t, srv)
			ids, err := tc.call(client)

			if gotMethod != tc.method {
				t.Fatalf("method = %s, want %s", gotMethod, tc.method)
			}
			if len(gotPath) < len(tc.pathSuffix) || gotPath[len(gotPath)-len(tc.pathSuffix):] != tc.pathSuffix {
				t.Fatalf("path = %s, want suffix %s", gotPath, tc.pathSuffix)
			}

			if !tc.ok {
				if err == nil {
					t.Fatal("expected error")
				}
				if tc.wantLocErr {
					if IsAPIError(err) {
						t.Fatalf("missing location returned API error: %v", err)
					}
					return
				}
				apiErr, isAPI := err.(*APIError)
				if !isAPI || apiErr.ResponseCode != tc.status {
					t.Fatalf("got %v, want API error %d", err, tc.status)
				}
				return
			}

			if err != nil {
				t.Fatal(err)
			}
			if len(ids) != len(tc.wantIDs) {
				t.Fatalf("ids = %#v, want %#v", ids, tc.wantIDs)
			}
			for i := range tc.wantIDs {
				if ids[i] != tc.wantIDs[i] {
					t.Fatalf("ids = %#v, want %#v", ids, tc.wantIDs)
				}
			}
		})
	}
}

func adminClientForServer(t *testing.T, srv *httptest.Server) *AdminAPIClient {
	t.Helper()
	cfg := DefaultAPIClientConfig()
	cfg.AuthServerURLProvider = NewAuthServerURLProvider(srv.URL)
	cfg.HTTPClient = srv.Client()
	client, err := NewAPIClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return client.AdminClient("realm", nil)
}
