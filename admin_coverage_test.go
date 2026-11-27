package keycloak

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
)

func TestAdminServiceCoverage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = readBody(r)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPost:
			w.Header().Set(httpHeaderLocationKey, "http://keycloak.example/admin/realms/realm/any/new-id")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"new-1","_id":"res-1","name":"n"}`))
		case http.MethodPut, http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(adminGETBody(r)))
		}
	}))
	t.Cleanup(srv.Close)
	client := adminClientForServer(t, srv)
	ctx := context.Background()

	t.Run("users", func(t *testing.T) {
		users := client.UsersService()
		_, err := users.List(ctx, "a@b.c", "Ada", "Lovelace", "ada", "ada", 0, 10)
		step(t, "list", err)
		_, err = users.List(ctx, "", "", "", "", "", 0, 0)
		step(t, "list defaults", err)
		_, err = users.Count(ctx)
		step(t, "count", err)
		_, err = users.Get(ctx, "user-1", HeaderMutator("X-Test", "1", true))
		step(t, "get", err)
		_, err = users.Create(ctx, &UserCreate{Username: "ada"})
		step(t, "create", err)
		step(t, "update", users.Update(ctx, "user-1", &User{Username: "ada"}))
		step(t, "delete", users.Delete(ctx, "user-1"))

		groups := users.GroupsService("user-1")
		_, err = groups.List(ctx)
		step(t, "groups", err)
		step(t, "add group", groups.Add(ctx, "group-1"))
		step(t, "remove group", groups.Remove(ctx, "group-1"))

		mappings := users.RoleMappingService("user-1")
		_, err = mappings.Get(ctx)
		step(t, "mappings", err)
		realms := mappings.RealmsService()
		_, err = realms.List(ctx)
		step(t, "realm roles", err)
		_, err = realms.Available(ctx)
		step(t, "available roles", err)
	})

	t.Run("groups", func(t *testing.T) {
		groups := client.GroupsService()
		_, err := groups.List(ctx, "adm", 0, 10)
		step(t, "list", err)
		_, err = groups.Count(ctx, "adm", true)
		step(t, "count", err)
		_, err = groups.Get(ctx, "group-1")
		step(t, "get", err)
		_, err = groups.Members(ctx, "group-1")
		step(t, "members", err)
		_, err = groups.Create(ctx, GroupCreate{Name: "admins"})
		step(t, "create", err)
		_, err = groups.CreateAndGet(ctx, GroupCreate{Name: "admins"})
		step(t, "create and get", err)
		step(t, "update", groups.Update(ctx, "group-1", Group{Name: "admins"}))
		step(t, "delete", groups.Delete(ctx, "group-1"))
		_, err = groups.CreateChild(ctx, "group-1", GroupCreate{Name: "nested"})
		step(t, "child", err)
		_, err = groups.CreateAndGetChild(ctx, "group-1", GroupCreate{Name: "nested"})
		step(t, "child and get", err)
	})

	t.Run("roles", func(t *testing.T) {
		roles := client.RoleService()
		_, err := roles.RealmRoles(ctx, 0, 10)
		step(t, "realm roles", err)
		_, err = roles.ClientRoles(ctx, "client-1", 0, 10)
		step(t, "client roles", err)
		_, err = roles.RealmRoleUsers(ctx, "reader", 0, 10)
		step(t, "realm users", err)
		_, err = roles.ClientRoleUsers(ctx, "client-1", "reader", 0, 10)
		step(t, "client users", err)
		_, err = roles.Get(ctx, "role-1")
		step(t, "get", err)
		_, err = roles.RealmRoleCreate(ctx, &RoleCreateRequest{Name: "reader"})
		step(t, "create realm", err)
		_, err = roles.RealmRoleCreateAndGet(ctx, &RoleCreateRequest{Name: "reader"})
		step(t, "create realm and get", err)
		_, err = roles.ClientRoleCreate(ctx, "client-1", &RoleCreateRequest{Name: "reader"})
		step(t, "create client", err)
		_, err = roles.ClientRoleCreateAndGet(ctx, "client-1", &RoleCreateRequest{Name: "reader"})
		step(t, "create client and get", err)
		step(t, "update", roles.Update(ctx, &Role{ID: "role-1", Name: "reader"}))
		_, err = roles.UpdateAndGet(ctx, &Role{ID: "role-1", Name: "reader"})
		step(t, "update and get", err)
		step(t, "delete", roles.Delete(ctx, "role-1"))
	})

	t.Run("clients", func(t *testing.T) {
		clients := client.ClientsService()
		_, err := clients.List(ctx, "app", true, 0, 10)
		step(t, "list", err)
		_, err = clients.Get(ctx, "client-1")
		step(t, "get", err)
		_, err = clients.Create(ctx, &ClientCreateRequest{ClientID: "app"})
		step(t, "create", err)
		_, err = clients.CreateAndGet(ctx, &ClientCreateRequest{ClientID: "app"})
		step(t, "create and get", err)
		step(t, "update", clients.Update(ctx, &Client{
			ID: "client-1",
			ProtocolMappers: []ClientProtocolMapper{{
				Name:           "Client Host",
				ProtocolMapper: ProtocolMapperUserSessionNote,
			}},
		}))
		step(t, "delete", clients.Delete(ctx, "client-1"))
	})

	t.Run("authz", func(t *testing.T) {
		authz := client.ClientAuthzService("client-1")
		_, err := authz.Overview(ctx)
		step(t, "overview", err)
		_, err = authz.Resources(ctx, true, 0, 10)
		step(t, "resources", err)
		_, err = authz.Resource(ctx, "res-1")
		step(t, "resource", err)
		_, err = authz.ResourceSearch(ctx, "docs")
		step(t, "resource search", err)
		_, err = authz.ResourceCreate(ctx, &ResourceCreateUpdateRequest{Name: "docs"})
		step(t, "resource create", err)
		_, err = authz.ResourceCreateAndGet(ctx, &ResourceCreateUpdateRequest{Name: "docs"})
		step(t, "resource create and get", err)
		step(t, "resource update", authz.ResourceUpdate(ctx, &ResourceCreateUpdateRequest{ID: "res-1", Name: "docs"}))
		step(t, "resource delete", authz.ResourceDelete(ctx, "res-1"))

		_, err = authz.Scopes(ctx, true, 0, 10, "read")
		step(t, "scopes", err)
		_, err = authz.ScopeSearch(ctx, "read")
		step(t, "scope search", err)
		_, err = authz.ScopeCreate(ctx, &ScopeCreateUpdateRequest{Name: "read"})
		step(t, "scope create", err)
		step(t, "scope update", authz.ScopeUpdate(ctx, &ScopeCreateUpdateRequest{ID: "scope-1", Name: "read"}))
		step(t, "scope delete", authz.ScopeDelete(ctx, "scope-1"))

		for _, kind := range []string{PolicyTypeRole, PolicyTypeJavascript, PolicyTypeTime} {
			_, err = authz.PolicyCreate(ctx, &PolicyCreateUpdateRequest{Type: kind, Name: kind})
			step(t, "policy create "+kind, err)
			step(t, "policy update "+kind, authz.PolicyUpdate(ctx, &PolicyCreateUpdateRequest{ID: "policy-1", Type: kind, Name: kind}))
		}
		if err = authz.PolicyUpdate(ctx, &PolicyCreateUpdateRequest{}); err == nil {
			t.Fatal("policy update without type")
		}
		_, err = authz.Policies(ctx, true, 0, 10)
		step(t, "policies", err)
		_, err = authz.Policy(ctx, "policy-1")
		step(t, "policy", err)
		_, err = authz.PolicyProviders(ctx)
		step(t, "providers", err)
		_, err = authz.PolicyDependents(ctx, "policy-1")
		step(t, "dependents", err)
		_, err = authz.PolicySearch(ctx, "readers")
		step(t, "policy search", err)
		step(t, "policy delete", authz.PolicyDelete(ctx, "policy-1"))

		for _, kind := range []string{PermissionTypeResource, PermissionTypeRole} {
			_, err = authz.PermissionCreate(ctx, &PermissionCreateUpdateRequest{Type: kind, Name: kind})
			step(t, "permission create "+kind, err)
			step(t, "permission update "+kind, authz.PermissionUpdate(ctx, &PermissionCreateUpdateRequest{ID: "perm-1", Type: kind, Name: kind}))
		}
		if _, err = authz.PermissionCreate(ctx, &PermissionCreateUpdateRequest{}); err == nil {
			t.Fatal("permission create without type")
		}
		_, err = authz.Permissions(ctx, 0, 10)
		step(t, "permissions", err)
		_, err = authz.Permission(ctx, "perm-1")
		step(t, "permission", err)
		step(t, "permission delete", authz.PermissionDelete(ctx, "perm-1"))
		_, err = authz.PermissionAssociatedPolicies(ctx, "perm-1")
		step(t, "associated", err)
		_, err = authz.ResourceScopes(ctx, "res-1")
		step(t, "resource scopes", err)
		_, err = authz.ResourceScope(ctx, "res-1", "scope-1")
		step(t, "resource scope", err)
		_, err = authz.ResourcePermissions(ctx, "res-1")
		step(t, "resource permissions", err)
	})
}

func TestAdminServiceRejectsServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	t.Cleanup(srv.Close)
	_, err := adminClientForServer(t, srv).UsersService().Get(context.Background(), "user-1")
	if !IsAPIError(err) {
		t.Fatalf("got %v", err)
	}
}

func adminGETBody(r *http.Request) string {
	p := r.URL.Path
	switch {
	case strings.HasSuffix(p, "/users/count"):
		return "4"
	case strings.HasSuffix(p, "/count"):
		return `{"count":2}`
	case r.URL.Query().Get("name") != "" && path.Base(p) == kcPathPartPolicy:
		return `{"id":"policy-1","name":"readers"}`
	case adminCollection(p):
		return "[]"
	default:
		return `{"id":"x","name":"n"}`
	}
}

func adminCollection(requestPath string) bool {
	switch path.Base(requestPath) {
	case kcPathPartClients, kcPathPartUsers, kcPathPartGroups, kcPathPartRoles,
		kcPathPartResource, kcPathPartScope, kcPathPartPolicy, kcPathPartPermission,
		kcPathPartMembers, kcPathPartAvailable, kcPathPartProviders,
		kcPathPartAssociatedPolicies, kcPathPartDependentPolicies,
		kcPathPartScopes, kcPathPartPermissions, kcPathPartRealm:
		return true
	default:
		return false
	}
}

func readBody(r *http.Request) string {
	buf, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()
	return string(buf)
}

func step(t *testing.T, name string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}
