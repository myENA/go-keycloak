package keycloak

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseResponseLocations(t *testing.T) {
	cases := []struct {
		name    string
		values  []string
		present bool
		want    []string
	}{
		{name: "missing"},
		{name: "empty", present: true},
		{
			name:    "absolute",
			present: true,
			values:  []string{"http://keycloak.example/admin/realms/realm/users/user-1"},
			want:    []string{"user-1"},
		},
		{
			name:    "relative",
			present: true,
			values:  []string{"/admin/realms/realm/groups/group-1"},
			want:    []string{"group-1"},
		},
		{
			name:    "trailing slash",
			present: true,
			values:  []string{"http://keycloak.example/admin/realms/realm/clients/client-1/"},
			want:    []string{"client-1"},
		},
		{
			name:    "query and fragment",
			present: true,
			values:  []string{"http://keycloak.example/admin/realms/realm/users/user-1?x=1#frag"},
			want:    []string{"user-1"},
		},
		{
			name:    "bare id",
			present: true,
			values:  []string{"user-1"},
			want:    []string{"user-1"},
		},
		{
			name:    "multiple",
			present: true,
			values:  []string{"http://keycloak.example/a/id-1", "http://keycloak.example/b/id-2"},
			want:    []string{"id-1", "id-2"},
		},
		{name: "blank", present: true, values: []string{""}},
		{name: "slash", present: true, values: []string{"/"}},
		{name: "host only", present: true, values: []string{"http://keycloak.example"}},
		{name: "dotdot", present: true, values: []string{"http://keycloak.example/users/.."}},
		{name: "invalid", present: true, values: []string{"http://%"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{Header: make(http.Header)}
			if tc.present {
				resp.Header[httpHeaderLocationKey] = tc.values
			}
			got, err := parseResponseLocations(resp)
			if tc.want == nil {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("ids = %#v, want %#v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("ids = %#v, want %#v", got, tc.want)
				}
			}
		})
	}
}

func TestCreateReturnsNewID(t *testing.T) {
	const (
		clientID = "client-1"
		groupID  = "group-1"
		roleID   = "role-1"
		childID  = "child-1"
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/realms/realm/groups":
			w.Header().Set(httpHeaderLocationKey, "http://keycloak.example/admin/realms/realm/groups/"+groupID)
			w.WriteHeader(http.StatusCreated)
		case "/admin/realms/realm/groups/" + groupID:
			writeJSON(w, Group{ID: groupID, Name: "admins"})
		case "/admin/realms/realm/groups/" + groupID + "/children":
			w.Header().Set(httpHeaderLocationKey, "http://keycloak.example/admin/realms/realm/groups/"+childID+"/")
			w.WriteHeader(http.StatusCreated)
		case "/admin/realms/realm/groups/" + childID:
			writeJSON(w, Group{ID: childID, Name: "nested"})
		case "/admin/realms/realm/roles":
			w.Header().Set(httpHeaderLocationKey, "http://keycloak.example/admin/realms/realm/roles-by-id/"+roleID+"?x=1")
			w.WriteHeader(http.StatusCreated)
		case "/admin/realms/realm/roles-by-id/" + roleID:
			writeJSON(w, Role{ID: roleID, Name: "readers"})
		case "/admin/realms/realm/clients/" + clientID + "/roles":
			w.Header().Set(httpHeaderLocationKey, "/admin/realms/realm/roles-by-id/"+roleID)
			w.WriteHeader(http.StatusCreated)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	client := adminClientForServer(t, srv)
	ctx := context.Background()

	created, err := client.GroupsService().Create(ctx, GroupCreate{Name: "admins"})
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 1 || created[0] != groupID {
		t.Fatalf("group ids = %#v", created)
	}
	group, err := client.GroupsService().CreateAndGet(ctx, GroupCreate{Name: "admins"})
	if err != nil {
		t.Fatal(err)
	}
	if group.ID != groupID || group.Name != "admins" {
		t.Fatalf("group = %#v", group)
	}

	childIDs, err := client.GroupsService().CreateChild(ctx, groupID, GroupCreate{Name: "nested"})
	if err != nil {
		t.Fatal(err)
	}
	if len(childIDs) != 1 || childIDs[0] != childID {
		t.Fatalf("child ids = %#v", childIDs)
	}
	child, err := client.GroupsService().CreateAndGetChild(ctx, groupID, GroupCreate{Name: "nested"})
	if err != nil {
		t.Fatal(err)
	}
	if child.ID != childID {
		t.Fatalf("child = %#v", child)
	}

	roleIDs, err := client.RoleService().RealmRoleCreate(ctx, &RoleCreateRequest{Name: "readers"})
	if err != nil {
		t.Fatal(err)
	}
	if len(roleIDs) != 1 || roleIDs[0] != roleID {
		t.Fatalf("role ids = %#v", roleIDs)
	}
	role, err := client.RoleService().RealmRoleCreateAndGet(ctx, &RoleCreateRequest{Name: "readers"})
	if err != nil {
		t.Fatal(err)
	}
	if role.ID != roleID || role.Name != "readers" {
		t.Fatalf("role = %#v", role)
	}

	clientRoleIDs, err := client.RoleService().ClientRoleCreate(ctx, clientID, &RoleCreateRequest{Name: "readers"})
	if err != nil {
		t.Fatal(err)
	}
	if len(clientRoleIDs) != 1 || clientRoleIDs[0] != roleID {
		t.Fatalf("client role ids = %#v", clientRoleIDs)
	}
	clientRole, err := client.RoleService().ClientRoleCreateAndGet(ctx, clientID, &RoleCreateRequest{Name: "readers"})
	if err != nil {
		t.Fatal(err)
	}
	if clientRole.ID != roleID {
		t.Fatalf("client role = %#v", clientRole)
	}
}

func TestClientCreateReturnsID(t *testing.T) {
	const id = "client-1"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/admin/realms/realm/clients":
			w.Header().Set(httpHeaderLocationKey, "http://keycloak.example/admin/realms/realm/clients/"+id+"/")
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && r.URL.Path == "/admin/realms/realm/clients/"+id:
			writeJSON(w, Client{ID: id, ClientID: "app", Name: "App"})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	api := adminClientForServer(t, srv)
	ctx := context.Background()

	created, err := api.ClientsService().Create(ctx, &ClientCreateRequest{ClientID: "app"})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != id {
		t.Fatalf("id = %q", created.ID)
	}
	if created.ClientID != "" || created.Name != "" {
		t.Fatalf("create returned fields the server did not send: %#v", created)
	}

	got, err := api.ClientsService().CreateAndGet(ctx, &ClientCreateRequest{ClientID: "app"})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != id || got.ClientID != "app" || got.Name != "App" {
		t.Fatalf("client = %#v", got)
	}
}

func TestClientCreateIDFailures(t *testing.T) {
	cases := []struct {
		name   string
		status int
		values []string
		apiErr bool
	}{
		{name: "missing location", status: http.StatusCreated},
		{name: "blank location", status: http.StatusCreated, values: []string{"/"}},
		{name: "two locations", status: http.StatusCreated, values: []string{"http://keycloak.example/clients/a", "http://keycloak.example/clients/b"}},
		{name: "not created", status: http.StatusOK, values: []string{"http://keycloak.example/clients/a"}, apiErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for _, value := range tc.values {
					w.Header().Add(httpHeaderLocationKey, value)
				}
				w.WriteHeader(tc.status)
			}))
			t.Cleanup(srv.Close)
			_, err := adminClientForServer(t, srv).ClientsService().Create(context.Background(), &ClientCreateRequest{ClientID: "app"})
			if err == nil {
				t.Fatal("expected error")
			}
			if tc.apiErr != IsAPIError(err) {
				t.Fatalf("api error = %v, want %v: %v", IsAPIError(err), tc.apiErr, err)
			}
		})
	}
}

func writeJSON(w http.ResponseWriter, body interface{}) {
	w.Header().Set(httpHeaderContentType, httpHeaderValueJSON)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}
