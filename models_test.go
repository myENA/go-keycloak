package keycloak

import (
	"encoding/json"
	"sort"
	"testing"
	"time"
)

func TestMicrosecondTimeJSON(t *testing.T) {
	var parsed MicrosecondTime
	if err := parsed.UnmarshalJSON(nil); err != nil {
		t.Fatal(err)
	}
	if err := parsed.UnmarshalJSON([]byte(`nope`)); err == nil {
		t.Fatal("expected error")
	}
	if err := json.Unmarshal([]byte(`1000`), &parsed); err != nil {
		t.Fatal(err)
	}
	buf, err := json.Marshal(&parsed)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf) != "1000" {
		t.Fatalf("marshal = %s", buf)
	}

	var zero MicrosecondTime
	buf, err = json.Marshal(&zero)
	if err != nil || string(buf) != "0" {
		t.Fatalf("zero = %s, %v", buf, err)
	}
	var missing *MicrosecondTime
	buf, err = missing.MarshalJSON()
	if err != nil || buf != nil {
		t.Fatalf("nil = %s, %v", buf, err)
	}
}

func TestPolicyTimeJSON(t *testing.T) {
	var parsed PolicyTime
	if err := parsed.UnmarshalJSON(nil); err != nil {
		t.Fatal(err)
	}
	if err := parsed.UnmarshalJSON([]byte(`not-a-time`)); err == nil {
		t.Fatal("expected error")
	}
	if err := parsed.UnmarshalJSON([]byte(`2006-01-02 15:04:05`)); err != nil {
		t.Fatal(err)
	}
	buf, err := parsed.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(buf) != `"2006-01-02 15:04:05"` {
		t.Fatalf("marshal = %s", buf)
	}
	if !time.Time(parsed).Equal(time.Date(2006, 1, 2, 15, 4, 5, 0, time.UTC)) {
		t.Fatalf("parsed = %s", time.Time(parsed))
	}
}

func TestPolicyConfigJSON(t *testing.T) {
	var conf PolicyConfig
	if err := conf.UnmarshalJSON([]byte(`{"roles":"[{\"id\":\"abc\",\"required\":true}]"}`)); err != nil {
		t.Fatal(err)
	}
	if len(conf.Roles) != 1 || conf.Roles[0].ID != "abc" {
		t.Fatalf("roles = %#v", conf.Roles)
	}
	if err := conf.UnmarshalJSON([]byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := conf.UnmarshalJSON([]byte(`nope`)); err == nil {
		t.Fatal("expected error")
	}
	if err := conf.UnmarshalJSON([]byte(`{"roles":"nope"}`)); err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectionHelpers(t *testing.T) {
	roles := Roles{{Name: "b"}, {Name: "a"}}
	sort.Sort(roles)
	if roles[0].Name != "a" || roles[1].Name != "b" {
		t.Fatalf("roles = %#v", roles)
	}
	policies := Policies{{Name: "b"}, {Name: "a"}}
	sort.Sort(policies)
	if policies[0].Name != "a" || policies[1].Name != "b" {
		t.Fatalf("policies = %#v", policies)
	}
	scopes := Scopes{{Name: "b"}, {Name: "a"}}
	sort.Sort(scopes)
	if scopes[0].Name != "a" || scopes[1].Name != "b" {
		t.Fatalf("scopes = %#v", scopes)
	}

	if ids := (ResourceMap)(nil).IDs(); len(ids) != 0 {
		t.Fatalf("nil resource ids = %#v", ids)
	}
	got := ResourceMap{"a": {ID: "1"}, "b": {ID: "2"}}.IDs()
	if len(got) != 2 || !contains(got, "1") || !contains(got, "2") {
		t.Fatalf("resource ids = %#v", got)
	}
	got = PolicyMap{"a": {ID: "1"}, "b": {ID: "2"}}.IDs()
	if len(got) != 2 || !contains(got, "1") || !contains(got, "2") {
		t.Fatalf("policy ids = %#v", got)
	}

	set := &JSONWebKeySet{Keys: []*JSONWebKey{{KeyID: "k1"}, {KeyID: "k2"}}}
	if set.KeychainByID("k2") == nil || set.KeychainByID("missing") != nil {
		t.Fatal("key lookup")
	}
	if (&JSONWebKeySet{}).KeychainByID("k1") != nil {
		t.Fatal("empty set")
	}
}

func TestTokenRequestPermissions(t *testing.T) {
	perm := NewOpenIDConnectTokenPermission("res", "read")
	req := NewOpenIDConnectTokenRequest(GrantTypeClientCredentials, perm)
	req.AddPermission("other", "write")
	if req.GrantType != GrantTypeClientCredentials {
		t.Fatalf("grant = %s", req.GrantType)
	}
	if len(req.Permissions) != 2 || req.Permissions[0] != "res#read" || req.Permissions[1] != "other#write" {
		t.Fatalf("permissions = %#v", req.Permissions)
	}
	fresh := new(OpenIDConnectTokenRequest)
	fresh.AddPermission("res", "read")
	if len(fresh.Permissions) != 1 {
		t.Fatalf("permissions = %#v", fresh.Permissions)
	}
}

func TestSessionNoteDefaults(t *testing.T) {
	mappers := []ClientProtocolMapper{{
		Name:           "Client IP Address",
		ProtocolMapper: ProtocolMapperUserSessionNote,
	}, {
		ProtocolMapper: ProtocolMapperUserSessionNote,
	}}
	if got := RepairUserSessionNoteMappers(mappers); got != 1 {
		t.Fatalf("repaired %d", got)
	}
	if mappers[0].Config.UserSessionNote != "clientAddress" {
		t.Fatalf("note = %q", mappers[0].Config.UserSessionNote)
	}
	if mappers[1].Config.UserSessionNote != "" {
		t.Fatalf("empty mapper note = %q", mappers[1].Config.UserSessionNote)
	}
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
