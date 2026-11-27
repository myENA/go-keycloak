package keycloak

import "testing"

func TestRepairUserSessionNoteMappers(t *testing.T) {
	mappers := []ClientProtocolMapper{
		{
			Name:           "Client ID",
			ProtocolMapper: ProtocolMapperUserSessionNote,
			Config:         ClientProtocolMapperConfig{ClaimName: "clientId"},
		},
		{
			Name:           "Client Host",
			ProtocolMapper: ProtocolMapperUserSessionNote,
			Config:         ClientProtocolMapperConfig{UserSessionNote: "clientHost", ClaimName: "clientHost"},
		},
		{
			Name:           "audience",
			ProtocolMapper: "oidc-audience-mapper",
			Config:         ClientProtocolMapperConfig{ClaimName: "aud"},
		},
		{
			Name:           "custom-note",
			ProtocolMapper: ProtocolMapperUserSessionNote,
			Config:         ClientProtocolMapperConfig{ClaimName: "department"},
		},
	}

	if got := RepairUserSessionNoteMappers(mappers); got != 2 {
		t.Fatalf("repaired %d, want 2", got)
	}
	if mappers[0].Config.UserSessionNote != "clientId" {
		t.Fatalf("Client ID note = %q", mappers[0].Config.UserSessionNote)
	}
	if mappers[1].Config.UserSessionNote != "clientHost" {
		t.Fatalf("Client Host note = %q", mappers[1].Config.UserSessionNote)
	}
	if mappers[2].Config.UserSessionNote != "" {
		t.Fatalf("audience mapper should stay untouched, note = %q", mappers[2].Config.UserSessionNote)
	}
	if mappers[3].Config.UserSessionNote != "department" {
		t.Fatalf("custom note = %q", mappers[3].Config.UserSessionNote)
	}

	if got := RepairUserSessionNoteMappers(mappers); got != 0 {
		t.Fatalf("second pass repaired %d, want 0", got)
	}
}
