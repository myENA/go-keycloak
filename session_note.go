package keycloak

const ProtocolMapperUserSessionNote = "oidc-usersessionmodel-note-mapper"

// defaultUserSessionNote is the Keycloak user-session note key for the built-in
// User Session Note mappers. Token issuance NPEs when that config value is empty.
func defaultUserSessionNote(name, claimName string) string {
	switch name {
	case "Client ID":
		return "clientId"
	case "Client Host":
		return "clientHost"
	case "Client IP Address":
		return "clientAddress"
	default:
		return claimName
	}
}

// RepairUserSessionNoteMappers sets user.session.note on User Session Note mappers
// that lost it. Client updates that round-trip protocolMappers through
// ClientProtocolMapperConfig used to drop the key and break authentication.
func RepairUserSessionNoteMappers(mappers []ClientProtocolMapper) int {
	repaired := 0
	for i := range mappers {
		mapper := &mappers[i]
		if mapper.ProtocolMapper != ProtocolMapperUserSessionNote || mapper.Config.UserSessionNote != "" {
			continue
		}
		note := defaultUserSessionNote(mapper.Name, mapper.Config.ClaimName)
		if note == "" {
			continue
		}
		mapper.Config.UserSessionNote = note
		repaired++
	}
	return repaired
}
