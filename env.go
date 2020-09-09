package keycloak

type RealmEnvironment struct {
	oidc  *OpenIDConfiguration
	uma2c *UMA2Configuration
}

// common configuration entries

func (e *RealmEnvironment) SupportsUMA2() bool {
	return e.uma2c != nil
}

func (e *RealmEnvironment) IssuerAddress() string {
	if e.uma2c != nil {
		return e.uma2c.Issuer
	} else {
		return e.oidc.Issuer
	}
}

func (e *RealmEnvironment) AuthorizationEndpoint() string {
	if e.uma2c != nil {
		return e.uma2c.AuthorizationEndpoint
	} else {
		return e.oidc.AuthorizationEndpoint
	}
}

func (e *RealmEnvironment) TokenEndpoint() string {
	if e.uma2c != nil {
		return e.uma2c.TokenEndpoint
	} else {
		return e.oidc.TokenEndpoint
	}
}

func (e *RealmEnvironment) IntrospectionEndpoint() string {
	if e.uma2c != nil {
		return e.uma2c.IntrospectionEndpoint
	} else {
		return e.oidc.IntrospectionEndpoint
	}
}

func (e *RealmEnvironment) EndSessionEndpoint() string {
	if e.uma2c != nil {
		return e.uma2c.EndSessionEndpoint
	} else {
		return e.oidc.EndSessionEndpoint
	}
}

func (e *RealmEnvironment) JSONWebKeysEndpoint() string {
	if e.uma2c != nil {
		return e.uma2c.JwksURI
	} else {
		return e.oidc.JSONWebKeysEndpoint
	}
}

func (e *RealmEnvironment) RegistrationEndpoint() string {
	if e.uma2c != nil {
		return e.uma2c.RegistrationEndpoint
	} else {
		return e.oidc.RegistrationEndpoint
	}
}

func (e *RealmEnvironment) GrantTypesSupported() []string {
	if e.uma2c != nil {
		return copyStrs(e.uma2c.GrantTypesSupported)
	} else {
		return copyStrs(e.oidc.GrantTypesSupported)
	}
}

func (e *RealmEnvironment) ResponseTypesSupported() []string {
	if e.uma2c != nil {
		return copyStrs(e.uma2c.ResponseTypesSupported)
	} else {
		return copyStrs(e.oidc.ResponseTypesSupported)
	}
}

func (e *RealmEnvironment) ResponseModesSupported() []string {
	if e.uma2c != nil {
		return copyStrs(e.uma2c.ResponseModesSupported)
	} else {
		return copyStrs(e.oidc.ResponseModesSupported)
	}
}

func (e *RealmEnvironment) TokenEndpointAuthMethodsSupported() []string {
	if e.uma2c != nil {
		return copyStrs(e.uma2c.TokenEndpointAuthMethodsSupported)
	} else {
		return copyStrs(e.oidc.TokenEndpointAuthMethodsSupported)
	}
}

func (e *RealmEnvironment) TokenEndpointAuthSigningAlgValuesSupported() []string {
	if e.uma2c != nil {
		return copyStrs(e.uma2c.TokenEndpointAuthSigningAlgValuesSupported)
	} else {
		return copyStrs(e.oidc.TokenEndpointAuthSigningAlgValuesSupported)
	}
}

func (e *RealmEnvironment) ScopesSupported() []string {
	if e.uma2c != nil {
		return copyStrs(e.uma2c.ScopesSupported)
	} else {
		return copyStrs(e.oidc.ScopesSupported)
	}
}

// oidc configuration entries

func (e *RealmEnvironment) UserInfoEndpoint() string {
	return e.oidc.UserInfoEndpoint
}

func (e *RealmEnvironment) CheckSessionIframe() string {
	return e.oidc.CheckSessionIframe
}

func (e *RealmEnvironment) SubjectTypesSupported() []string {
	return copyStrs(e.oidc.SubjectTypesSupported)
}

func (e *RealmEnvironment) IDTokenSigningAlgValuesSupported() []string {
	return copyStrs(e.oidc.IDTokenSigningAlgValuesSupported)
}

func (e *RealmEnvironment) IDTokenEncryptionAlgValuesSupported() []string {
	return copyStrs(e.oidc.IDTokenEncryptionAlgValuesSupported)
}

func (e *RealmEnvironment) IDTokenEncryptionEncValuesSupported() []string {
	return copyStrs(e.oidc.IDTokenEncryptionEncValuesSupported)
}

func (e *RealmEnvironment) UserInfoSigningAlgValuesSupported() []string {
	return copyStrs(e.oidc.UserinfoSigningAlgValuesSupported)
}

func (e *RealmEnvironment) RequestObjectSigningAlgValuesSupported() []string {
	return copyStrs(e.oidc.RequestObjectSigningAlgValuesSupported)
}

func (e *RealmEnvironment) ClaimsSupported() []string {
	return copyStrs(e.oidc.ClaimsSupported)
}

func (e *RealmEnvironment) ClaimTypesSupported() []string {
	return copyStrs(e.oidc.ClaimTypesSupported)
}

func (e *RealmEnvironment) ClaimsParameterSupported() bool {
	return e.oidc.ClaimsParameterSupported
}

func (e *RealmEnvironment) RequestParameterSupported() bool {
	return e.oidc.RequestParameterSupported
}

func (e *RealmEnvironment) RequestURIParameterSupported() bool {
	return e.oidc.RequestURIParameterSupported
}

func (e *RealmEnvironment) CodeChallengeMethodsSupported() []string {
	return copyStrs(e.oidc.CodeChallengeMethodsSupported)
}

func (e *RealmEnvironment) TLSClientCertificateBoundAccessTokens() bool {
	return e.oidc.TLSClientCertificateBoundAccessToken
}

// uma2 configuration entries

func (e *RealmEnvironment) ResourceRegistrationEndpoint() (string, bool) {
	if e.uma2c != nil {
		return e.uma2c.ResourceRegistrationEndpoint, true
	}
	return "", false
}

func (e *RealmEnvironment) PermissionEndpoint() (string, bool) {
	if e.uma2c != nil {
		return e.uma2c.PermissionEndpoint, true
	}
	return "", false
}

func (e *RealmEnvironment) PolicyEndpoint() (string, bool) {
	if e.uma2c != nil {
		return e.uma2c.PermissionEndpoint, true
	}
	return "", false
}
