package keycloak

import (
	"context"
	"fmt"
	"os"
)

// RealmProvider
//
// This interface describes any implementation that can provide a realm name to the given context
type RealmProvider interface {
	// SetRealmValue MUST either return a context with the realm key defined, or the original context with an error
	// describing why it was unable to do so.  It must also defer to any pre-defined key value already present in the
	// context.
	SetRealmValue(context.Context) (context.Context, error)
}

// StaticRealmProvider will set its value as the context's realm key if the incoming context does not already contain
// a realm key
type StaticRealmProvider string

// NewStaticRealmProvider will return to you a type of RealmProvider that, given that the incoming context does not
// already have a realm defined, will always set it to the value provided to this constructor
func NewStaticRealmProvider(keycloakRealm string) StaticRealmProvider {
	return StaticRealmProvider(keycloakRealm)
}

// NewStaticRealmProviderFromEnvironment will attempt to fetch the provided env key using os.GetEnv, creating a new
// StaticRealmProvider with that as the value.
func NewStaticRealmProviderFromEnvironment(envKey string) StaticRealmProvider {
	realm := os.Getenv(envKey)
	if envKey == "" {
		panic(fmt.Sprintf("provided \"envKey\" value %q yielded empty string", envKey))
	}
	return StaticRealmProvider(realm)
}

// SetRealmValue will attempt to locate a pre-existing realm key on the provided context, returning the original
// context if one is found.  If not, it will return a new context with its own realm value defined.
func (rp StaticRealmProvider) SetRealmValue(ctx context.Context) (context.Context, error) {
	// always defer to one explicitly defined
	if _, ok := ContextRealm(ctx); ok {
		return ctx, nil
	}
	return context.WithValue(ctx, ContextKeyRealm, string(rp)), nil
}
