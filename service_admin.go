package keycloak

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
)

// AdminService is the container for all modeled API calls that hit the /admin/{realm}/... series of endpoints
// in
type AdminService struct {
	*baseService
}

// NewAdminService will return to you a new realm admin service that also contains base modeled api calls.
func NewAdminService(c *APIClient) *AdminService {
	kc := new(AdminService)
	kc.baseService = newBaseService(c)
	return kc
}

// AdminRealmsPath builds a request path under the /admin/realms/{realm}/... path
func (k AdminService) adminRealmsPath(ctx context.Context, bits ...string) (string, error) {
	if realm, ok := contextStringValue(ctx, ContextKeyRealm); ok {
		return fmt.Sprintf(kcURLPathAdminRealmsFormat, k.c.pathPrefix, realm, path.Join(bits...)), nil
	}
	return "", errors.New("context does not contain realm value")
}

func (k *AdminService) callAdminRealms(ctx context.Context, method, requestPath string, body interface{}, mutators ...RequestMutator) (*http.Response, error) {
	var err error
	if ctx, err = k.c.requireAllContextValues(ctx); err != nil {
		return nil, err
	}
	requestPath, err = k.adminRealmsPath(ctx, requestPath)
	if err != nil {
		return nil, err
	}
	return k.c.Call(ctx, method, requestPath, body, mutators...)
}

func (k *AdminService) callAdminRealmsRequireOK(ctx context.Context, method, requestPath string, body interface{}, mutators ...RequestMutator) (*http.Response, error) {
	var err error

	if ctx, err = k.c.requireAllContextValues(ctx); err != nil {
		return nil, err
	}
	if requestPath, err = k.adminRealmsPath(ctx, requestPath); err != nil {
		return nil, err
	}
	return k.c.CallRequireOK(ctx, method, requestPath, body, mutators...)
}
