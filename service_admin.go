package keycloak

import (
	"context"
	"fmt"
	"net/http"
	"path"
)

// AdminService is the container for all modeled API calls that hit the /admin/{realm}/... series of endpoints
// in
type AdminService struct {
	tc *tokenAPIClient
}

func (tc *tokenAPIClient) AdminService() *AdminService {
	kc := new(AdminService)
	kc.tc = tc
	return kc
}

// AdminRealmsPath builds a request path under the /admin/realms/{realm}/... path
func (s *AdminService) adminRealmsPath(bits ...string) string {
	return fmt.Sprintf(kcURLPathAdminRealmsFormat, s.tc.PathPrefix(), s.tc.RealmName(), path.Join(bits...))
}

func (s *AdminService) callAdminRealms(ctx context.Context, method, requestPath string, body interface{}, mutators ...RequestMutator) (*http.Response, error) {
	return s.tc.callFn(ctx, method, s.adminRealmsPath(requestPath), body, mutators...)
}
