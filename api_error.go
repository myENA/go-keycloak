package keycloak

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
)

type APIError struct {
	ResponseCode    int         `json:"response_code"`
	ResponseStatus  string      `json:"response_status"`
	ResponseHeaders http.Header `json:"response_headers"`

	Err            string `json:"error"`
	ErrDescription string `json:"error_description"`
}

func newAPIError(successCode int, resp *http.Response) *APIError {
	e := new(APIError)
	e.ResponseCode = resp.StatusCode
	e.ResponseStatus = resp.Status
	e.ResponseHeaders = resp.Header
	b, _ := ioutil.ReadAll(resp.Body)
	if len(b) > 0 {
		if err := json.Unmarshal(b, e); err != nil {
			e.ErrDescription = string(b)
		}
	}
	return e
}

func (e *APIError) Error() string {
	if e.ResponseCode == 0 {
		return ""
	}
	return fmt.Sprintf("Call returned non-200: status=%q; error=%q; error_description=%q", e.ResponseStatus, e.Err, e.ErrDescription)
}

func IsAPIError(err error) bool {
	if err == nil {
		return false
	}
	_, ok := err.(*APIError)
	for err != nil && !ok {
		err = errors.Unwrap(err)
		_, ok = err.(*APIError)
	}
	return ok
}
