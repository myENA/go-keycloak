package keycloak

import (
	"context"
	"io"
	"net/http"
	"net/url"
)

type Request struct {
	*http.Request
	query url.Values
}

func NewRequestWithContext(ctx context.Context, method, uri string, body io.Reader) (*Request, error) {
	var (
		err error

		r = new(Request)
	)
	if r.Request, err = http.NewRequestWithContext(ctx, method, uri, body); err != nil {
		return nil, err
	}
	r.query = r.Request.URL.Query()
	return r, nil
}

func (r *Request) Query() url.Values {
	return r.query
}

func (r *Request) build() *http.Request {
	r.Request.URL.RawQuery = r.query.Encode()
	return r.Request
}
