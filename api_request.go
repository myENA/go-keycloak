package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
)

const (
	uriPathParameterSearchFormat      = "{%s}"
	uriQueryParameterPrefixFormat     = "%s?"
	uriQueryParameterAddNoValueFormat = "%s%s&"
	uriQueryParameterAddValueFormat   = "%s%s=%s&"
	uriQueryParameterCutSet           = "&"

	apiRequestURLFormat = "%s%s"

	headerKeyContentType         = "Content-Type"
	headerKeyContentDisposition  = "Content-Disposition"
	headerKeyAccept              = "Accept"
	headerValueApplicationJSON   = "application/json"
	headerValueMultipartFormData = "multipart/form-data"
)

var apiRequestID uint64

type APIRequest struct {
	id     uint64
	method string
	uri    string

	queryParameters map[string][]string
	pathParameters  map[string]string
	headers         url.Values
	cookies         []*http.Cookie
	body            io.Reader
	bodyT           string
	mpw             *multipart.Writer
}

func NewAPIRequest(method, uri string) *APIRequest {
	r := &APIRequest{
		id:              atomic.AddUint64(&apiRequestID, 1),
		method:          method,
		uri:             uri,
		queryParameters: make(map[string][]string),
		pathParameters:  make(map[string]string),
		headers:         make(url.Values),
		cookies:         make([]*http.Cookie, 0),
	}
	return r
}

func (r *APIRequest) ID() uint64 {
	return r.id
}

func (r *APIRequest) Method() string {
	return r.method
}

func (r *APIRequest) URI() string {
	return r.uri
}

func (r *APIRequest) AddHeader(name, value string) {
	r.headers.Add(name, value)
}

func (r *APIRequest) SetHeader(name, value string) {
	r.headers.Set(name, value)
}

func (r *APIRequest) SetHeaders(headers url.Values) {
	r.headers = make(url.Values)
	for k, vs := range headers {
		for _, v := range vs {
			r.AddHeader(k, v)
		}
	}
}

func (r *APIRequest) RemoveHeader(name string) {
	r.headers.Del(name)
}

func (r *APIRequest) Headers() url.Values {
	return r.headers
}

func (r *APIRequest) SetCookies(cookies []*http.Cookie) {
	r.cookies = cookies
}

func (r *APIRequest) AddCookie(cookie *http.Cookie) {
	r.cookies = append(r.cookies, cookie)
}

func (r *APIRequest) SetCookie(cookie *http.Cookie) {
	for i, cc := range r.cookies {
		if cc.Name == cookie.Name {
			r.cookies[i] = cookie
			return
		}
	}
	r.cookies = append(r.cookies, cookie)
}

func (r *APIRequest) RemoveCookie(name string) {
	nc := make([]*http.Cookie, 0)
	for _, cc := range r.cookies {
		if cc.Name != name {
			nc = append(nc, cc)
		}
	}
	r.cookies = nc
}

func (r *APIRequest) Cookies() []*http.Cookie {
	return r.cookies
}

// AddQueryParameter will add a value to the specified param
func (r *APIRequest) AddQueryParameter(param string, value []string) {
	if _, ok := r.queryParameters[param]; !ok {
		r.queryParameters[param] = make([]string, 0)
	}
	r.queryParameters[param] = append(r.queryParameters[param], value...)
}

// SetQueryParameter will set a query param to a specific value, overriding any previously set value
func (r *APIRequest) SetQueryParameter(param string, value []string) {
	delete(r.queryParameters, param)
	r.AddQueryParameter(param, value)
}

// SetQueryParameters will override any / all existing query parameters
func (r *APIRequest) SetQueryParameters(params map[string][]string) {
	r.queryParameters = make(map[string][]string)
	for k, v := range params {
		r.AddQueryParameter(k, v)
	}
}

// RemoveQueryParameter will attempt to delete all values for a specific query parameter from this request.
func (r *APIRequest) RemoveQueryParameter(param string) {
	delete(r.queryParameters, param)
}

// QueryParameters will return all values of currently set query parameters
func (r *APIRequest) QueryParameters() map[string][]string {
	return r.queryParameters
}

// SetPathParameter will define a path parameter value, overriding any existing value
func (r *APIRequest) SetPathParameter(param, value string) {
	r.pathParameters[param] = value
}

// SetPathParameters will re-define all path parameters, overriding any / all existing ones
func (r *APIRequest) SetPathParameters(params map[string]string) {
	r.pathParameters = make(map[string]string)
	for k, v := range params {
		r.SetPathParameter(k, v)
	}
}

// RemovePathParameter will attempt to remove a single parameter from the current list of path parameters
func (r *APIRequest) RemovePathParameter(param string) {
	delete(r.pathParameters, param)
}

func (r *APIRequest) PathParameters() map[string]string {
	return r.pathParameters
}

func (r *APIRequest) SetBody(body interface{}) error {
	// set body type string
	r.bodyT = fmt.Sprintf("%T", body)

	// test for reader
	if ar, ok := body.(io.Reader); ok {
		r.body = ar
		return nil
	}

	// test for raw bytes
	if b, ok := body.([]byte); ok {
		r.body = bytes.NewBuffer(b)
		return nil
	}

	// test for form data
	if v, ok := body.(url.Values); ok {
		r.body = bytes.NewBufferString(v.Encode())
		return nil
	}

	// finally, attempt json marshal
	if b, err := json.Marshal(body); err != nil {
		return err
	} else {
		r.body = bytes.NewBuffer(b)
		return nil
	}
}

func (r *APIRequest) Body() io.Reader {
	return r.body
}

func (r *APIRequest) BodyType() string {
	return r.bodyT
}

func (r *APIRequest) MultipartForm() {
	r.body = new(bytes.Buffer)
	r.mpw = multipart.NewWriter(r.body.(*bytes.Buffer))
}

func (r *APIRequest) AddMultipartFile(key, filename string, f io.Reader) error {
	w, err := r.mpw.CreateFormFile(key, filename)
	if err != nil {
		return fmt.Errorf("error creating multipart form file part with key=%q and filename=%q: %w", key, filename, err)
	}
	if _, err = io.Copy(w, f); err != nil {
		return fmt.Errorf("error copying bytes from file %q to multipart writer: %w", filename, err)
	}
	addContentDispositionHeader(r, key, filename)
	return nil
}

func (r *APIRequest) AddMultipartField(key string, value interface{}) error {
	var (
		vr io.Reader
		ok bool
	)
	w, err := r.mpw.CreateFormField(key)
	if err != nil {
		return fmt.Errorf("error creating form field part with key=%q: %w", key, err)
	}
	vr, ok = value.(io.Reader)
	if !ok {
		if b, ok := value.([]byte); ok {
			vr = bytes.NewBuffer(b)
		} else if s, ok := value.(string); ok {
			vr = bytes.NewBufferString(s)
		} else if b, err := json.Marshal(value); err != nil {
			return fmt.Errorf("error marshalling form field part with key=%q and type=%T: %w", key, value, err)
		} else {
			vr = bytes.NewBuffer(b)
		}
	}
	if _, err = io.Copy(w, vr); err != nil {
		return fmt.Errorf("error copying bytes into multipart writer for key=%q with type=%T: %w", key, value, err)
	}
	return nil
}

func (r *APIRequest) AddMultipartFieldsFromValues(values url.Values) error {
	for k, vs := range values {
		for _, v := range vs {
			if err := r.AddMultipartField(k, v); err != nil {
				return err
			}
		}
	}
	return nil
}

// CompiledURI will return to you the full request URI, not including scheme, hostname, and port.  This method is not
// thread safe, as you shouldn't be calling this asynchronously anyway.
func (r *APIRequest) CompiledURI() string {
	pathParams := r.PathParameters()
	queryParams := r.QueryParameters()
	uri := r.uri
	if len(pathParams) > 0 {
		for k, v := range pathParams {
			uri = strings.Replace(uri, fmt.Sprintf(uriPathParameterSearchFormat, k), v, 1)
		}
	}
	// TODO: could probably be made more efficient.
	if len(queryParams) > 0 {
		uri = fmt.Sprintf(uriQueryParameterPrefixFormat, uri)
		for param, values := range queryParams {
			for _, value := range values {
				if value == "" {
					uri = fmt.Sprintf(uriQueryParameterAddNoValueFormat, uri, param)
				} else {
					uri = fmt.Sprintf(uriQueryParameterAddValueFormat, uri, param, value)
				}
			}
		}
		uri = strings.TrimRight(uri, uriQueryParameterCutSet)
	}
	return uri
}

// ToHTTP will attempt to construct an executable http.request
func (r *APIRequest) ToHTTP(ctx context.Context, addr string) (*http.Request, error) {
	var (
		compiledURL string
		httpRequest *http.Request
		err         error
	)

	compiledURL = fmt.Sprintf(apiRequestURLFormat, addr, r.CompiledURI())

	if r.mpw != nil {
		r.SetHeader(headerKeyContentType, r.mpw.FormDataContentType())
		if err = r.mpw.Close(); err != nil {
			return nil, fmt.Errorf("error closing multipart writer: %w", err)
		}
	}

	if httpRequest, err = http.NewRequestWithContext(ctx, r.method, compiledURL, r.Body()); err != nil {
		return nil, err
	}

	for header, values := range r.headers {
		for _, value := range values {
			httpRequest.Header.Add(header, value)
		}
	}

	return httpRequest, nil
}
func addContentDispositionHeader(req *APIRequest, key, filename string) {
	req.AddHeader(
		headerKeyContentDisposition,
		fmt.Sprintf(
			"form-data: name=%s; filename=%s;",
			strconv.Quote(key),
			strconv.Quote(filename),
		),
	)
}
