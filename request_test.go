package keycloak

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestAPIRequestBuild(t *testing.T) {
	first := NewAPIRequest(http.MethodGet, "http://example/users/{id}")
	second := NewAPIRequest(http.MethodPost, "http://example/users")
	if first.ID() == 0 || second.ID() == first.ID() {
		t.Fatalf("ids = %d %d", first.ID(), second.ID())
	}
	if first.Method() != http.MethodGet || first.URI() != "http://example/users/{id}" {
		t.Fatalf("request = %s %s", first.Method(), first.URI())
	}

	first.SetPathParameter("id", "a b")
	first.AddQueryParameter("q", "1")
	first.AddQueryParameter("q", "2")
	if got := first.CompiledURI(); got != "http://example/users/a%20b?q=1&q=2" {
		t.Fatalf("uri = %s", got)
	}
	first.SetQueryParameter("q", "3")
	first.SetQueryParameters(url.Values{"q": {"4"}})
	first.RemoveQueryParameter("missing")
	first.SetPathParameters(map[string]string{"id": "user-1"})
	first.RemovePathParameter("missing")
	if _, ok := first.PathParameters()["id"]; !ok {
		t.Fatal("missing path id")
	}
	first.RemovePathParameter("id")
	if len(first.PathParameters()) != 0 {
		t.Fatal("path parameter remains")
	}

	first.AddHeader("A", "1")
	first.SetHeader("A", "2")
	first.RemoveHeader("A")
	first.SetHeaders(url.Values{"B": {"3"}})
	if first.Headers().Get("B") != "3" {
		t.Fatalf("headers = %#v", first.Headers())
	}

	first.AddCookie(&http.Cookie{Name: "a", Value: "1"})
	first.SetCookie(&http.Cookie{Name: "a", Value: "2"})
	first.AddCookie(&http.Cookie{Name: "b", Value: "3"})
	first.SetCookie(&http.Cookie{Name: "c", Value: "4"})
	first.RemoveCookie("b")
	if len(first.Cookies()) != 2 {
		t.Fatalf("cookies = %#v", first.Cookies())
	}
	first.SetCookies([]*http.Cookie{{Name: "d", Value: "5"}})
	if len(first.Cookies()) != 1 || first.Cookies()[0].Name != "d" {
		t.Fatalf("cookies = %#v", first.Cookies())
	}

	req, err := first.ToHTTP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != http.MethodGet {
		t.Fatalf("method = %s", req.Method)
	}
	if _, err = NewAPIRequest(http.MethodGet, "http://[").ToHTTP(context.Background()); err == nil {
		t.Fatal("expected url error")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read") }

func TestAPIRequestBody(t *testing.T) {
	req := NewAPIRequest(http.MethodPost, "http://example")
	if err := req.SetBody(nil); err != nil || req.Body() != nil || req.BodyType() != "nil" || req.BodyLen() != 0 {
		t.Fatalf("nil body type=%s len=%d err=%v", req.BodyType(), req.BodyLen(), err)
	}
	if err := req.SetBody([]byte("ab")); err != nil || req.BodyLen() != 2 {
		t.Fatal(err)
	}
	if err := req.SetBody(strings.NewReader("hi")); err != nil || req.Body() == nil {
		t.Fatal(err)
	}
	values := url.Values{"a": {"b"}}
	if err := req.SetBody(values); err != nil || req.BodyLen() != len(values.Encode()) {
		t.Fatal(err)
	}
	if err := req.SetBody(struct {
		A string `json:"a"`
	}{A: "z"}); err != nil || req.BodyLen() == 0 {
		t.Fatal(err)
	}
	if err := req.SetBody(struct{ C chan int }{}); err == nil {
		t.Fatal("expected marshal error")
	}
}

func TestAPIRequestMultipart(t *testing.T) {
	req := NewAPIRequest(http.MethodPost, "http://example/upload")
	req.MultipartForm()
	if err := req.AddMultipartField("name", "ada"); err != nil {
		t.Fatal(err)
	}
	if err := req.AddMultipartField("bin", []byte("ab")); err != nil {
		t.Fatal(err)
	}
	if err := req.AddMultipartField("reader", strings.NewReader("hi")); err != nil {
		t.Fatal(err)
	}
	if err := req.AddMultipartField("meta", map[string]string{"a": "b"}); err != nil {
		t.Fatal(err)
	}
	if err := req.AddMultipartField("bad", make(chan int)); err == nil {
		t.Fatal("expected marshal error")
	}
	if err := req.AddMultipartFieldsFromValues(url.Values{"q": {"1", "2"}}); err != nil {
		t.Fatal(err)
	}
	if err := req.AddMultipartFile("file", "a.txt", strings.NewReader("data")); err != nil {
		t.Fatal(err)
	}
	if got := req.Headers().Get(headerKeyContentDisposition); !strings.Contains(got, "a.txt") {
		t.Fatalf("disposition = %q", got)
	}

	httpReq, err := req.ToHTTP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(httpReq.Header.Get(headerKeyContentType), "multipart/form-data") {
		t.Fatalf("content type = %s", httpReq.Header.Get(headerKeyContentType))
	}
	buf, err := io.ReadAll(httpReq.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(buf, []byte("ada")) || !bytes.Contains(buf, []byte("a.txt")) {
		t.Fatalf("body = %s", buf)
	}

	failed := NewAPIRequest(http.MethodPost, "http://example/upload")
	failed.MultipartForm()
	if err = failed.AddMultipartFile("file", "c.txt", errReader{}); err == nil {
		t.Fatal("expected read error")
	}
}

func TestMutators(t *testing.T) {
	if value, ok := DefaultParameterFormatter("", "", nil); ok || value != "" {
		t.Fatalf("nil = %q %v", value, ok)
	}
	cases := []struct {
		in    interface{}
		value string
		ok    bool
	}{
		{"ada", "ada", true},
		{"", "", false},
		{2, "2", true},
		{0, "0", false},
		{int64(3), "3", true},
		{int64(0), "0", false},
		{1.25, "1.25000000", true},
		{float64(0), "0.00000000", false},
		{uint64(4), "4", true},
		{uint64(0), "0", false},
		{true, "true", true},
		{false, "false", false},
	}
	for _, tc := range cases {
		value, ok := DefaultParameterFormatter(ParameterDestinationQuery, "k", tc.in)
		if value != tc.value || ok != tc.ok {
			t.Fatalf("%#v -> %q %v, want %q %v", tc.in, value, ok, tc.value, tc.ok)
		}
	}
	if value, _ := DefaultParameterFormatter("", "", struct{ A int }{A: 1}); value == "" {
		t.Fatal("empty default format")
	}

	req := NewAPIRequest(http.MethodGet, "http://example/users")
	if err := QueryMutator("first", 0, true)(req); err != nil {
		t.Fatal(err)
	}
	if err := QueryMutator("q", "1", false)(req); err != nil {
		t.Fatal(err)
	}
	if err := QueryMutator("q", "2", false)(req); err != nil {
		t.Fatal(err)
	}
	if err := NonZeroQueryMutator("max", 0, 20, true)(req); err != nil {
		t.Fatal(err)
	}
	if err := NonZeroQueryMutator("search", "", nil, true)(req); err != nil {
		t.Fatal(err)
	}
	if err := NonZeroQueryMutator("viewableOnly", false, nil, true)(req); err != nil {
		t.Fatal(err)
	}
	if err := NonZeroQueryMutator("name", "ada", nil, true)(req); err != nil {
		t.Fatal(err)
	}
	if req.QueryParameters().Get("first") != "0" || req.QueryParameters().Get("max") != "20" || req.QueryParameters().Get("name") != "ada" {
		t.Fatalf("query = %s", req.QueryParameters().Encode())
	}
	if _, ok := req.QueryParameters()["search"]; ok {
		t.Fatal("empty search was set")
	}
	if _, ok := req.QueryParameters()["viewableOnly"]; ok {
		t.Fatal("false viewableOnly was set")
	}
	if got := req.QueryParameters()["q"]; len(got) != 2 {
		t.Fatalf("q = %#v", got)
	}

	if err := HeaderMutator("A", "1", false)(req); err != nil {
		t.Fatal(err)
	}
	if err := HeaderMutator("A", "2", true)(req); err != nil {
		t.Fatal(err)
	}
	if err := NonZeroHeaderMutator("B", "", "fallback", true)(req); err != nil {
		t.Fatal(err)
	}
	if err := NonZeroHeaderMutator("C", "", nil, true)(req); err != nil {
		t.Fatal(err)
	}
	if req.Headers().Get("A") != "2" || req.Headers().Get("B") != "fallback" {
		t.Fatalf("headers = %#v", req.Headers())
	}
	if _, ok := req.Headers()["C"]; ok {
		t.Fatal("empty header was set")
	}

	if err := BearerAuthRequestMutator("")(req); err != nil {
		t.Fatal(err)
	}
	if err := BearerAuthRequestMutator("tok")(req); err != nil {
		t.Fatal(err)
	}
	if req.Headers().Get(HTTPpHeaderAuthorization) != "Bearer tok" {
		t.Fatalf("auth = %s", req.Headers().Get(HTTPpHeaderAuthorization))
	}
	if err := BasicAuthRequestMutator("user", "pass")(req); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(req.Headers().Get(HTTPpHeaderAuthorization), "Basic ") {
		t.Fatalf("auth = %s", req.Headers().Get(HTTPpHeaderAuthorization))
	}

	ran := false
	_, err := baseRequestMutatorRunner(req, nil, func(*APIRequest) error {
		ran = true
		return nil
	})
	if err != nil || !ran {
		t.Fatalf("runner ran=%v err=%v", ran, err)
	}
	if _, err = baseRequestMutatorRunner(req); err != nil {
		t.Fatal(err)
	}
	if _, err = baseRequestMutatorRunner(req, func(*APIRequest) error { return errors.New("boom") }); err == nil {
		t.Fatal("expected mutator error")
	}

	runner := buildRequestMutatorRunner(&DebugConfig{
		BaseRequestMutators:  []APIRequestMutator{func(r *APIRequest) error { r.SetHeader("Pre", "1"); return nil }},
		FinalRequestMutators: []APIRequestMutator{func(r *APIRequest) error { r.SetHeader("Post", "1"); return nil }},
	})
	if _, err = runner(req, func(r *APIRequest) error { r.SetHeader("Mid", "1"); return nil }); err != nil {
		t.Fatal(err)
	}
	if req.Headers().Get("Pre") != "1" || req.Headers().Get("Mid") != "1" || req.Headers().Get("Post") != "1" {
		t.Fatalf("headers = %#v", req.Headers())
	}
	if _, err = buildRequestMutatorRunner(nil)(NewAPIRequest(http.MethodGet, "http://example")); err != nil {
		t.Fatal(err)
	}
	if _, err = buildRequestMutatorRunner(&DebugConfig{})(NewAPIRequest(http.MethodGet, "http://example")); err != nil {
		t.Fatal(err)
	}
	postErr := buildRequestMutatorRunner(&DebugConfig{
		FinalRequestMutators: []APIRequestMutator{func(*APIRequest) error { return errors.New("post") }},
	})
	if _, err = postErr(NewAPIRequest(http.MethodGet, "http://example")); err == nil {
		t.Fatal("expected post mutator error")
	}
	if got := requestMutators(nil, HeaderMutator("Z", "1", true)); len(got) != 1 {
		t.Fatalf("mutators = %d", len(got))
	}
}
