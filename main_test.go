package main

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func makeBodyMatch(rules ...ConfigRule) HTTPMatch {
	return HTTPMatch{RuleOptions: RuleOptions{Body: rules}}
}

func makeQuerystringMatch(rules ...ConfigRule) HTTPMatch {
	return HTTPMatch{RuleOptions: RuleOptions{Querystring: rules}}
}

func makeRequest(body string, contentType string) *http.Request {
	request, _ := http.NewRequest("GET", "", strings.NewReader(body))

	if contentType != "" {
		request.Header.Add("Content-Type", contentType)
	}

	return request
}

func TestIsSamePath(t *testing.T) {
	type testCase struct {
		name string
		a    string
		b    string
		out  bool
	}

	cases := []testCase{
		{name: "with exact matches", a: "/v1", b: "/v1", out: true},
		{name: "with trailing slashes", a: "/v1", b: "/v1/", out: true},
		{name: "with trailing slashes", a: "/v1//", b: "/v1/", out: true},
		{name: "with trailing slashes and different paths", a: "/v2", b: "/v1", out: false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			match := isSamePath(c.a, c.b)
			assert.Equal(t, match, c.out)
		})
	}
}

func TestIsSameCaseInsensitive(t *testing.T) {
	t.Log("Running with equavalent strings")
	isSame := isSameCaseInsensitive("aba", "aBa")
	assert.True(t, isSame)

	t.Log("Running with non-equavalent strings")
	isNotSame := isSameCaseInsensitive("aca", "aBa")
	assert.False(t, isNotSame)
}

func TestMergeUrl(t *testing.T) {
	type testCase struct {
		name        string
		destination *url.URL
		source      *url.URL
		out         string
	}

	cases := []testCase{
		{
			name:        "with different paths",
			destination: &url.URL{Path: "/v1"},
			source:      &url.URL{Path: "/users"},
			out:         "/v1/users",
		},
		{
			name:        "with a new querystring",
			destination: &url.URL{RawQuery: "a=2"},
			source:      &url.URL{Path: "/users", RawQuery: "b=3"},
			out:         "/users?b=3",
		},
		{
			name:        "with a new fragment",
			destination: &url.URL{Path: "/v1", Fragment: "anchor1"},
			source:      &url.URL{Fragment: "anchor2"},
			out:         "/v1#anchor2",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := mergeURL(c.destination, c.source)
			assert.Equal(t, c.out, result.String())
		})
	}
}

func TestRedact(t *testing.T) {
	type testCase struct {
		name  string
		match HTTPMatch
		value interface{}
		out   interface{}
	}

	cases := []testCase{
		{
			name:  "with a number",
			match: makeBodyMatch(),
			value: 10.0,
			out:   0.0,
		},
		{
			name:  "with nil",
			match: makeBodyMatch(),
			value: nil,
			out:   nil,
		},
		{
			name:  "with an unsupported value",
			match: makeBodyMatch(),
			value: 12,
			out:   nil,
		},
		{
			name:  "with a string",
			match: makeBodyMatch(),
			value: "data",
			out:   "REDACTED",
		},
		{
			name:  "with a boolean",
			match: makeBodyMatch(),
			value: true,
			out:   false,
		},
		{
			name:  "with a slice of values",
			match: makeBodyMatch(),
			value: []interface{}{"a", 20.0, true},
			out:   []interface{}{"REDACTED", 0.0, false},
		},
		{
			name:  "with a map of values",
			match: makeBodyMatch(),
			value: map[string]interface{}{"string": "data", "bool": true},
			out:   map[string]interface{}{"string": "REDACTED", "bool": false},
		},
		{
			name:  "with a map of values",
			match: makeBodyMatch(),
			value: map[string]interface{}{"string": "data", "bool": true},
			out:   map[string]interface{}{"string": "REDACTED", "bool": false},
		},
		{
			name:  "with a map of values that are themselves containers",
			match: makeBodyMatch(),
			value: map[string]interface{}{"array": []interface{}{"str1", "str2"}},
			out:   map[string]interface{}{"array": []interface{}{"REDACTED", "REDACTED"}},
		},
		{
			name:  "with a whitelist",
			match: makeBodyMatch(ConfigRule{Whitelist: "$.bleep"}, ConfigRule{Whitelist: "$.array[0]"}),
			value: map[string]interface{}{"array": []interface{}{"str1", "str2"}},
			out:   map[string]interface{}{"array": []interface{}{"str1", "REDACTED"}},
		},
		{
			name:  "with a whitelist that matches two keys",
			match: makeBodyMatch(ConfigRule{Whitelist: "$.bleep"}, ConfigRule{Whitelist: "$.array[0]"}),
			value: map[string]interface{}{"array": []interface{}{"str1", "str2"}, "bleep": "bloop"},
			out:   map[string]interface{}{"array": []interface{}{"str1", "REDACTED"}, "bleep": "bloop"},
		},
		{
			name:  "with a wildcard whitelist",
			match: makeBodyMatch(ConfigRule{Whitelist: "$.array[*]"}),
			value: map[string]interface{}{"array": []interface{}{"str1", "str2"}},
			out:   map[string]interface{}{"array": []interface{}{"str1", "str2"}},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			value := redact(c.match, c.value, "$")
			assert.Equal(t, c.out, value)
		})
	}
}

func TestMapBody(t *testing.T) {
	type testCase struct {
		name  string
		match HTTPMatch
		body  string
		out   string
	}

	cases := []testCase{
		{
			name:  "with a basic body",
			match: makeBodyMatch(),
			body:  `{"a": "bloop"}`,
			out:   `{"a":"REDACTED"}`,
		},
		{
			name:  "with a basic body and a whitelist",
			match: makeBodyMatch(ConfigRule{Whitelist: "$.a"}),
			body:  `{"a": "bloop", "b": [true, "hey"]}`,
			out:   `{"a":"bloop","b":[false,"REDACTED"]}`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result, err := mapBody(c.match, "application/json", []byte(c.body))
			if err != nil {
				t.Fail()
			}
			assert.Equal(t, string(result[:]), c.out)
		})
	}
}

func TestMapBodyWithWrongContentType(t *testing.T) {
	body := []byte("{ query: { id } }")
	result, err := mapBody(HTTPMatch{}, "application/graphql", body)
	if err != nil {
		t.Fail()
	}
	assert.Equal(t, result, []byte{})
}

func TestGetContentType(t *testing.T) {
	request, err := http.NewRequest("GET", "", strings.NewReader(""))
	if err != nil {
		t.Fail()
	}

	request.Header.Add("Content-Type", "application/json; charset=utf8")
	result := getContentType(request)
	assert.Equal(t, result, "application/json")
}

func TestRedactBody(t *testing.T) {
	type testCase struct {
		name         string
		match        HTTPMatch
		request      *http.Request
		expectedBody string
	}

	cases := []testCase{
		{
			name:         "with an empty JSON body",
			match:        HTTPMatch{},
			request:      makeRequest(`{}`, "application/json"),
			expectedBody: "{}",
		},
		{
			name:         "with a non-empty JSON body",
			match:        HTTPMatch{},
			request:      makeRequest(`{"a": "data"}`, "application/json"),
			expectedBody: `{"a":"REDACTED"}`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := redactBody(c.match, c.request)
			if err != nil {
				t.Fail()
			}

			body, err := ioutil.ReadAll(c.request.Body)
			if err != nil {
				t.Fail()
			}

			assert.Equal(t, string(body[:]), c.expectedBody)
			assert.Equal(t, strconv.FormatInt(c.request.ContentLength, 10), c.request.Header.Get("Content-Length"))
			assert.Equal(t, c.request.ContentLength, int64(len(body)))
		})
	}
}

func TestRedactQuerystring(t *testing.T) {
	type testCase struct {
		name  string
		match HTTPMatch
		in    url.URL
		out   string
	}

	cases := []testCase{
		{
			name:  "with empty query",
			match: HTTPMatch{},
			in:    url.URL{RawQuery: ""},
			out:   "",
		},
		{
			name:  "with a query with no whitelist",
			match: HTTPMatch{},
			in:    url.URL{RawQuery: "a=2&b=3"},
			out:   "a=REDACTED&b=REDACTED",
		},
		{
			name:  "with a query with a single whitelist value",
			match: makeQuerystringMatch(ConfigRule{Whitelist: "a"}),
			in:    url.URL{RawQuery: "a=2&b=3"},
			out:   "a=2&b=REDACTED",
		},
		{
			name:  "with a query with many whitelist values",
			match: makeQuerystringMatch(ConfigRule{Whitelist: "a"}, ConfigRule{Whitelist: "b"}),
			in:    url.URL{RawQuery: "a=2&b=3&c=2"},
			out:   "a=2&b=3&c=REDACTED",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := redactQuerystring(c.match, &c.in)
			assert.Equal(t, result, c.out)
		})
	}
}

func TestMakeDirectory(t *testing.T) {
	makeRequestWithExtras := func(method string, path string, query string, body string) *http.Request {
		request := makeRequest(body, "application/json")

		request.Method = method
		request.URL.Path = path
		request.URL.RawQuery = query

		return request
	}

	config := Config{
		ProxyPass: "https://api.usebutton.com/ingest",
		Match: MatchOptions{
			HTTP: []HTTPMatch{
				HTTPMatch{
					Path:   "/v1/whitelist",
					Method: "GET",
					RuleOptions: RuleOptions{
						Body: []ConfigRule{
							ConfigRule{
								Whitelist: "$.a.b",
							},
							ConfigRule{
								Whitelist: "$.a.c",
							},
						},
						Querystring: []ConfigRule{
							ConfigRule{
								Whitelist: "a",
							},
						},
					},
				},
			},
		},
	}

	director, _ := makeDirector(config)

	type testCase struct {
		name          string
		request       *http.Request
		expectedBody  string
		expectedQuery string
		expectedURL   string
	}

	cases := []testCase{
		{
			name:         "with an empty payload",
			request:      makeRequest("{}", "application/json"),
			expectedBody: "{}",
			expectedURL:  "https://api.usebutton.com/ingest",
		},
		{
			name:         "with an unsupported content-type",
			request:      makeRequest("{ id }", "application/graphql"),
			expectedBody: "",
			expectedURL:  "https://api.usebutton.com/ingest",
		},
		{
			name:         "with a json payload",
			request:      makeRequestWithExtras("", "", "", `{"a":{"b":10}}`),
			expectedBody: `{"a":{"b":0}}`,
			expectedURL:  "https://api.usebutton.com/ingest",
		},
		{
			name:         "with a json payload an exemptions",
			request:      makeRequestWithExtras("GET", "/v1/whitelist", "a=1&c=2", `{"a":{"b":10,"c":"data","d":10}}`),
			expectedBody: `{"a":{"b":10,"c":"data","d":0}}`,
			expectedURL:  "https://api.usebutton.com/ingest/v1/whitelist?a=1&c=REDACTED",
		},
		{
			name:         "with a json payload an exemptions but wrong method",
			request:      makeRequestWithExtras("POST", "/v1/whitelist", "a=1", `{"a":{"b":10}}`),
			expectedBody: `{"a":{"b":0}}`,
			expectedURL:  "https://api.usebutton.com/ingest/v1/whitelist?a=REDACTED",
		},
		{
			name:         "with a json payload an exemptions but wrong pathname",
			request:      makeRequestWithExtras("GET", "/v2/whitelist", "a=1", `{"a":{"b":10}}`),
			expectedBody: `{"a":{"b":0}}`,
			expectedURL:  "https://api.usebutton.com/ingest/v2/whitelist?a=REDACTED",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			director(c.request)

			body, err := ioutil.ReadAll(c.request.Body)
			if err != nil {
				t.Fail()
			}

			assert.Equal(t, string(body[:]), c.expectedBody)
			assert.Equal(t, c.request.URL.String(), c.expectedURL)
			assert.Equal(t, c.request.Host, "api.usebutton.com")
			assert.Equal(t, c.request.Header.Get("x-privacy-proxy-redacted"), "1")
		})
	}
}
