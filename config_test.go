package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFindHTTPMatch(t *testing.T) {
	makeConfig := func(matches ...HTTPMatch) Config {
		return Config{Match: MatchOptions{HTTP: matches}}
	}

	type testCase struct {
		name   string
		config Config
		method string
		path   string
		out    HTTPMatch
	}

	cases := []testCase{
		{
			name:   "with no rules",
			config: makeConfig(),
			out:    HTTPMatch{},
		},
		{
			name:   "with no match for method",
			config: makeConfig(HTTPMatch{Method: "POST"}),
			out:    HTTPMatch{},
		},
		{
			name:   "with a match for method",
			config: makeConfig(HTTPMatch{Method: "POST"}),
			method: "POST",
			out:    HTTPMatch{Method: "POST"},
		},
		{
			name:   "with a case-insensitive match for method",
			config: makeConfig(HTTPMatch{Method: "POST"}),
			method: "post",
			out:    HTTPMatch{Method: "POST"},
		},
		{
			name:   "with no match for path",
			config: makeConfig(HTTPMatch{Path: "/v1"}),
			out:    HTTPMatch{},
		},
		{
			name:   "with a match for path",
			config: makeConfig(HTTPMatch{Path: "/v1"}),
			path:   "/v1",
			out:    HTTPMatch{Path: "/v1"},
		},
		{
			name:   "with a trailing-slash insensitive match for path",
			config: makeConfig(HTTPMatch{Path: "/v1"}),
			path:   "/v1/",
			out:    HTTPMatch{Path: "/v1"},
		},
		{
			name:   "with no matches that satisfy method and path",
			config: makeConfig(HTTPMatch{Path: "/v1", Method: "GET"}, HTTPMatch{Path: "/v2", Method: "POST"}),
			path:   "/v1",
			method: "POST",
			out:    HTTPMatch{},
		},
		{
			name:   "with only the first match returning",
			config: makeConfig(HTTPMatch{Path: "/v1", Method: "GET"}, HTTPMatch{Method: "POST"}, HTTPMatch{Path: "/v1", Method: "POST"}),
			path:   "/v1",
			method: "POST",
			out:    HTTPMatch{Method: "POST"},
		},
		{
			name:   "with only the first match returning",
			config: makeConfig(HTTPMatch{Path: "/v1", Method: "GET"}, HTTPMatch{Method: "POST"}, HTTPMatch{}),
			path:   "/v2",
			method: "GET",
			out:    HTTPMatch{},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			match := c.config.FindHTTPMatch(c.method, c.path)
			assert.Equal(t, match, c.out)
		})
	}
}

func TestHasBodyWhitelistMatch(t *testing.T) {
	makeRuleOptions := func(rules ...ConfigRule) RuleOptions {
		return RuleOptions{Body: rules}
	}

	type testCase struct {
		name        string
		ruleOptions RuleOptions
		location    string
		out         bool
	}

	cases := []testCase{
		{
			name:        "with no rules",
			ruleOptions: makeRuleOptions(),
			location:    "$.a",
			out:         false,
		},
		{
			name:        "with a rule that doesn't match",
			ruleOptions: makeRuleOptions(ConfigRule{Whitelist: "$.a"}),
			location:    "$.b",
			out:         false,
		},
		{
			name:        "with a rule that matches",
			ruleOptions: makeRuleOptions(ConfigRule{Whitelist: "$.a"}),
			location:    "$.a",
			out:         true,
		},
		{
			name:        "with a complex rule that matches",
			ruleOptions: makeRuleOptions(ConfigRule{Whitelist: "$[*]"}),
			location:    "$[5]",
			out:         true,
		},
		{
			name:        "with a rule that matches out of many",
			ruleOptions: makeRuleOptions(ConfigRule{Whitelist: "$.b"}, ConfigRule{Whitelist: "$.a"}),
			location:    "$.a",
			out:         true,
		},
		{
			name:        "with no rule that matches out of many",
			ruleOptions: makeRuleOptions(ConfigRule{Whitelist: "$.b"}, ConfigRule{Whitelist: "$.a"}),
			location:    "$.c",
			out:         false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hasMatch := c.ruleOptions.HasBodyWhitelistMatch(c.location)
			assert.Equal(t, hasMatch, c.out)
		})
	}
}

func TestHasQuerystringWhitelistMatch(t *testing.T) {
	makeRuleOptions := func(rules ...ConfigRule) RuleOptions {
		return RuleOptions{Querystring: rules}
	}

	type testCase struct {
		name        string
		ruleOptions RuleOptions
		key         string
		out         bool
	}

	cases := []testCase{
		{
			name:        "with no rules",
			ruleOptions: makeRuleOptions(),
			key:         "a",
			out:         false,
		},
		{
			name:        "with one matching rule",
			ruleOptions: makeRuleOptions(ConfigRule{Whitelist: "a"}),
			key:         "a",
			out:         true,
		},
		{
			name:        "one matching rule out of many",
			ruleOptions: makeRuleOptions(ConfigRule{Whitelist: "a"}, ConfigRule{Whitelist: "b"}),
			key:         "b",
			out:         true,
		},
		{
			name:        "no matching rules out of many",
			ruleOptions: makeRuleOptions(ConfigRule{Whitelist: "a"}, ConfigRule{Whitelist: "b"}),
			key:         "c",
			out:         false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hasMatch := c.ruleOptions.HasQuerystringWhitelistMatch(c.key)
			assert.Equal(t, hasMatch, c.out)
		})
	}
}

func TestLocationToRegex(t *testing.T) {
	type testCase struct {
		name    string
		pattern string
		test    string
		match   bool
	}

	cases := []testCase{
		{
			name:    "matches itself",
			pattern: "$.a",
			test:    "$.a",
			match:   true,
		},
		{
			name:    "must match the entire pattern",
			pattern: "$.a",
			test:    "!$.a",
			match:   false,
		},
		{
			name:    "must match the entire pattern",
			pattern: "$.a",
			test:    "$.a!",
			match:   false,
		},
		{
			name:    "must match the entire pattern",
			pattern: "$.a",
			test:    "!$.a!",
			match:   false,
		},
		{
			name:    "matches array indices",
			pattern: "$.a[5]",
			test:    "$.a[5]",
			match:   true,
		},
		{
			name:    "matches array indices",
			pattern: "$.a[5]",
			test:    "$.a[4]",
			match:   false,
		},
		{
			name:    "matches wildcard array indices",
			pattern: "$.a[*]",
			test:    "$.a[4]",
			match:   true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hasMatch := locationToRegex(c.pattern).MatchString(c.test)
			assert.Equal(t, hasMatch, c.match)
		})
	}
}
