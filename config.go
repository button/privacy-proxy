package main

import (
	"io/ioutil"
	"regexp"

	// hashicorp/hcl has a bug that was a show-stopper for parsing the config
	// the way I wanted: https://github.com/hashicorp/hcl/issues/164
	//
	// This is fixed by the following fork (a PR has been submitted against it:
	// https://github.com/hashicorp/hcl/pull/228)
	//
	// TODO: replace with hashicorp/hcl when 228 is merged.
	"github.com/carlsverre/hcl"
)

var (
	ArraySplat     = regexp.MustCompile(`\[\*\]`)
	EscapeReserved = regexp.MustCompile(`([.$\[\]])`)
)

type ConfigRule struct {
	Whitelist string
}

type RuleOptions struct {
	Body        []ConfigRule
	Querystring []ConfigRule
}

type HTTPMatch struct {
	Path        string
	Method      string
	RuleOptions `hcl:"rule"`
}

type MatchOptions struct {
	HTTP []HTTPMatch
}

type Config struct {
	Match     MatchOptions
	Port      string
	ProxyPass string `hcl:"proxy_pass"`
}

func loadConfig(file string, config *Config) error {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}

	return hcl.Unmarshal(data, config)
}

// Parses a location string into a regex capable of matching against.  A
// location string supports specifying an arbitrarily nested key in a tree-type
// data structure (like a JSON or XML blob).
//
// For instance, given the following JSON:
//
//   { "a": [{ "c": 4 }, { "c" }] }
//
// We can whitelist all c values with:
//
//   $.a[*].c
//
// * `$` specifies the root of the document
// * `.` specifies dereferencing a key on an Object
// * `[n]` specifies dereferencing an index of an Array where n can be..
//   * any positive integer to specify a specific index to whitelist
//   * `*` to specify all indexes in an Array
func locationToRegex(location string) *regexp.Regexp {
	result := ArraySplat.ReplaceAllLiteralString(location, "[\\d+]")
	result = EscapeReserved.ReplaceAllString(result, "\\$1")

	pattern := "^" + result + "$"
	return regexp.MustCompile(pattern)
}

// FindHTTPMatch finds the first http match clause in the server's config that
// matches the method and pathname of the current request.  Used to lookup the
// whitelist rules defined for the match.
func (config Config) FindHTTPMatch(method string, pathname string) HTTPMatch {
	for _, m := range config.Match.HTTP {
		isMatch := true

		if m.Method != "" {
			isMatch = isMatch && isSameCaseInsensitive(m.Method, method)
		}

		if m.Path != "" {
			isMatch = isMatch && isSamePath(m.Path, pathname)
		}

		if isMatch {
			return m
		}
	}

	return HTTPMatch{}
}

// HasBodyWhitelistMatch returns whether or not the whitelist request body rules
// match the location of data currently being scanned.
func (r RuleOptions) HasBodyWhitelistMatch(location string) bool {
	for _, rule := range r.Body {
		re := locationToRegex(rule.Whitelist) // todo: cache, somewhere
		if re.MatchString(location) {
			return true
		}
	}

	return false
}

// HasQuerystringWhitelistMatch returns whether or not a key in a querystring
// has been whitelisted
func (r RuleOptions) HasQuerystringWhitelistMatch(key string) bool {
	for _, rule := range r.Querystring {
		if rule.Whitelist == key {
			return true
		}
	}

	return false
}
