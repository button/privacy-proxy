// Privacy Proxy is a simple application-layer reverse-proxy that by default
// redacts all data from HTTP querystrings and request bodies while preserving
// the shape of the data.  By specifying a whitelist in a config file, certain
// data can be allowed to pass through unaffected.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"

	"gopkg.in/alecthomas/kingpin.v2"
)

// What we redact a value, we overwrite it with these, depending on type.
const (
	RedactedStr    = "REDACTED"
	RedactedNumber = 0.0
	RedactedBool   = false
)

// Supported content types
const (
	JSON = "application/json"
)

// Returns true iff two strings are equivalent regardless of trailing slashes
func isSamePath(a string, b string) bool {
	return strings.TrimRight(a, "/") == strings.TrimRight(b, "/")
}

// Returns true iff two strings are equal regardless of case
func isSameCaseInsensitive(a string, b string) bool {
	return strings.ToLower(a) == strings.ToLower(b)
}

// Redacts any non-whitelisted key locations from `value`.  If a key is
// whitelisted, the entire value of that key is passed through.
//
// Returns a redacted copy of `value`, does not mutate.
func redact(match HTTPMatch, value interface{}, locationPrefix string) interface{} {
	if match.HasBodyWhitelistMatch(locationPrefix) {
		return value
	}

	switch typedValue := value.(type) {
	case map[string]interface{}:
		m := make(map[string]interface{})
		for k, v := range typedValue {
			m[k] = redact(match, v, locationPrefix+"."+k)
		}
		return m
	case []interface{}:
		m := make([]interface{}, len(typedValue))
		for k, v := range typedValue {
			m[k] = redact(match, v, locationPrefix+"["+strconv.Itoa(k)+"]")
		}
		return m
	case float64:
		return RedactedNumber
	case string:
		return RedactedStr
	case bool:
		return RedactedBool
	case nil:
		return nil
	default:
		return nil
	}
}

// Maps a request body to a redacted version, preserving the "shape" of the
// data.  Currently supports only the following content-types:
//
// * application/json
//
// If the content-type isn't supported, zero bytes are returned.
func mapBody(match HTTPMatch, contentType string, body []byte) ([]byte, error) {
	newBody := []byte{}

	if !isSameCaseInsensitive(contentType, JSON) {
		return newBody, nil
	}

	var parsed interface{}
	err := json.Unmarshal(body, &parsed)
	if err != nil {
		return newBody, err
	}

	redacted := redact(match, parsed, "$")

	newBody, err = json.Marshal(redacted)
	if err != nil {
		return []byte{}, err
	}

	return newBody, nil
}

// Extract the content-type of the request, taking care to strip any charset
// or boundary information (delimited by a ';' character).  Returns the empty
// string if not found.
//
// e.g. getContentType("application/diggy; charset=utf8")
//   => "application/diggy"
func getContentType(r *http.Request) string {
	headerValue := r.Header.Get("Content-Type")
	if headerValue == "" {
		return ""
	}

	headerValueSplit := strings.Split(headerValue, ";")
	return headerValueSplit[0]
}

// Redact values from the request body unless the key location is whitelisted
// in the config.  If the type of the body can't be inferred, the body will be
// set to zero bytes.  Mutates r.
func redactBody(ruleMatch HTTPMatch, r *http.Request) error {
	if r.Body == nil {
		return nil
	}

	body, err := ioutil.ReadAll(r.Body)

	if err != nil {
		return err
	}

	redactedBody := []byte{}
	contentType := getContentType(r)

	if contentType != "" {
		redactedBody, err = mapBody(ruleMatch, contentType, body)
	}

	contentLength := len(redactedBody)

	r.Body = ioutil.NopCloser(bytes.NewReader(redactedBody))
	r.Header.Set("Content-Length", strconv.Itoa(contentLength))
	r.ContentLength = int64(contentLength)

	return err
}

// Redact values from the querystring unless the key was whitelisted in the
// config.  Returns a string that can be assigned to any url.URL's RawQuery
// property.
func redactQuerystring(ruleMatch HTTPMatch, u *url.URL) string {
	queryValues := url.Values{}

	for k, values := range u.Query() {
		for _, v := range values {
			value := RedactedStr
			if ruleMatch.HasQuerystringWhitelistMatch(k) {
				value = v
			}

			queryValues.Add(k, value)
		}
	}

	return queryValues.Encode()
}

// Merge a source URL onto a destination URL.  For example, if:
//
// source = /v1/users?a=2#anchor
// destination = /upstream
//
// then mergeUrl returns
//
// /upstream/v1/users?a=2#anchor
//
// mergeURL returns a new url.URL instance, it does not mutate its arguments.
func mergeURL(destination *url.URL, source *url.URL) url.URL {
	result := *destination

	result.Path = path.Join(destination.Path, source.Path)
	result.RawQuery = source.RawQuery
	result.Fragment = source.Fragment

	return result
}

// A director is used to handle the reading and potential re-writing of a
// request we're proxying.
func makeDirector(config Config) (func(*http.Request), error) {
	targetURL, err := url.Parse(config.ProxyPass)
	if err != nil {
		return func(r *http.Request) {}, err
	}

	return func(r *http.Request) {
		originalURL := r.URL
		upsteamURL := mergeURL(targetURL, r.URL)

		r.URL = &upsteamURL
		r.Host = r.URL.Host
		r.Header.Add("x-privacy-proxy-redacted", "1")

		// Find the first matching HTTP ruleset from the config to use
		// for filtering the request.
		ruleMatch := config.FindHTTPMatch(r.Method, originalURL.Path)

		err = redactBody(ruleMatch, r)
		if err != nil {
			fmt.Println(err)
		}

		r.URL.RawQuery = redactQuerystring(ruleMatch, r.URL)
	}, nil
}

func main() {
	var (
		app        = kingpin.New("privacy-proxy", "A Data-Redacting Reverse Proxy")
		configPath = app.Arg("config", "An HCL formatted config file").Required().String()
	)

	kingpin.Version("0.0.1")
	kingpin.MustParse(app.Parse(os.Args[1:]))

	config := Config{}
	err := loadConfig(*configPath, &config)
	if err != nil {
		log.Fatal(err)
	}

	director, err := makeDirector(config)
	if err != nil {
		log.Fatal(err)
	}
	proxy := &httputil.ReverseProxy{Director: director}

	port := config.Port
	if port == "" {
		port = "8888"
	}

	if config.ProxyPass == "" {
		log.Fatal("Must specify backend server as `proxy_pass` in " + *configPath)
	}

	fmt.Println("Privacy Proxy listening on " + port + "...")
	err = http.ListenAndServe(":"+port, proxy)
	if err != nil {
		log.Fatal(err)
	}
}
