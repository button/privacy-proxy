# Privacy Proxy

> The best way to prevent leaking information is to prevent taking information.

Privacy Proxy is a reverse proxy designed for filtering in-bound data streams to
your organization free of any Personally Identifiable Information.  By default,
Privacy Proxy strips all request body and querystring data of proxied HTTP
requests.

It makes accepting data into your systems a deliberate step, rather than an
incidental one.  Placing Privacy Proxy as close to SSL termination as possible
ensures data you don't want isn't accidentally dropped into logfiles, bug
aggregators, internal tools, etc.

```
                               +-------------------+
{                              |   Privacy Proxy   |     {
  "event_id": 42,              |                   |       "event_id": 42,
  "email": diggy@net.cool"  +-->                   +-->    "email: "REDACTED"
}                              |  Whitelist:       |     }
                               |    - event_id     |
                               |                   |
                               +-------------------+
```

It's unclear what the optimal form of this idea is.  It might be a middleware,
a load balancer module, or otherwise.  This reverse proxy is one instance of the
core idea of a whitelist redactor.

**Table of Contents**

1. [Quick Start](#quick-start)
2. [Config](#config)
3. [Whitelist Syntax](#whitelist-syntax)
4. [Deployment](#deployment)
5. [FAQ](#faq)
6. [Design Principles](#design-principles)
7. [Future Work](#future-work)
8. [Contributing](#contributing)

### Quick Start

We're going to define a reverse proxy available on port `8080` that forwards
traffic to `http://httpbin.org`.  It will only pass through values with
a top-level key named `event_id` sent with an HTTP `POST` request at `/post`.

We can declare that by writing a simple [.hcl](https://github.com/hashicorp/hcl)
file:

###### `config.hcl`
```hcl
port = "8080"
proxy_pass = "http://httpbin.org"

match "http" {
  pathname = "/post"
  method = "post"

  rule "body" {
    whitelist = "$.event_id"
  }
}
```

Start Privacy Proxy...

```bash
$ go get github.com/button/privacy-proxy
$ ./privacy-proxy config.hcl
```

Make a request...

```bash
$ curl -H 'Content-Type: application/json' -X POST -d '{"ssn": "123-12-1234", "event_id": 1989}' localhost:8080/post
```

The payload we send onto `httpbin.org` (and which is conveniently echoed back)
will be stripped of the `ssn` key:

```json
{
  "event_id": 1989,
  "ssn": "REDACTED"
}
```

Nice!

### Config

###### `port` _(default: 8888)_

The TCP port to listen on.

###### `proxy_pass`

The upstream location to forward traffic to.  Must be an [absolute URI](https://tools.ietf.org/html/rfc3986#page-27) including scheme and hostname.  Supports atypical ports and
a pathname prefix to stack proxied requests on top of.

For instance if `proxy_pass` is `http://api.company.com:9000/data` and a request
comes in for `GET /foo`, we'll forward to
`http://api.company.com:9000/data/foo`.

###### `match`

A `match` clause specifies when a whitelist of rules match for a request.  For
instance, we might want to have a different set of fields we whitelist for
requests to `POST /users` than `POST /events`.  Only the first `match` clause that
matches a request will be used, so clauses should be declared in order of most
to least specific.

A `match` clause must be scoped to the protocol we're matching.  Currently, only
`"http"` is supported.  An HTTP `match` clause that will match all HTTP requests
is written:

```hcl
match "http" {
  # ...
}
```

The two fields we can optionally specify for an HTTP request are:

* `pathname`
* `method`

If either are omitted, they will match any value.  An HTTP `match` clause that
 matches any `POST` request is written:

```hcl
match "http" {
  method = "POST"
}
```

###### `rule`

Inside a `match` clause we can specify any number of `rule` clauses, which
define our whitelist to pass-through.  Whitelisting is supported on request
bodies and querystrings:

```hcl
match "http" {
  pathname = "/events"

  rule "body" {
    whitelist = "$.event_id"
  }

  rule "body" {
    whitelist = "$.event_created_date"
  }
}

match "http" {
  method = "GET"

  rule "querystring" {
    whitelist = "$.foo"
  }
}
```

### Whitelist Syntax

To specify a value to whitelist, we write a string identifying its location in
a tree-like document.  They always start with the special character `$`
indicating the root.  To declare arbitrarily nested fields, we can append as
many of the following expressions as we like:

* `.<KEY>`:  Dereference a key in an Object-like structure
* `[INDEX]`: Dereference an index in an Array-like structure
  * if `INDEX` is positive integer: matches just the element at position `INDEX`
    (zero-indexed).
  * if `INDEX` is `*`: matches all indexes

For instance, given the following JSON:

```json
{
  "a": [
    { "c": 4 },
    { "c": 2 }
  ]
}
```

We can whitelist all `c` values with:

```
"$.a[*].c"
```

Note that if the value at `c` was actually a container type (like an Object or
Array), it would _pass the whole value through_.  For this reason, it's
generally recommended to whitelist leaf nodes of documents (more specific).

### Deployment

Your Privacy Proxy should be placed as close to the data source as possible.
This helps prevent against PII leaking to e.g. log files inadvertently.  If you
have a load balancer that terminates SSL, you could use this as the downstream
server and then forward this on to your application tier.

### FAQ

> _Isn't this a dumb idea?_

Maybe!

> _Extra network hops?  No way!_

Fair!  It's definitely going to add a bit to your round trip time. Redacting PII
in application code is always in-bounds and always a great idea.  For cases
where you can afford the latency, Privacy Proxy is a nice architectural block to
build safe systems with.

### Design Principles

##### Whitelist Filtering

Privacy Proxy chooses to whitelist values it should pass through.  The mental model
is, "every value I enumerate I consent to seeing in my system."  This forces us
as engineers to exercise a bit more thought and diligence over which data we're
interested and willing to steward on behalf of a user.

Additionally, consider an alternative blacklist approach:

```
                                +----------------+
{                               | Privacy Proxy  |     {
  "event_id": 42,               |                |       "event_id": 42,
  "email": "diggy@net.cool"  +-->                +-->    "email: "REDACTED"
}                               |  Blacklist:    |     }
                                |    - email     |
                                |                |
                                +----------------+
```

If six months later the incoming data is augmented to include a new, potentially
risky field and we don't notice (after all, it's backwards compatible!), our
blacklist will happily pass through some spooky data:

```
                                +-----------------+
{                               |  Privacy Proxy  |     {
  "event_id": 42,               |                 |       "event_id": 42,
  "email": "diggy@net.cool", +-->                 +-->    "email: "REDACTED",
  "ssn": "123-4567-8910"        |  Blacklist:     |       "ssn": "123-4567-8910"
}                               |    - email      |     }
                                |                 |
                                +-----------------+
```

Put another way, it should be harder to _accept_ a new third party field than
_reject_ one.  Whitelists are our friend in this way.

##### Hashing

An interesting alternative to overwriting redacted data would be hashing it.
This might be a good option for cases where equality between values in a data
stream are important but actual content isn't.

Of course, even with a salt and industry standard hashing algorithms, this
will never be quite as good as overwriting, and depending on jurisdiction might
still qualify as PII.

### Future Work

* Regex value checking: i.e. did someone *accidentally* send an email when we
  wanted a hash?
* More expressive location syntax
* More expressive pathname matching
* A centralized node that can monitor and deploy config updates to edge nodes
* Support additional request body types:
  * XML
  * Protobuf
  * Form encoding
* Support for other architectures: Middleware, AWS Lambda, queues, etc.  Keep a
  hard separation between the core redacting logic and the host interface to
  make it pluggable.

### Contributing

We welcome contributions to Privacy Proxy!  Please review our
[Code of Conduct](https://github.com/button/privacy-proxy/blob/master/CODE_OF_CONDUCT.md)
before submitting an Issue or Pull Request.

1) _(Optional)_: Vet your idea by submitting an [Issue](https://github.com/button/privacy-proxy/issues/new)
2) Implement a change you'd like to see
3) Run the tests: `go test`
4) Submit a focused PR with an appropriate description of the problem, goals,
and proposed solution.
