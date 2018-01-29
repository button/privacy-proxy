port = "8080"
proxy_pass = "http://httpbin.org"

match "http" {
  pathname = "/post"
  method = "post"

  rule "body" {
    whitelist = "$.events[*].event_id"
  }

  rule "body" {
    whitelist = "$.events[*].user.id"
  }
}

match "http" {
  pathname = "/get"
  method = "GET"

  rule "querystring" {
    whitelist = "eventid"
  }
}
