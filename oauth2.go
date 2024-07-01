package main

import (
	"bytes"
	"net/url"
	"strings"
)

type OAuth2Config struct {
	RedirectURL  string
	ClientID     string
	ClientSecret string
	Endpoint     OAuth2Endpoint
	Scopes       []string
}

type OAuth2Endpoint struct {
	AuthURL  string
	TokenURL string
}

type AuthURLOption func(url.Values)

func SetAuthURLParam(key string, value string) AuthURLOption {
	return func(v url.Values) {
		v.Set(key, value)
	}
}

func (c *OAuth2Config) AuthCodeURL(state string, opts ...AuthURLOption) string {
	var buf bytes.Buffer
	buf.WriteString(c.Endpoint.AuthURL)
	v := url.Values{
		"response_type": {"code"},
		"client_id":     {c.ClientID},
	}
	if c.RedirectURL != "" {
		v.Set("redirect_uri", c.RedirectURL)
	}
	if len(c.Scopes) > 0 {
		v.Set("scope", strings.Join(c.Scopes, " "))
	}
	if state != "" {
		v.Set("state", state)
	}
	for _, opt := range opts {
		opt(v)
	}
	if strings.Contains(c.Endpoint.AuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	return buf.String()
}
