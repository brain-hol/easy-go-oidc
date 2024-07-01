package main

import "testing"

func newConf(url string) *OAuth2Config {
	return &OAuth2Config{
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
		RedirectURL:  "REDIRECT_URL",
		Scopes:       []string{"scope1", "scope2"},
		Endpoint: OAuth2Endpoint{
			AuthURL:  url + "/auth",
			TokenURL: url + "/token",
		},
	}
}

func TestAuthCodeURL(t *testing.T) {
	conf := newConf("server")
	got := conf.AuthCodeURL("abc")
	const want = "server/auth?client_id=CLIENT_ID&redirect_uri=REDIRECT_URL&response_type=code&scope=scope1+scope2&state=abc"
	if got != want {
		t.Errorf("got auth code URL = %q; want %q", got, want)
	}
}

func TestAuthCodeURL_CustomParam(t *testing.T) {
	conf := newConf("server")
	setTestParam := SetAuthURLParam("testParam", "testValue")
	got := conf.AuthCodeURL("stateAbc", setTestParam)
	const want = "server/auth?client_id=CLIENT_ID&redirect_uri=REDIRECT_URL&response_type=code&scope=scope1+scope2&state=stateAbc&testParam=testValue"
	if got != want {
		t.Errorf("got auth code URL = %q; want %q", got, want)
	}
}
