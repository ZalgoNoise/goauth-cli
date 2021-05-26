package oauth

import (
	"testing"
	// "fmt"
	// "strings"
)

func TestNewClientID(t *testing.T) {
	type input struct {
		id           string
		secret       string
		scopes       string
		refreshToken string
	}

	tests := []struct {
		input input
		ok    bool
	}{
		{
			input: input{
				id:           "ClientID",
				secret:       "ClientSecret",
				scopes:       "https://www.googleapis.com/auth/userinfo.email",
				refreshToken: "",
			},
			ok: true,
		}, {
			input: input{
				id:           "ClientID",
				secret:       "ClientSecret",
				scopes:       "https://www.googleapis.com/auth/userinfo.email",
				refreshToken: "SomeRefreshToken",
			},
			ok: true,
		}, {
			input: input{
				id:           "ClientID",
				secret:       "ClientSecret",
				scopes:       "",
				refreshToken: "SomeRefreshToken",
			},
			ok: true,
		}, {
			input: input{
				id:           "ClientID",
				secret:       "ClientSecret",
				scopes:       "",
				refreshToken: "",
			},
			ok: false,
		}, {
			input: input{
				id:           "ClientID",
				secret:       "",
				scopes:       "https://www.googleapis.com/auth/userinfo.email",
				refreshToken: "",
			},
			ok: false,
		}, {
			input: input{
				id:           "",
				secret:       "ClientSecret",
				scopes:       "https://www.googleapis.com/auth/userinfo.email",
				refreshToken: "",
			},
			ok: false,
		},
	}

	for _, test := range tests {
		_, err := NewClientID(
			test.input.id,
			test.input.secret,
			test.input.scopes,
			test.input.refreshToken,
		)
		if err != nil && test.ok != false {
			t.Errorf(`TestNewClientID(%q) = %q, expected error to be %v`, test.input, err, test.ok)
		}
	}
}

func TestClientIDAuthURL(t *testing.T) {
	type input struct {
		id           string
		secret       string
		scopes       string
		refreshToken string
	}

	tests := []struct {
		input input
		want    string
	}{
		{
			input: input{
				id:           "ClientID",
				secret:       "ClientSecret",
				scopes:       "https://www.googleapis.com/auth/userinfo.email",
				refreshToken: "",
			},
			want: "https://accounts.google.com/o/oauth2/auth?client_id=ClientID&redirect_uri=urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob&response_type=code&access_type=offline&prompt=consent&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email",
		},{
			input: input{
				id:           "ClientID",
				secret:       "ClientSecret",
				scopes:       "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile",
				refreshToken: "",
			},
			want: "https://accounts.google.com/o/oauth2/auth?client_id=ClientID&redirect_uri=urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob&response_type=code&access_type=offline&prompt=consent&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.profile",
		},
	}

	for _, test := range tests {
		clientID, _ := NewClientID(
			test.input.id,
			test.input.secret,
			test.input.scopes,
			test.input.refreshToken,
		)

		clientID.RefreshToken.SetAuthURL(clientID)
		if clientID.RefreshToken.GetAuthURL() != test.want {
			t.Errorf(`TestClientIDAuthURL(%q) = %q, expected result to be %q`, test.input.scopes, clientID.RefreshToken.GetAuthURL(), test.want)
		}
	}
}
