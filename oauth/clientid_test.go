package oauth

import (
	"testing"
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
