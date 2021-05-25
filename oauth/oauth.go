package oauth

import (
	"fmt"
	"strconv"
)

type TokenError struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

// AccessToken struct
type AccessToken struct {
	Token        string `json:"access_token,omitempty"`
	Expiry       int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scopes       string `json:"scope,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
}

// type Authenticator interface {
// 	SetToken(body []byte)
// }

func (a *AccessToken) IsSet() bool {
	if a.Token != "" {
		return true
	}

	return false
}

func (a *AccessToken) PrintLong() {
	if a.RefreshToken != "" {
		fmt.Println(`====
Access Token: ` + a.Token + `
Expiry: ` + strconv.Itoa(a.Expiry) + `
Refresh Token: ` + a.RefreshToken + `
====`)
		return
	}

	fmt.Println(`====
Access Token: ` + a.Token + `
Expiry: ` + strconv.Itoa(a.Expiry) + `
====`)
	return
}

func (a *AccessToken) PrintShort() {
	fmt.Print(a.Token)
}
