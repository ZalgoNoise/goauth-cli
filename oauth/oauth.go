package oauth

import (
	"fmt"
	"strconv"
)

// TokenError represents a JSON response containing an error
// when requesting an Access Token
type TokenError struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

// AccessToken struct represents a JSON response containing an
// Access Token, for either Client IDs or Service Accounts
type AccessToken struct {
	Token        string `json:"access_token,omitempty"`
	Expiry       int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scopes       string `json:"scope,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
}

// IsSet method will check whether the Access Token value is
// set or not, returning a boolean (true / false) accordingly
func (a *AccessToken) IsSet() bool {
	if a.Token != "" {
		return true
	}

	return false
}

// PrintLong method will output a more verbose message when the
// Access Token is about to be returned to the user
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

// PrintShort method will output strictly the Access Token,
// without line feeds. This might be especially useful when feeding
// the value into another program or app (like a cURL HTTP request)
func (a *AccessToken) PrintShort() {
	fmt.Print(a.Token)
}
