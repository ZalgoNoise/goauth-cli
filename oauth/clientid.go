package oauth

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

)

// ClientID struct will represent a Client ID object
type ClientID struct {
	Type         string
	ID           string
	Secret       string
	Scopes       string
	RefreshToken *RefreshToken
	AccessToken  *AccessToken
}

// RefreshToken struct will represent a Refresh Token object
type RefreshToken struct {
	AccessCode string
	AuthURL    string
	TokenURL   string
	Token      string
}

// NewClientID function will generate a Client ID based on
// the input parameters provided
func NewClientID(id, secret, scopes, refreshToken string) (*ClientID, error) {
	client := &ClientID{
		Type: "client_id",
	}

	if id == "" {
		return nil, errors.New(`Client ID not defined - mandatory field`)
	}
	if secret == "" {
		return nil, errors.New(`Client Secret not defined - mandatory field`)
	}
	if scopes == "" && refreshToken == "" {
		return nil, errors.New(`Scopes not defined - mandatory field when Refresh Token is absent`)
	}

	client.SetID(id)
	client.SetSecret(secret)
	client.SetScopes(scopes)
	client.InitToken()

	if refreshToken != "" {
		client.RefreshToken.SetToken(refreshToken)
		return client, nil
	}

	return client, nil
}

// Gen method will initiate the process of creating an Access Code
// (by having the user visiting an authorization page), and with doing
// so creating a Refresh Token for this request
func (c *ClientID) Gen() {
	c.RefreshToken.SetAuthURL(c)
	fmt.Println(`Please visit the following URL and paste the Access code below: 
===
` + c.RefreshToken.GetAuthURL() + `
===
Access Code:	`)

	reader := bufio.NewReader(os.Stdin)
	accessCode, _ := reader.ReadString('\n')
	// convert CRLF to LF
	accessCode = strings.Replace(accessCode, "\n", "", -1)
	c.RefreshToken.SetAccessCode(accessCode)

	post, err := json.Marshal(map[string]string{
		"code":          c.RefreshToken.GetAccessCode(),
		"client_id":     c.GetID(),
		"client_secret": c.GetSecret(),
		"redirect_uri":  `urn:ietf:wg:oauth:2.0:oob`,
		"grant_type":    `authorization_code`,
	})

	if err != nil {
		panic(err)
	}

	postBytes := bytes.NewBuffer(post)

	resp, err := http.Post(c.RefreshToken.TokenURL, "application/json", postBytes)

	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		panic(err)
	}

	c.SetToken(body)
	return
}

// SetToken method will define the token values for Client IDs;
// setting the Access Token and Refresh Token values respectively
func (c *ClientID) SetToken(body []byte) {
	if err := json.Unmarshal(body, c.AccessToken); err != nil {
		panic(err)
	}
	c.RefreshToken.Token = c.AccessToken.RefreshToken
}

// Refresh method will create a new Access Token based on a valid
// combination of credentials and refresh token values
func (c *ClientID) Refresh() {
	if c.RefreshToken.HasToken() {
		post, err := json.Marshal(map[string]string{
			"client_id":     c.GetID(),
			"client_secret": c.GetSecret(),
			"refresh_token": c.RefreshToken.GetToken(),
			"grant_type":    `refresh_token`,
		})

		if err != nil {
			panic(err)
		}

		postBytes := bytes.NewBuffer(post)

		resp, err := http.Post(c.RefreshToken.TokenURL, "application/json", postBytes)

		if err != nil {
			panic(err)
		}

		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)

		if err != nil {
			panic(err)
		}

		json.Unmarshal(body, c.AccessToken)
		c.RefreshToken.Token = c.AccessToken.RefreshToken
		return
	}
	c.Gen()
	return
}

// SetID method will define the Client ID value for the ClientID
// object
func (c *ClientID) SetID(input string) {
	c.ID = input
	return
}

// SetSecret method will define the Client ID secret for the
// ClientID object
func (c *ClientID) SetSecret(input string) {
	c.Secret = input
	return
}

// SetScopes method will define the access scopes for the ClientID
// object
func (c *ClientID) SetScopes(input string) {
	c.Scopes = input
	return
}

// InitToken method initiates the tokens in a Client ID, so that
// their methods can be accessed later on
func (c *ClientID) InitToken() {
	c.RefreshToken = &RefreshToken{}
	c.AccessToken = &AccessToken{}
	c.RefreshToken.SetTokenURL()
	return
}

// GetID method returns the Client ID value from a ClientID object
func (c *ClientID) GetID() string {
	return c.ID
}

// GetSecret method returns the Client ID secret from a ClientID
// object
func (c *ClientID) GetSecret() string {
	return c.Secret
}

// GetScopes method returns the access scopes from a ClientID object
func (c *ClientID) GetScopes() string {
	return c.Scopes
}

// SetAccessCode method will define the access code for the
// RefreshToken object
func (r *RefreshToken) SetAccessCode(input string) {
	r.AccessCode = input
	return
}

// SetAuthURL method  will define the auth URL for the RefreshToken
// object
func (r *RefreshToken) SetAuthURL(c *ClientID) {
	scopes := url.QueryEscape(c.Scopes)
	r.AuthURL = `https://accounts.google.com/o/oauth2/auth?client_id=` + c.ID + `&redirect_uri=urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob&response_type=code&access_type=offline&prompt=consent&scope=` + scopes
	return
}

// SetTokenURL method will define the token URL for the
// RefreshToken object
func (r *RefreshToken) SetTokenURL() {
	r.TokenURL = `https://accounts.google.com/o/oauth2/token`
	return
}

// SetToken method will define the Refresh Token value for the
// RefreshToken object
func (r *RefreshToken) SetToken(input string) {
	r.Token = input
	return
}

// GetAccessCode method retuns the Access Code value from the
// RefreshToken object
func (r *RefreshToken) GetAccessCode() string {
	return r.AccessCode
}

// GetAuthURL method returns the auth URL from the RefreshToken
// object
func (r *RefreshToken) GetAuthURL() string {
	return r.AuthURL
}

// GetTokenURL method returns the token URL from the RefreshToken
// object
func (r *RefreshToken) GetTokenURL() string {
	return r.TokenURL
}

// GetToken method returns the Refresh Token from the RefreshToken
// object
func (r *RefreshToken) GetToken() string {
	return r.Token
}

// HasToken method check whether the Refresh Token value is set
// from a RefreshToken object, returning a boolean
func (r *RefreshToken) HasToken() bool {
	if r.Token != "" {
		return true
	}
	return false
}
