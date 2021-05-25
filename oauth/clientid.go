package oauth

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// ClientID struct
type ClientID struct {
	Type         string
	ID           string
	Secret       string
	Scopes       string
	RefreshToken *RefreshToken
	AccessToken  *AccessToken
}

// RefreshToken struct
type RefreshToken struct {
	AccessCode string
	AuthURL    string
	TokenURL   string
	Token      string
}

// NewClientID function
func NewClientID(id, secret, scopes, refreshToken string) *ClientID {
	client := &ClientID{
		Type: "client_id",
	}
	client.SetID(id)
	client.SetSecret(secret)
	client.SetScopes(scopes)
	client.InitToken()

	if refreshToken != "" {
		client.RefreshToken.SetToken(refreshToken)
		return client
	}

	return client
}

// Gen method
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

func (c *ClientID) SetToken(body []byte) {
	if err := json.Unmarshal(body, c.AccessToken); err != nil {
		panic(err)
	}
	c.RefreshToken.Token = c.AccessToken.RefreshToken
}

// Refresh method
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

// SetID method
func (c *ClientID) SetID(input string) {
	c.ID = input
	return
}

// SetSecret method
func (c *ClientID) SetSecret(input string) {
	c.Secret = input
	return
}

// SetScopes method
func (c *ClientID) SetScopes(input string) {
	c.Scopes = input
	return
}

// InitToken method
func (c *ClientID) InitToken() {
	c.RefreshToken = &RefreshToken{}
	c.AccessToken = &AccessToken{}
	c.RefreshToken.SetTokenURL()
	return
}

// GetID method
func (c *ClientID) GetID() string {
	return c.ID
}

// GetSecret method
func (c *ClientID) GetSecret() string {
	return c.Secret
}

// GetScopes method
func (c *ClientID) GetScopes() string {
	return c.Scopes
}

// SetAccessCode method
func (r *RefreshToken) SetAccessCode(input string) {
	r.AccessCode = input
	return
}

// SetAuthURL method
func (r *RefreshToken) SetAuthURL(c *ClientID) {
	scopes := url.QueryEscape(c.Scopes)
	r.AuthURL = `https://accounts.google.com/o/oauth2/auth?client_id=` + c.ID + `&redirect_uri=urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob&response_type=code&access_type=offline&prompt=consent&scope=` + scopes
	return
}

// SetTokenURL method
func (r *RefreshToken) SetTokenURL() {
	r.TokenURL = `https://accounts.google.com/o/oauth2/token`
	return
}

// SetToken method
func (r *RefreshToken) SetToken(input string) {
	r.Token = input
	return
}

// GetAccessCode method
func (r *RefreshToken) GetAccessCode() string {
	return r.AccessCode
}

// GetAuthURL method
func (r *RefreshToken) GetAuthURL() string {
	return r.AuthURL
}

// GetTokenURL method
func (r *RefreshToken) GetTokenURL() string {
	return r.TokenURL
}

// GetToken method
func (r *RefreshToken) GetToken() string {
	return r.Token
}

// HasToken method
func (r *RefreshToken) HasToken() bool {
	if r.Token != "" {
		return true
	}
	return false
}
