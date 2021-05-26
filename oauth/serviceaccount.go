package oauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
)

// ServiceAccount struct represents a service account object
// based on the provided JSON key file from GCP
type ServiceAccount struct {
	Type            string `json:"type,omitempty"`
	ProjectID       string `json:"project_id,omitempty"`
	PrivateKeyID    string `json:"private_key_id,omitempty"`
	PrivateKey      string `json:"private_key,omitempty"`
	ClientEmail     string `json:"client_email,omitempty"`
	ClientID        string `json:"client_id,omitempty"`
	AuthURI         string `json:"auth_uri,omitempty"`
	TokenURI        string `json:"token_uri,omitempty"`
	AuthProvCertURL string `json:"auth_provider_x509_cert_url,omitempty"`
	ClientCertURL   string `json:"client_x509_cert_url,omitempty"`
	JWT             *JWT
	AccessToken     *AccessToken
}

// NewServiceAccount function creates a new ServiceAccount object
// based on the input parameters
func NewServiceAccount(file, scope, sub string) *ServiceAccount {
	svAcc := &ServiceAccount{}

	f, err := ioutil.ReadFile(file)
	if err != nil {
		panic(err)
	}

	if err := json.Unmarshal(f, svAcc); err != nil {
		panic(err)
	}

	svAcc.Init(scope, sub)
	return svAcc
}

// Init method will initiate a ServiceAccount object by
// creating (and signing) the JWT for the request
func (s *ServiceAccount) Init(scope, sub string) {
	s.JWT = &JWT{
		Claim: &JWTClaim{},
	}
	s.AccessToken = &AccessToken{}

	s.JWT.InitHeader()

	s.JWT.Claim.SetIssuer(s.GetEmail())
	s.JWT.Claim.SetScope(scope)
	s.JWT.Claim.SetAudience(s.GetTokenURI())
	s.JWT.Claim.SetExpiry()

	if sub != "" {
		s.JWT.Claim.SetSubscriber(sub)
	}

	var err error
	if s.JWT.Signature, err = s.JWT.Sign(s.PrivateKey); err != nil {
		panic(err)
	}

	if s.JWT.Output, err = s.JWT.Build(); err != nil {
		panic(err)
	}

}

// Auth method will issue a request for an Access Token, based
// on the created JWT
func (s *ServiceAccount) Auth() {
	post, err := json.Marshal(map[string]string{
		"grant_type": `urn:ietf:params:oauth:grant-type:jwt-bearer`,
		"assertion":  s.JWT.GetOutput(),
	})

	if err != nil {
		panic(err)
	}

	postBytes := bytes.NewBuffer(post)

	resp, err := http.Post(s.GetTokenURI(), `application/json`, postBytes)

	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		panic(err)
	}

	CheckResponse(body)
	s.SetToken(body)
	return
}

// SetToken method will define the AccessToken object in the
// calling ServiceAccount
func (s *ServiceAccount) SetToken(body []byte) {
	if err := json.Unmarshal(body, s.AccessToken); err != nil {
		panic(errors.New(`Unable to complete the request:

` + string(body) + `

`))
	}
}

// GetPrivateKey method returns the ServiceAccount's defined
// Private Key
func (s *ServiceAccount) GetPrivateKey() string {
	return s.PrivateKey
}

// GetEmail method returns the ServiceAccount's defined
// service account email
func (s *ServiceAccount) GetEmail() string {
	return s.ClientEmail
}

// GetClientID method returns the ServiceAccount's associated
// ClientID (Workspace Domain-wide Delegation)
func (s *ServiceAccount) GetClientID() string {
	return s.ClientID
}

// GetTokenURI method returns the ServiceAccount's defined
// token URI
func (s *ServiceAccount) GetTokenURI() string {
	return s.TokenURI
}

// CheckResponse function will look into the returned HTTP response
// to check whether it actually contains an error
func CheckResponse(body []byte) {
	chk := &TokenError{}

	json.Unmarshal(body, chk)

	if chk.Error != "" {
		panic(errors.New(`Found error in response:

	Error: ` + chk.Error + `
	Desc: ` + chk.Description))
	}

}
