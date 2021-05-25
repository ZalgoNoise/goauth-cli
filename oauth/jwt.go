package oauth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

const (
	audienceURL string = `https://oauth2.googleapis.com/token`
)

var (
	jwtHeader []byte = []byte(`{"alg":"RS256","typ":"JWT"}`)
	byteDot   []byte = []byte(`.`)
)

// JWT struct will define the contents of a JWT object
type JWT struct {
	Header    []byte
	Claim     *JWTClaim
	Signature []byte
	Output    []byte
}

// JWTClaim struct will represent the JWT body structure
type JWTClaim struct {
	Issuer     string `json:"iss,omitempty"`
	Subscriber string `json:"sub,omitempty"`
	Scope      string `json:"scope,omitempty"`
	Audience   string `json:"aud,omitempty"`
	Expiry     int64  `json:"exp,omitempty"`
	Issued     int64  `json:"iat,omitempty"`
}

// SetExpiry method
func (c *JWTClaim) SetExpiry() {
	c.Issued = time.Now().Unix()
	c.Expiry = (c.Issued + 3590)
	return
}

// Sign method
func (j *JWT) Sign(pkey string) ([]byte, error) {

	headerB64, err := b64(j.Header)
	if err != nil {
		return nil, err
	}

	claimB64, err := b64(j.Claim)
	if err != nil {
		return nil, err
	}

	joinedB64 := headerB64 + `.` + claimB64

	key, err := newKey([]byte(pkey))
	if err != nil {
		return nil, err
	}

	sig, err := key.Sign([]byte(joinedB64))

	if err != nil {
		return nil, err
	}

	return sig, nil

}

// Build method
func (j *JWT) Build() ([]byte, error) {
	headerB64, err := b64(j.Header)
	if err != nil {
		return nil, err
	}

	claimB64, err := b64(j.Claim)
	if err != nil {
		return nil, err
	}

	sigB64, err := b64(j.Signature)
	if err != nil {
		return nil, err
	}

	return byteJoin(
		[]byte(headerB64),
		byteDot,
		[]byte(claimB64),
		byteDot,
		[]byte(sigB64),
	), nil
}

func b64(input interface{}) (string, error) {
	switch t := input.(type) {
	case *JWTClaim:
		var buf []byte
		buf, err := json.Marshal(t)
		if err != nil {
			return "", err
		}
		return base64.URLEncoding.EncodeToString(buf), nil

	case []byte:
		return base64.URLEncoding.EncodeToString(t), nil

	default:
		return "", errors.New("Invalid data type provided")
	}

}

func byteJoin(input ...[]byte) []byte {
	var empty []byte
	array := bytes.Join(input, empty)
	return array
}

// InitHeader method
func (j *JWT) InitHeader() {
	j.Header = jwtHeader
	return
}

// SetIssuer method
func (c *JWTClaim) SetIssuer(input string) {
	c.Issuer = input
	return
}

// SetSubscriber method
func (c *JWTClaim) SetSubscriber(input string) {
	c.Subscriber = input
	return
}

// SetScope method
func (c *JWTClaim) SetScope(input string) {
	c.Scope = input
	return
}

// SetAudience method
func (c *JWTClaim) SetAudience(input string) {
	c.Audience = input
	return
}

// GetOutput method
func (j *JWT) GetOutput() string {
	return string(j.Output)
}
