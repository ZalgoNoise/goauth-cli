package conf

import "github.com/ZalgoNoise/goauth-cli/oauth"

// GoAuth struct represents an instance (execution) of GoAuth
type GoAuth struct {
	Conf           *GoAuthConf
	ClientID       *oauth.ClientID
	ServiceAccount *oauth.ServiceAccount
}

// NewGoAuth function will create and return a new GoAuth object
// based on the input configuration
func NewGoAuth() *GoAuth {
	return &GoAuth{
		Conf: GetOpts(),
	}
}

// OnStart method will list the actions to take upon setting up
// a new GoAuth instance
func (g *GoAuth) OnStart() {
	if g.Conf.IsClientID != false {
		g.ExecClientID()
	} else if g.Conf.IsServiceAccount != false {
		g.ExecServiceAccount()
	}

}

// OnFinish method will list the actions to take upon completing
// execution
func (g *GoAuth) OnFinish() {

	if g.Conf.IsClientID != false && g.ClientID.AccessToken.IsSet() {
		if g.Conf.IsNinjaMode != false && g.Conf.RefreshToken != "" {
			g.ClientID.AccessToken.PrintShort()
			return
		}
		g.ClientID.AccessToken.PrintLong()
		return
	} else if g.Conf.IsServiceAccount != false && g.ServiceAccount.AccessToken.IsSet() {
		if g.Conf.IsNinjaMode != false {
			g.ServiceAccount.AccessToken.PrintShort()
			return
		}
		g.ServiceAccount.AccessToken.PrintLong()
		return
	}

}

// ExecClientID method will process the actions required for a
// Client ID account type
func (g *GoAuth) ExecClientID() {
	var err error

	g.ClientID, err = oauth.NewClientID(
		g.Conf.AccountName,
		g.Conf.Secret,
		g.Conf.Scopes,
		g.Conf.RefreshToken,
	)
	
	if err != nil {
		panic(err)
	}

	if g.ClientID.RefreshToken.HasToken() {
		g.ClientID.Refresh()
	} else {
		g.ClientID.Gen()
	}
}

// ExecServiceAccount method will process the actions required for a
// Service Account account type
func (g *GoAuth) ExecServiceAccount() {
	g.ServiceAccount = oauth.NewServiceAccount(
		g.Conf.Secret,
		g.Conf.Scopes,
		g.Conf.Subscriber,
	)

	g.ServiceAccount.Auth()

}

// GoAuthConf struct will represent the configuration for this
// instance of GoAuth
type GoAuthConf struct {
	IsClientID       bool
	IsServiceAccount bool
	IsWebUI          bool
	IsNinjaMode      bool
	AccountName      string
	Secret           string
	Scopes           string
	Subscriber       string
	RefreshToken     string
}

// NewClientID method will create a new Client ID object based
// on its available input parameters
func (c *GoAuthConf) NewClientID(clientid, secret, scopes, refreshToken string, ninjaMode bool) *GoAuthConf {
	return &GoAuthConf{
		IsClientID:       true,
		IsServiceAccount: false,
		IsNinjaMode:      ninjaMode,
		AccountName:      clientid,
		Secret:           secret,
		Scopes:           scopes,
		RefreshToken:     refreshToken,
	}
}

// NewServiceAccount method will create a new Service Account
// object based on its available input parameters
func (c *GoAuthConf) NewServiceAccount(keyfile, scopes, subscriber string, ninjaMode bool) *GoAuthConf {
	return &GoAuthConf{
		IsClientID:       false,
		IsServiceAccount: true,
		IsNinjaMode:      ninjaMode,
		Secret:           keyfile,
		Scopes:           scopes,
		Subscriber:       subscriber,
	}
}
