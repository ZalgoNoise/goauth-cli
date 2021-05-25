package conf

import "goauth/oauth"

// GoAuth struct
type GoAuth struct {
	Conf           *GoAuthConf
	ClientID       *oauth.ClientID
	ServiceAccount *oauth.ServiceAccount
}

// NewGoAuth function
func NewGoAuth() *GoAuth {
	return &GoAuth{
		Conf: GetOpts(),
	}
}

// OnStart method
func (g *GoAuth) OnStart() {
	if g.Conf.IsClientID != false {
		g.ExecClientID()
	} else if g.Conf.IsServiceAccount != false {
		g.ExecServiceAccount()
	}

}

// OnFinish method
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

// ExecClientID method
func (g *GoAuth) ExecClientID() {
	g.ClientID = oauth.NewClientID(
		g.Conf.AccountName,
		g.Conf.Secret,
		g.Conf.Scopes,
		g.Conf.RefreshToken,
	)

	if g.ClientID.RefreshToken.HasToken() {
		g.ClientID.Refresh()
	} else {
		g.ClientID.Gen()
	}
}

// ExecServiceAccount method
func (g *GoAuth) ExecServiceAccount() {
	g.ServiceAccount = oauth.NewServiceAccount(
		g.Conf.Secret,
		g.Conf.Scopes,
		g.Conf.Subscriber,
	)

	g.ServiceAccount.Auth()

}

// GoAuthConf struct
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

// NewClientID method
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

// NewServiceAccount method
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
