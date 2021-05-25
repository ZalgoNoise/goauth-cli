package main

import "github.com/ZalgoNoise/goauth-cli/conf"

func main() {

	goauth := conf.NewGoAuth()

	goauth.OnStart()
	goauth.OnFinish()

}
