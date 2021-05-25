package main

import "goauth/conf"

func main() {

	goauth := conf.NewGoAuth()

	goauth.OnStart()
	goauth.OnFinish()

}
