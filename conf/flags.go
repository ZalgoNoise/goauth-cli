package conf

import (
	"errors"
	"flag"
)

const (
	noOptError = `At least one option must be set: Client ID or Service Account`
	noRefError = `No value provided for option: `
)

// GetOpts function will collect the user's input from the set
// flags on runtime, and create a GoAuthConf object based on it
func GetOpts() *GoAuthConf {
	cfg := &GoAuthConf{}

	// execution modes
	setClientID := flag.Bool("c", false, "Client ID as a credential type")
	setServiceAccount := flag.Bool("s", false, "Service Account as a credential type")

	// auth settings (short form)
	accountName := flag.String("i", "", "Client ID name / value. Service accounts only refer to the keyfile [-k {file}]")
	secret := flag.String("k", "", "Secret or key for the credentials. A string for a Client ID Secret, a path to a JSON file for Service Accounts")
	scopes := flag.String("x", "", "Space-delimited list of scopes to use in the request")
	subscriber := flag.String("u", "", "[optional] Impersonated user (Service Accounts)")
	refresh := flag.String("r", "", "[optional] Refresh Token (Client IDs)")

	// auth settings (long form)
	accountNameLong := flag.String("id", "", "Client ID name / value. Service accounts only refer to the keyfile [-k {file}]")
	secretLong := flag.String("key", "", "Secret or key for the credentials. A string for a Client ID Secret, a path to a JSON file for Service Accounts")
	scopesLong := flag.String("scope", "", "Space-delimited list of scopes to use in the request")
	subscriberLong := flag.String("user", "", "[optional] Impersonated user (Service Accounts)")
	refreshLong := flag.String("refresh", "", "[optional] Refresh Token (Client IDs)")

	// runtime options
	ninjaMode := flag.Bool("z", false, "Ninja Mode: returns only the access tokens as a string, so the output can be fed into other programs or apps")

	flag.Parse()

	if *setClientID != false {

		return cfg.NewClientID(
			StringCheck(*accountName, *accountNameLong, "Client ID name"),
			StringCheck(*secret, *secretLong, "Client ID secret"),
			StringCheck(*scopes, *scopesLong, "Authorization scopes"),
			StringCheck(*refresh, *refreshLong, ""),
			*ninjaMode,
		)

	} else if *setServiceAccount != false {
		return cfg.NewServiceAccount(
			StringCheck(*secret, *secretLong, "JSON Keyfile for the Service Account, from GCP"),
			StringCheck(*scopes, *scopesLong, "Authorization scopes"),
			StringCheck(*subscriber, *subscriberLong, ""),
			*ninjaMode,
		)

	} else {
		panic(errors.New(noOptError))
	}

}

// StringCheck function will verify which of either short or long
// form is defined, and return it. If none are set, an empty string
// is returned
func StringCheck(short, long, ref string) string {

	if short != "" {
		return short
	} else if long != "" {
		return long
	}

	if ref != "" {
		panic(errors.New(noRefError + ref))
	}
	return ""

}
