## GoAuth (CLI)

GoAuth is a CLI tool written in Golang to generate Access Tokens for your GCP Client IDs and Service Accounts.

## Build Support

GoAuth currently is currently set to be built and tested with `bazel`, however you should be able to build and run simply with `go`.

Architectural support in `bazel` is defined to support all 4 main architectures:
- x86
- x86_64
- arm
- arm64

## Runtime

GoAuth supports generating Access Tokens for either Client IDs or Service Accounts. You can check all available flags with `goauth -h`.


### Client IDs without Refresh Tokens

To retrieve an Access Token for a ClientID you must supply the following details:
- Client ID value
- Client Secret value
- Access scopes
- [optional] Refresh Token

This can be issued in the following command:

```
goauth \
    -c \
    -i 'client_id' \
    -k 'client_secret' \
    -x 'access_scopes' 
```

or with `bazel`:

```
bazel run //:goauth -- \
    -c \
    -i 'client_id' \
    -k 'client_secret' \
    -x 'access_scopes' 
```

This command generates an offline access code retrieval URL. You should copy it and paste it to your browser to grant access to the app, and by doing so retrieving an Access Code which must be returned to the terminal:

```
Please visit the following URL and paste the Access code below: 
===
{URL}
===
Access Code:

```

The response will return the Access Token and a Refresh Token which can be reused.

### Client IDs with Refresh Tokens

Requests containing Refresh Tokens will not need an access scope specified, provided that the [`-r`] flag is populated with a valid Refresh Token for the referred Client ID:


```
goauth \
    -c \
    -i 'client_id' \
    -k 'client_secret' \
    -r 'refresh_token' 
```

or with `bazel`:

```
bazel run //:goauth -- \
    -c \
    -i 'client_id' \
    -k 'client_secret' \
    -r 'refresh_token' 
```

### Service Accounts

Service account authorization is very straightforward where no Refresh Tokens are involved, so no interaction is necessary beyond supplying valid credentials. 

This configuration is currently accepting a JSON keyfile (obtained via GCP) to simplify the way the data is collected for the token to be requested, avoiding pasting your private key in plaintext, in the terminal.

The Access Token can be retrieved with the following command:


```
goauth \
    -s \
    -k 'json_keyfile' \
    -x 'access_scopes' \
    -u 'impersonated_user'
```

or with `bazel`:

```
bazel run //:goauth -- \
    -s \
    -k 'json_keyfile' \
    -x 'access_scopes' \
    -u 'impersonated_user'
```


## Extras

#### Ninja-mode (Direct token)

Enabling this flag [`-z`] will spit out __only__ the Access Token (no linefeed included) which may allow the binary to be used (or fed to) other programs - such as a `cURL` HTTP request.