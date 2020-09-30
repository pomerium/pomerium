# Auth0 Go SDK

[![GoDoc](https://godoc.org/gopkg.in/auth0.v4?status.svg)](https://godoc.org/gopkg.in/auth0.v4)
[![Build](https://github.com/go-auth0/auth0/workflows/Build/badge.svg)](https://github.com/go-auth0/auth0/actions?query=branch%3Amaster)
[![Maintainability](https://api.codeclimate.com/v1/badges/bf038abb77ffb7c94cde/maintainability)](https://codeclimate.com/github/go-auth0/auth0/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/bf038abb77ffb7c94cde/test_coverage)](https://codeclimate.com/github/go-auth0/auth0/test_coverage)

## Documentation

Reference documentation can be found at [godoc.org](https://godoc.org/gopkg.in/auth0.v1). For more information about [Auth0](http://auth0.com/) please visit the [Auth0 Docs](http://docs.auth0.com/) page.

## Management API

The Auth0 Management API is meant to be used by back-end servers or trusted parties performing administrative tasks. Generally speaking, anything that can be done through the Auth0 dashboard (and more) can also be done through this API.

### Usage

```go
import (
	gopkg.in/auth0.v4
	gopkg.in/auth0.v4/management
)
```

Initialize a new client using a domain, client ID and secret.

```go
m, err := management.New(domain, id, secret)
if err != nil {
	// handle err
}
```

With the management client we can now interact with the Auth0 Management API.

```go
c := &management.Client{
	Name:        auth0.String("Client Name"),
	Description: auth0.String("Long description of client"),
}

err = m.Client.Create(c)
if err != nil {
	// handle err
}

fmt.Printf("Created client %s\n", c.ClientID)
```

The following Auth0 resources are supported:

- [x] [Branding](https://auth0.com/docs/api/management/v2/#!/Branding/get_branding)
- [x] [Clients (Applications)](https://auth0.com/docs/api/management/v2#!/Clients/get_clients)
- [x] [Client Grants](https://auth0.com/docs/api/management/v2#!/Client_Grants/get_client_grants)
- [x] [Connections](https://auth0.com/docs/api/management/v2#!/Connections/get_connections)
- [x] [Custom Domains](https://auth0.com/docs/api/management/v2#!/Custom_Domains/get_custom_domains)
- [ ] [Device Credentials](https://auth0.com/docs/api/management/v2#!/Device_Credentials/get_device_credentials)
- [x] [Grants](https://auth0.com/docs/api/management/v2#!/Grants/get_grants)
- [x] [Hooks](https://auth0.com/docs/api/management/v2#!/Hooks/get_hooks)
- [x] [Hook Secrets](https://auth0.com/docs/api/management/v2/#!/Hooks/get_secrets)
- [x] [Logs](https://auth0.com/docs/api/management/v2#!/Logs/get_logs)
- [x] [Prompts](https://auth0.com/docs/api/management/v2#!/Prompts/get_prompts)
- [x] [Resource Servers (APIs)](https://auth0.com/docs/api/management/v2#!/Resource_Servers/get_resource_servers)
- [x] [Roles](https://auth0.com/docs/api/management/v2#!/Roles)
- [x] [Rules](https://auth0.com/docs/api/management/v2#!/Rules/get_rules)
- [x] [Rules Configs](https://auth0.com/docs/api/management/v2#!/Rules_Configs/get_rules_configs)
- [x] [User Blocks](https://auth0.com/docs/api/management/v2#!/User_Blocks/get_user_blocks)
- [x] [Users](https://auth0.com/docs/api/management/v2#!/Users/get_users)
- [x] [Users By Email](https://auth0.com/docs/api/management/v2#!/Users_By_Email/get_users_by_email)
- [x] [Blacklists](https://auth0.com/docs/api/management/v2#!/Blacklists/get_tokens)
- [x] [Email Templates](https://auth0.com/docs/api/management/v2#!/Email_Templates/get_email_templates_by_templateName)
- [x] [Emails](https://auth0.com/docs/api/management/v2#!/Emails/get_provider)
- [x] [Guardian](https://auth0.com/docs/api/management/v2#!/Guardian/get_factors)
- [x] [Jobs](https://auth0.com/docs/api/management/v2#!/Jobs/get_jobs_by_id)
- [x] [Stats](https://auth0.com/docs/api/management/v2#!/Stats/get_active_users)
- [x] [Tenants](https://auth0.com/docs/api/management/v2#!/Tenants/get_settings)
- [ ] [Anomaly](https://auth0.com/docs/api/management/v2#!/Anomaly/get_ips_by_id)
- [x] [Tickets](https://auth0.com/docs/api/management/v2#!/Tickets/post_email_verification)

## What is Auth0?

Auth0 helps you to:

* Add authentication with [multiple authentication sources](https://docs.auth0.com/identityproviders), either social like **Google, Facebook, Microsoft Account, LinkedIn, GitHub, Twitter, Box, Salesforce, amont others**, or enterprise identity systems like **Windows Azure AD, Google Apps, Active Directory, ADFS or any SAML Identity Provider**.
* Add authentication through more traditional **[username/password databases](https://docs.auth0.com/mysql-connection-tutorial)**.
* Add support for **[linking different user accounts](https://docs.auth0.com/link-accounts)** with the same user.
* Support for generating signed [Json Web Tokens](https://docs.auth0.com/jwt) to call your APIs and **flow the user identity** securely.
* Analytics of how, when and where users are logging in.
* Pull data from other sources and add it to the user profile, through [JavaScript rules](https://docs.auth0.com/rules).

## Create a free Auth0 Account

1.  Go to [Auth0](https://auth0.com) and click "Try Auth0 for Free".
2.  Use Google, GitHub or Microsoft Account to login.

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## Author

[Alex Kalyvitis](https://github.com/alexkappa)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
