/*
Package auth0 provides a client for using the Auth0 Management API.

Usage

    import (
        gopkg.in/auth0.v4
        gopkg.in/auth0.v4/management
    )

Initialize a new client using a domain, client ID and secret.

    m, err := management.New(domain, id, secret)
    if err != nil {
        // handle err
    }

With the management client we can now interact with the Auth0 Management API.

    c := &management.Client{
        Name:        auth0.String("Client Name"),
        Description: auth0.String("Long description of client"),
    }

    err = m.Client.Create(c)
    if err != nil {
        // handle err
    }

Authentication

The auth0 package handles authentication by exchanging the client id and secret
supplied when creating a new management client.

This is done using the https://godoc.org/golang.org/x/oauth2 package.

Rate Limiting

The auth0 package also handles rate limiting by respecting the `X-Ratelimit-*`
headers sent by the server.

The amount of time the client waits for the rate limit to be reset is taken from
the `X-Ratelimit-Reset` header as the amount of seconds to wait.

Configuration

There are several other options that can be specified during the creation of a
new client.

    m, err := management.New(domain, id, secret,
        management.WithDebug(true),
        management.WithContext(context.Background()),
        management.WithTimeout(5 * time.Seconds))

Request Configuration

As with the global client configuration, fine-grained configuration can be done
on a request basis.

    c, err := m.Connection.List(
        management.Parameter("strategy", "auth0"),
    )

*/
package auth0
