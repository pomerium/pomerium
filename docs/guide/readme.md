# Quick start

1.  [Download] pre-built binaries or build Pomerium from source.
1.  Generate a wild-card certificate for a test domain like `corp.example.com`. For convenience, an included [script] can generate a free one using LetsEncrypt and [certbot].

    Once complete, move the generated public and private keys (`cert.pem`/`privkey.pem`) next to the pomerium binary. Certificates can also be set as environmental variables or dynamically with a [KMS].

1.  Next, set configure your [identity provider](./identity-providers.md) by generating an OAuth **Client ID** and **Client Secret** as well as setting a **Redirect URL** endpoint. The Redirect URL endpoint will be called by the identity provider following user authentication.

1.  Pomerium is configured using [environmental variables]. A minimal configuration is as follows.

    ```bash
    # file : env
    # The URL that the identity provider will call back after authenticating the user
    export REDIRECT_URL="https://sso-auth.corp.example.com/oauth2/callback"
    # Generate 256 bit random keys  e.g. `head -c32 /dev/urandom | base64`
    export SHARED_SECRET=REPLACE_ME
    export COOKIE_SECRET=REPLACE_ME
    # Allow users with emails from the following domain post-fix (e.g. example.com)
    export ALLOWED_DOMAINS=*
    ## Identity Provider Settings
    export IDP_PROVIDER="google"
    export IDP_PROVIDER_URL="https://accounts.google.com" # optional for google
    export IDP_CLIENT_ID="YOU_GOT_THIS_FROM_STEP-3.apps.googleusercontent.com"
    export IDP_CLIENT_SECRET="YOU_GOT_THIS_FROM_STEP-3"
    # key/value list of simple routes.
    export ROUTES='http.corp.example.com':'httpbin.org'
    ```

    You can also view the [env.example] configuration file for a more comprehensive list of options.

1.  For a first run, I suggest setting the debug flag which provides user friendly logging.

    ```bash
    source ./env
    ./pomerium -debug
    ```

[download]: https://github.com/pomerium/pomerium/releases
[environmental variables]: https://12factor.net/config
[env.example]: https://github.com/pomerium/pomerium/blob/master/env.example
[kms]: https://en.wikipedia.org/wiki/Key_management
[certbot]: https://certbot.eff.org/docs/install.html
[script]: https://github.com/pomerium/pomerium/blob/master/scripts/generate_wildcard_cert.sh
