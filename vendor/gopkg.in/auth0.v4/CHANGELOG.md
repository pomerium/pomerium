## v4.6.0

* `management.ConnectionOptions`: Now supports `OAuth2` connection type ([#141](https://github.com/go-auth0/auth0/pull/141)).
* `management.ConnectionOptionsSAML`: Add missing options ([#138](https://github.com/go-auth0/auth0/pull/138/)).

## v4.5.0

* `management.User`: add `LastIP` and `LoginsCount` fields ([#137](https://github.com/go-auth0/auth0/pull/137)).

## v4.3.6

* `management.ConnectionOptionsOIDC`: add missing `Scopes()` and `SetScopes()` methods.

## v4.3.5

* `management.ConnectionOptions*`: `SetScopes()` was ignoring the `enable` argument.

## v4.2.0

* `management.UserManager`: `Roles()` returns `RoleList` ([#109](https://github.com/go-auth0/auth0/pull/109)).
* `management.UserManager`: `Permissions()` returns `PermissionList`.
* `management.RoleManager`: `Users()` returns `UserList`.
* `management.RoleManager`: `Permissions()` returns `PermissionList`.

## v4.1.1

* `management.Branding`: Support for both `BrandingColors.PageBackgroundGradient` as well as `BrandingColors.PageBackground`. ([#99](https://github.com/go-auth0/auth0/pull/99))

## v4.1.0

* `management.ConnectionOptionsEmail`, `management.ConnectionOptionsSMS`: add `authParams`.
* `management.UserIdentity`: correctly marshal/unmarshal integer `user_id`'s ([#101](https://github.com/go-auth0/auth0/issues/101), [#102](https://github.com/go-auth0/auth0/pull/102)). 

## v4.0.1

* `management.Tenant`: Add `use_scope_descriptions_for_consent` flag.

## v4.0.0

* **Breaking Change:** `Connection.Options` is now an `interface{}` accepting different types depending on the strategy.