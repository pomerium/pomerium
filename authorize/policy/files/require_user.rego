package pomerium.require_user

deny[status] {
    status := [401, "user not logged in"]
    is_null(input.user)
}

deny[status] {
    status := [401, "user not logged in"]
    is_null(input.user.id)
}
