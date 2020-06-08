package pomerium.require_email

deny[status] {
    status := [403, "user has invalid email"]

    allowed_emails := data.allowed_emails
    user_email := input.user.email
    impersonate_email := input.impersonate_email

    count([email |
        some email
        allowed_emails[_] = email
        user_email = email
    ]) == 0

    count([email |
        some email
        allowed_emails[_] = email
        impersonate_email = email
    ]) == 0
}
