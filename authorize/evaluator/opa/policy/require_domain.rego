package pomerium.require_domain

deny[status] {
    status := [401, "user not logged in"]
    not input.user
}

deny[status] {
    status := [403, "user has invalid domain"]

    allowed_domains := data.allowed_domains
    email := input.user.email
    impersonate_email := input.impersonate_email

    count([domain |
        some domain
        allowed_domains[_] = domain
        email_under_domain(email, domain)
    ]) == 0

    count([domain |
        some domain
        allowed_domains[_] = domain
        email_under_domain(impersonate_email, domain)
    ]) == 0
}

email_under_domain(email, domain) {
    is_string(email)
    is_string(domain)

	x := split(email, "@")
	count(x) == 2
	x[1] == domain
}
