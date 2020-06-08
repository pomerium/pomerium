package pomerium.require_domain

test_no_user {
    denials := deny with
        data.allowed_domains as ["example.com"]
    denials == {[401, "user not logged in"]}
}

test_deny {
    denials := deny with
        data.allowed_domains as ["example.com"] with
        input.user as { "id": "user1", "email": "x@notexample.com" } with
        input.impersonate_email as null
    denials == {[403, "user has invalid domain"]}
}

test_allow {
    denials := deny with
        data.allowed_domains as ["example.com"] with
        input.user as { "id": "user1", "email": "x@example.com" } with
        input.impersonate_email as null
    count(denials) == 0
}

test_allow_impersonate {
    denials := deny with
        data.allowed_domains as ["example.com"] with
        input.user as { "id": "user1", "email": "x@notexample.com" } with
        input.impersonate_email as "x@example.com"
    count(denials) == 0
}
