package pomerium.require_email

test_deny {
    denials := deny with
        data.allowed_emails as ["x@example.com"] with
        input.user as { "id": "user1", "email": "y@notexample.com" } with
        input.impersonate_email as null
    denials == {[403, "user has invalid email"]}
}

test_allow {
    denials := deny with
        data.allowed_emails as ["x@example.com"] with
        input.user as { "id": "user1", "email": "x@example.com" } with
        input.impersonate_email as null
    count(denials) == 0
}

test_allow_impersonate {
    denials := deny with
        data.allowed_emails as ["x@example.com"] with
        input.user as { "id": "user1", "email": "y@example.com" } with
        input.impersonate_email as "x@example.com"
    count(denials) == 0
}
