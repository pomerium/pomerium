package pomerium.require_user

test_no_user {
    denials := deny with
        input.user as null
    denials == {[401, "user not logged in"]}
}
