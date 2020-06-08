package pomerium.require_group

test_deny {
    denials := deny with
        data.allowed_groups as ["a", "b", "c"] with
        input.user as { "id": "user1" } with
        input.databroker_data as { "type.googleapis.com/directory.User": { "user1": { "Groups": ["d", "e"] } }} with
        input.impersonate_groups as []
    denials == {[403, "user not in required group"]}
}

test_allow {
    denials := deny with
        data.allowed_groups as ["a", "b", "c"] with
        input.user as { "id": "user1" } with
        input.databroker_data as { "type.googleapis.com/directory.User": { "user1": { "Groups": ["a", "d", "e"] } }} with
        input.impersonate_groups as []
    count(denials) == 0
}

test_allow_impersonate {
    denials := deny with
        data.allowed_groups as ["a", "b", "c"] with
        input.user as { "id": "user1" } with
        input.databroker_data as { "type.googleapis.com/directory.User": { "user1": { "Groups": [] } }} with
        input.impersonate_groups as ["a"]
    count(denials) == 0
}
