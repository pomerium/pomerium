package pomerium.require_group

deny[status] {
    status := [403, "user not in required group"]

    allowed_groups := data.allowed_groups
    user_id := input.user.id
    databroker_data := input.databroker_data
    directory_groups := databroker_data["type.googleapis.com/directory.User"][user_id].Groups
    impersonate_groups := input.impersonate_groups

    count([group |
        some group
        allowed_groups[_] = group
        directory_groups[_] = group
    ]) == 0

    count([group |
        some group
        allowed_groups[_] = group
        impersonate_groups[_] = group
    ]) == 0
}
