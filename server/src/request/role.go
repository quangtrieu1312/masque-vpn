package request

type DeleteRoles struct {
    IDs []int64 `json:"ids"`
}

type UpsertRoles struct {
    Names []string `json:"names"`
}

type AssignResourcesToRoles struct {
    ResourceIDs []int64 `json:"resource_ids"`
    RoleIDs []int64 `json:"role_ids"`
}

type UnassignResourcesToRoles struct {
    ResourceIDs []int64 `json:"resource_ids"`
    RoleIDs []int64 `json:"role_ids"`
}

type UpdateRoleName struct {
    Name string `json:"name"`
}
