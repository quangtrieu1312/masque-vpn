package request

type DeleteClients struct {
    IDs []int64 `json:"ids"`
}

type UpsertClients struct {
    Names []string `json:"names"`
}

type AssignRolesToClients struct {
    ClientIDs []int64 `json:"client_ids"`
    RoleIDs []int64 `json:"role_ids"`
}

type UnassignRolesToClients struct {
    ClientIDs []int64 `json:"client_ids"`
    RoleIDs []int64 `json:"role_ids"`
}

type UpdateClientName struct {
    Name string `json:"name"`
}

type FetchClientResources struct {
    ClientID int64 `json:"client_id"`
}

type FetchClientRoles struct {
    ClientID int64 `json:"client_id"`
}
