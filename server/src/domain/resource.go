package domain

type Resource struct {
    Name string
    Value string
    Clients []*Client
    Roles []*Role
}
