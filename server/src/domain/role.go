package domain

type Role struct {
    Name string
    Clients []*Client
    Resources []*Resource
}
