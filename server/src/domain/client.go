package domain

type Client struct {
    Name string
    LastSeen uint64
    Roles []*Role
}
